//! Turning one job into many: a pattern in the source's file name stands
//! for every file in that directory whose name matches, and with
//! [`recursive`] a directory stands for every file below it.

use glob::{MatchOptions, Pattern};
use tracing::{debug, info, warn};

use crate::{Endpoint, Error, Location, Result};

use super::Job;

/// Whether the last path component of `loc` is a pattern (`*` or `[…]`).
/// `?` does not count: in a URL it starts the query.
pub fn has_pattern(loc: &Location) -> bool {
    !loc.scheme().is_mail()
        && !loc.is_dir_target()
        && loc
            .filename()
            .is_some_and(|n| n.contains('*') || n.contains('['))
}

/// Expand every job whose source is a pattern into one job per matching
/// file. Jobs without a pattern pass through unchanged, in place. A pattern
/// that matches nothing is an error unless `allow_empty` is set, in which
/// case it contributes no jobs.
pub async fn expand(
    jobs: Vec<Job>,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
    allow_empty: bool,
) -> Result<Vec<Job>> {
    let mut out = Vec::with_capacity(jobs.len());
    for job in jobs {
        if !has_pattern(&job.src) {
            out.push(job);
            continue;
        }
        let matches = matching_files(&job.src, open).await?;
        if matches.is_empty() && !allow_empty {
            return Err(Error::InvalidUrl(format!(
                "{} matches no file (--allow-empty makes that fine)",
                job.src
            )));
        }
        for dst in &job.dsts {
            if !dst.is_dir_target() && !dst.scheme().is_mail() {
                return Err(Error::InvalidUrl(format!(
                    "{} is a pattern, so its target {} must be a directory (end it with /)",
                    job.src, dst
                )));
            }
        }
        for src in matches {
            out.push(Job {
                src,
                dsts: job.dsts.clone(),
            });
        }
    }
    Ok(out)
}

/// The files in the directory of `pattern` whose names match it, as
/// locations, in listing order.
async fn matching_files(
    pattern: &Location,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
) -> Result<Vec<Location>> {
    let name = pattern.filename().unwrap_or("");
    let glob = Pattern::new(name)
        .map_err(|e| Error::InvalidUrl(format!("pattern {name} in {pattern}: {}", e.msg)))?;
    let dir = pattern.parent()?;
    let entries = open(&dir)?.receiver()?.list().await?;
    let opts = MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        // As in a shell: `*` leaves dotfiles alone.
        require_literal_leading_dot: true,
    };
    let mut found = Vec::new();
    for e in entries {
        if e.is_dir || !glob.matches_with(&e.name, opts) {
            continue;
        }
        match dir.join(&e.name) {
            Ok(loc) => found.push(loc),
            Err(err) => debug!(name = %e.name, "skipping unsafe name: {err}"),
        }
    }
    info!(pattern = %pattern, matches = found.len(), "expanded");
    Ok(found)
}

/// Directories are not followed deeper than this; a sane tree is nowhere
/// near it, a listing that loops (a symlink cycle, say) would be.
const MAX_DEPTH: usize = 64;

/// The outcome of [`recursive`]: the file jobs, and the directories that
/// have to exist on the targets before they run, shallowest first.
#[derive(Debug, Default)]
pub struct Tree {
    pub jobs: Vec<Job>,
    pub dirs: Vec<Location>,
}

/// Expand every job whose source is a directory into one job per file
/// below it. A source ending in `/` copies its contents into the target,
/// one without copies the directory itself, as `rsync` has it. Jobs whose
/// source is a file pass through unchanged.
///
/// Targets must be directories. Listing is depth-first in name order, and
/// symbolic links are whatever the listing says they are (a file's content
/// is copied, a directory is descended into, up to a depth limit).
pub async fn recursive(
    jobs: Vec<Job>,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
) -> Result<Tree> {
    let mut tree = Tree::default();
    for job in jobs {
        let src = &job.src;
        if src.scheme().is_mail() {
            return Err(Error::InvalidUrl(format!("{src} cannot be a source")));
        }
        for dst in &job.dsts {
            if !dst.is_dir_target() && !dst.scheme().is_mail() {
                return Err(Error::InvalidUrl(format!(
                    "copying a tree into {dst} needs a directory target (end it with /)"
                )));
            }
        }
        // A file source is a job as it is. `size()` says whether it is one;
        // a directory answers `None` (and so does anything unreachable,
        // which the listing below will then complain about properly).
        let ep = open(src)?;
        if !src.is_dir_target() && ep.receiver()?.size().await?.is_some() {
            tree.jobs.push(job);
            continue;
        }
        let (root, base) = if src.is_dir_target() {
            (src.clone(), String::new())
        } else {
            // `a/b` goes to `<dst>/b/…`.
            let name = src
                .filename()
                .ok_or_else(|| Error::InvalidUrl(format!("{src} has no directory name")))?;
            (src.join("/")?, format!("{name}/"))
        };
        if !base.is_empty() {
            for dst in &job.dsts {
                if !dst.scheme().is_mail() {
                    tree.dirs.push(dst.join(&base)?);
                }
            }
        }
        let mut stack = vec![(root, base, 0usize)];
        while let Some((dir, rel, depth)) = stack.pop() {
            let entries = open(&dir)?.receiver()?.list().await?;
            let mut subdirs = Vec::new();
            for e in entries {
                if e.is_dir {
                    if depth >= MAX_DEPTH {
                        warn!(%dir, name = %e.name, "too deep, not descending");
                        continue;
                    }
                    let sub_rel = format!("{rel}{}/", e.name);
                    match dir.join(&format!("{}/", e.name)) {
                        Ok(sub) => {
                            for dst in &job.dsts {
                                if !dst.scheme().is_mail() {
                                    tree.dirs.push(dst.join(&sub_rel)?);
                                }
                            }
                            subdirs.push((sub, sub_rel, depth + 1));
                        }
                        Err(err) => debug!(name = %e.name, "skipping unsafe name: {err}"),
                    }
                    continue;
                }
                match dir.join(&e.name) {
                    Ok(file) => tree.jobs.push(Job {
                        src: file,
                        dsts: job
                            .dsts
                            .iter()
                            .map(|d| {
                                if d.scheme().is_mail() {
                                    Ok(d.clone())
                                } else {
                                    d.join(&rel)
                                }
                            })
                            .collect::<Result<Vec<_>>>()?,
                    }),
                    Err(err) => debug!(name = %e.name, "skipping unsafe name: {err}"),
                }
            }
            // Pushed in reverse so the listing order comes back out.
            stack.extend(subdirs.into_iter().rev());
        }
        info!(source = %src, files = tree.jobs.len(), dirs = tree.dirs.len(), "expanded a tree");
    }
    Ok(tree)
}

/// Create the directories a tree copy needs, in the order given. A target
/// that has no directories to speak of (S3) does nothing; one that cannot
/// create them (HTTP) is an error.
pub async fn create_dirs(
    dirs: &[Location],
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
) -> Result<()> {
    for dir in dirs {
        let ep = open(dir)?;
        let sender = ep.sender()?;
        if !sender.supports_mkdir() {
            return Err(Error::UnsupportedOperation {
                scheme: dir.scheme().to_string(),
                op: "create directories (copy a tree elsewhere, or files one by one)",
            });
        }
        debug!(%dir, "creating");
        sender.mkdir_all().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(s: &str) -> Location {
        Location::parse(s).unwrap()
    }

    #[test]
    fn patterns_are_recognized_in_the_file_name_only() {
        assert!(has_pattern(&loc("sftp://h/in/*.csv")));
        assert!(has_pattern(&loc("/tmp/in/report[0-9].bin")));
        assert!(!has_pattern(&loc("sftp://h/in/plain.csv")));
        assert!(!has_pattern(&loc("sftp://h/in/")));
        assert!(!has_pattern(&loc("mailto:a@example.com")));
    }

    async fn expand_local(pattern: &str, dst: &str, allow_empty: bool) -> Result<Vec<Job>> {
        let open = |l: &Location| crate::protocols::open(l.clone());
        expand(
            vec![Job {
                src: loc(pattern),
                dsts: vec![loc(dst)],
            }],
            &open,
            allow_empty,
        )
        .await
    }

    #[tokio::test]
    async fn a_pattern_becomes_one_job_per_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        for n in ["a.csv", "b.csv", "c.txt", ".hidden.csv"] {
            std::fs::write(dir.path().join(n), n).unwrap();
        }
        std::fs::create_dir(dir.path().join("sub.csv")).unwrap();
        let out = format!("{}/out/", dir.path().display());
        let jobs = expand_local(&format!("{}/*.csv", dir.path().display()), &out, false)
            .await
            .unwrap();
        let mut names: Vec<&str> = jobs.iter().map(|j| j.src.filename().unwrap()).collect();
        names.sort();
        assert_eq!(names, vec!["a.csv", "b.csv"]);
        assert!(
            jobs.iter()
                .all(|j| j.dsts.len() == 1 && j.dsts[0].path() == out)
        );

        let jobs = expand_local(&format!("{}/[ab].*", dir.path().display()), &out, false)
            .await
            .unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[tokio::test]
    async fn no_match_is_an_error_unless_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let pattern = format!("{}/*.nothing", dir.path().display());
        let err = expand_local(&pattern, "/tmp/out/", false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("matches no file"), "{err}");
        assert!(
            expand_local(&pattern, "/tmp/out/", true)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_pattern_needs_a_directory_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.csv"), "a").unwrap();
        let pattern = format!("{}/*.csv", dir.path().display());
        let err = expand_local(&pattern, "/tmp/out/one.csv", false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must be a directory"), "{err}");
        expand_local(&pattern, "mailto:a@example.com", false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn plain_jobs_pass_through_untouched() {
        let open = |l: &Location| crate::protocols::open(l.clone());
        let jobs = vec![Job {
            src: loc("/nonexistent/plain.bin"),
            dsts: vec![loc("/tmp/out/")],
        }];
        let out = expand(jobs, &open, false).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].src.path(), "/nonexistent/plain.bin");
    }
}

#[cfg(test)]
mod tree_tests {
    use super::*;

    fn loc(s: &str) -> Location {
        Location::parse(s).unwrap()
    }

    fn make_tree(root: &std::path::Path) {
        std::fs::create_dir_all(root.join("a/deep")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("top.txt"), "top").unwrap();
        std::fs::write(root.join("a/one.txt"), "one").unwrap();
        std::fs::write(root.join("a/deep/two.txt"), "two").unwrap();
    }

    #[tokio::test]
    async fn a_directory_source_becomes_a_job_per_file_plus_the_directories() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        make_tree(&src);
        let out = format!("{}/out/", dir.path().display());
        let open = |l: &Location| crate::protocols::open(l.clone());

        // Contents of `src/` into `out/`.
        let tree = recursive(
            vec![Job {
                src: loc(&format!("{}/", src.display())),
                dsts: vec![loc(&out)],
            }],
            &open,
        )
        .await
        .unwrap();
        let mut files: Vec<(String, String)> = tree
            .jobs
            .iter()
            .map(|j| (j.src.path().to_string(), j.dsts[0].path().to_string()))
            .collect();
        files.sort();
        assert_eq!(
            files,
            vec![
                (
                    format!("{}/a/deep/two.txt", src.display()),
                    format!("{out}a/deep/")
                ),
                (format!("{}/a/one.txt", src.display()), format!("{out}a/")),
                (format!("{}/top.txt", src.display()), out.clone()),
            ]
        );
        let dirs: Vec<String> = tree.dirs.iter().map(|d| d.path().to_string()).collect();
        assert_eq!(
            dirs,
            vec![
                format!("{out}a/"),
                format!("{out}empty/"),
                format!("{out}a/deep/")
            ]
        );

        create_dirs(&tree.dirs, &open).await.unwrap();
        assert!(dir.path().join("out/a/deep").is_dir());
        assert!(dir.path().join("out/empty").is_dir());

        // `src` without a slash goes to `out/src/…`.
        let tree = recursive(
            vec![Job {
                src: loc(src.to_str().unwrap()),
                dsts: vec![loc(&out)],
            }],
            &open,
        )
        .await
        .unwrap();
        assert_eq!(tree.dirs[0].path(), format!("{out}src/"));
        assert!(
            tree.jobs
                .iter()
                .all(|j| j.dsts[0].path().starts_with(&format!("{out}src/")))
        );
        assert_eq!(tree.jobs.len(), 3);
    }

    #[tokio::test]
    async fn a_file_source_passes_through_and_targets_must_be_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.txt"), "f").unwrap();
        let open = |l: &Location| crate::protocols::open(l.clone());
        let file = loc(dir.path().join("f.txt").to_str().unwrap());
        let tree = recursive(
            vec![Job {
                src: file.clone(),
                dsts: vec![loc("/tmp/out/")],
            }],
            &open,
        )
        .await
        .unwrap();
        assert_eq!(tree.jobs.len(), 1);
        assert!(tree.dirs.is_empty());
        let err = recursive(
            vec![Job {
                src: file,
                dsts: vec![loc("/tmp/out/one.txt")],
            }],
            &open,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("directory target"), "{err}");
    }
}
