//! Turning one job into many: a pattern in the source's file name stands
//! for every file in that directory whose name matches, and with
//! [`recursive`] a directory stands for every file below it.

use glob::{MatchOptions, Pattern};
use tracing::{debug, info, warn};

use crate::{Endpoint, Error, Location, Result};

use super::Job;

/// Whether the last path component of `loc` needs [`expand`]: a pattern
/// (`*`, or `[…]` with its closing bracket), or a name with a character
/// escaped by `\` that `expand` turns into the plain name. `?` does not
/// count: in a URL it starts the query.
pub fn has_pattern(loc: &Location) -> bool {
    !loc.scheme().is_mail()
        && !loc.is_dir_target()
        && loc.filename().is_some_and(|n| {
            let name = Name::parse(n);
            name.wild || name.escaped
        })
}

/// A source's file name, read as a pattern.
#[derive(Debug, PartialEq, Eq)]
struct Name {
    /// The name for the glob matcher, with every character meant
    /// literally in brackets (`[*]`, `[[]`).
    pattern: String,
    /// It has a `*` or a character class: it stands for several files.
    wild: bool,
    /// The name with its escapes resolved, for a name that is not wild.
    literal: String,
    /// It had a `\` escape.
    escaped: bool,
}

impl Name {
    /// `*` is any run of characters and `[…]` a class, as in a shell. A
    /// `\` before `*`, `?`, `[`, `]` or `\` makes that character literal;
    /// so does writing it in brackets (`[*]`), which also works where `\`
    /// separates or cannot be written. A `[` without its `]` is literal,
    /// and so is `?`, which in a URL starts the query.
    fn parse(name: &str) -> Name {
        let chars: Vec<char> = name.chars().collect();
        let mut out = Name {
            pattern: String::new(),
            wild: false,
            literal: String::new(),
            escaped: false,
        };
        let literal = |out: &mut Name, c: char| {
            out.literal.push(c);
            match c {
                '*' | '?' | '[' | ']' => {
                    out.pattern.push('[');
                    out.pattern.push(c);
                    out.pattern.push(']');
                }
                _ => out.pattern.push(c),
            }
        };
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            match c {
                '\\' if matches!(chars.get(i + 1), Some('*' | '?' | '[' | ']' | '\\')) => {
                    out.escaped = true;
                    literal(&mut out, chars[i + 1]);
                    i += 2;
                    continue;
                }
                '*' => {
                    out.wild = true;
                    out.pattern.push('*');
                }
                '[' => match class_end(&chars, i) {
                    Some(end) => {
                        out.wild = true;
                        out.pattern.extend(&chars[i..=end]);
                        i = end + 1;
                        continue;
                    }
                    None => literal(&mut out, c),
                },
                _ => literal(&mut out, c),
            }
            i += 1;
        }
        out
    }
}

/// Where the class that opens at `chars[start]` (a `[`) closes, as the
/// glob matcher reads it: a `]` right after `[` or `[!` belongs to the
/// class. `None` when it does not close.
fn class_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    if chars.get(i) == Some(&'!') {
        i += 1;
    }
    if chars.get(i) == Some(&']') {
        i += 1;
    }
    (i..chars.len()).find(|&j| chars[j] == ']')
}

/// Expand every job whose source is a pattern into one job per matching
/// file. Jobs without a pattern pass through unchanged, in place. A pattern
/// that matches nothing is an error unless `allow_empty` is set, in which
/// case it contributes no jobs.
pub async fn expand(
    jobs: Vec<Job>,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
    allow_empty: bool,
    limit: Option<usize>,
) -> Result<Vec<Job>> {
    let mut out = Vec::with_capacity(jobs.len());
    for mut job in jobs {
        if !has_pattern(&job.src) {
            check_limit(out.len() + 1, limit, &job.src)?;
            out.push(job);
            continue;
        }
        let name = Name::parse(job.src.filename().unwrap_or(""));
        if !name.wild {
            // Only escapes: the one file of that name.
            job.src = job.src.sibling(&name.literal)?;
            check_limit(out.len() + 1, limit, &job.src)?;
            out.push(job);
            continue;
        }
        let matches = matching_files(&job.src, &name.pattern, open).await?;
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
            check_limit(out.len(), limit, &job.src)?;
        }
    }
    Ok(out)
}

/// The text a job list over the limit is refused with; a server maps it
/// to its own error kind by this prefix.
pub const OVER_LIMIT: &str = "more files than the limit allows";

fn check_limit(count: usize, limit: Option<usize>, source: &Location) -> Result<()> {
    match limit {
        Some(max) if count > max => Err(Error::InvalidUrl(format!(
            "{OVER_LIMIT} ({max}) at {source}"
        ))),
        _ => Ok(()),
    }
}

/// The files in the directory of `pattern` whose names match it, as
/// locations, in listing order.
async fn matching_files(
    pattern: &Location,
    glob: &str,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
) -> Result<Vec<Location>> {
    let name = pattern.filename().unwrap_or("");
    let glob = Pattern::new(glob)
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
            Err(err) => {
                warn!(name = %e.name, "skipping a listed name that cannot be copied: {err}")
            }
        }
    }
    info!(matches = found.len(), "pattern expanded");
    debug!(%pattern, "pattern expanded");
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
    limit: Option<usize>,
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
            check_limit(tree.jobs.len() + 1, limit, src)?;
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
                            check_limit(tree.dirs.len(), limit, src)?;
                            subdirs.push((sub, sub_rel, depth + 1));
                        }
                        Err(err) => {
                            warn!(name = %e.name, "skipping a listed name that cannot be copied: {err}")
                        }
                    }
                    continue;
                }
                match dir.join(&e.name) {
                    Ok(file) => {
                        tree.jobs.push(Job {
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
                        });
                        check_limit(tree.jobs.len(), limit, src)?;
                    }
                    Err(err) => {
                        warn!(name = %e.name, "skipping a listed name that cannot be copied: {err}")
                    }
                }
            }
            // Pushed in reverse so the listing order comes back out.
            stack.extend(subdirs.into_iter().rev());
        }
        info!(
            files = tree.jobs.len(),
            dirs = tree.dirs.len(),
            "tree expanded"
        );
        debug!(source = %src, "tree expanded");
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

    #[tokio::test]
    async fn the_limit_stops_a_tree_early() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..4 {
            std::fs::write(dir.path().join(format!("f{i}")), "x").unwrap();
        }
        let job = Job {
            src: loc(&format!("{}/", dir.path().display())),
            dsts: vec![loc("/tmp/out/")],
        };
        let open = |l: &Location| crate::protocols::open(l.clone());
        let err = recursive(vec![job.clone()], &open, Some(2))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(OVER_LIMIT), "{err}");
        assert_eq!(
            recursive(vec![job], &open, Some(4))
                .await
                .unwrap()
                .jobs
                .len(),
            4
        );
    }

    #[test]
    fn patterns_are_recognized_in_the_file_name_only() {
        assert!(has_pattern(&loc("sftp://h/in/*.csv")));
        assert!(has_pattern(&loc("/tmp/in/report[0-9].bin")));
        assert!(!has_pattern(&loc("sftp://h/in/plain.csv")));
        assert!(!has_pattern(&loc("sftp://h/in/")));
        assert!(!has_pattern(&loc("mailto:a@example.com")));
        // A `[` that does not close is a character like any other.
        assert!(!has_pattern(&loc("/tmp/in/report[1.csv")));
        // An escape needs `expand`, to become the plain name.
        assert!(has_pattern(&loc(r"/tmp/in/report\[1\].csv")));
    }

    #[test]
    fn a_name_is_read_with_its_escapes_and_classes() {
        let n = Name::parse(r"report\[1\].csv");
        assert!(!n.wild && n.escaped);
        assert_eq!(n.literal, "report[1].csv");
        let n = Name::parse(r"a\*b");
        assert_eq!((n.wild, n.literal.as_str()), (false, "a*b"));
        let n = Name::parse(r"a\*b*.csv");
        assert!(n.wild);
        assert_eq!(n.pattern, "a[*]b*.csv");
        let n = Name::parse("report[1.csv");
        assert!(!n.wild && !n.escaped);
        assert_eq!(n.pattern, "report[[]1.csv");
        let n = Name::parse("x[]a].csv");
        assert!(n.wild);
        assert_eq!(n.pattern, "x[]a].csv");
        let n = Name::parse("a[*]b");
        assert!(n.wild, "a class of one is still a class");
        // `?` is a character, and a `\` before anything else is kept.
        let n = Name::parse(r"what?\n*");
        assert_eq!(n.pattern, r"what[?]\n*");
    }

    #[tokio::test]
    async fn escaped_and_bracketed_characters_match_themselves() {
        let dir = tempfile::tempdir().unwrap();
        for n in ["report[1].csv", "report1.csv", "a*b", "ab", "x[1.csv"] {
            std::fs::write(dir.path().join(n), n).unwrap();
        }
        let d = dir.path().display();
        let names = |jobs: Vec<Job>| {
            let mut v: Vec<String> = jobs
                .iter()
                .map(|j| j.src.filename().unwrap().to_string())
                .collect();
            v.sort();
            v
        };
        // Escapes alone name one file, which need not be listed.
        let jobs = expand_local(&format!(r"{d}/report\[1\].csv"), "/tmp/out/x", false)
            .await
            .unwrap();
        assert_eq!(names(jobs), ["report[1].csv"]);
        let jobs = expand_local(&format!(r"{d}/a\*b"), "/tmp/out/x", false)
            .await
            .unwrap();
        assert_eq!(names(jobs), ["a*b"]);
        // Brackets work as well, and in a pattern with a wildcard.
        let jobs = expand_local(&format!("{d}/report[[]1[]].*"), "/tmp/out/", false)
            .await
            .unwrap();
        assert_eq!(names(jobs), ["report[1].csv"]);
        let jobs = expand_local(&format!(r"{d}/report\[*"), "/tmp/out/", false)
            .await
            .unwrap();
        assert_eq!(names(jobs), ["report[1].csv"]);
        // An unbalanced `[` is taken literally.
        let jobs = expand_local(&format!("{d}/x[1.*"), "/tmp/out/", false)
            .await
            .unwrap();
        assert_eq!(names(jobs), ["x[1.csv"]);
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
            None,
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
        let out = expand(jobs, &open, false, None).await.unwrap();
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("directory target"), "{err}");
    }
}
