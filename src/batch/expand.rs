//! Turning one job into many: a pattern in the source's file name stands
//! for every file in that directory whose name matches.

use glob::{MatchOptions, Pattern};
use tracing::{debug, info};

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
