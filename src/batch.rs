//! Many transfers in one run.
//!
//! A [`Job`] is one source with its targets, exactly what [`copy_many`] takes.
//! [`run`] pushes a list of them through the pipeline with a bounded number
//! in flight, and reports every one. Where the list comes from (arguments,
//! a file, standard input) is the caller's business; [`jobs`] parses the
//! textual forms.

pub mod expand;
pub mod jobs;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::transfer::{CopyOptions, FanoutReport, Progress};
use crate::{Endpoint, Error, Location, Result, copy_many};

/// One source and where it goes.
#[derive(Debug, Clone)]
pub struct Job {
    pub src: Location,
    pub dsts: Vec<Location>,
}

/// How [`run`] schedules the jobs.
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Jobs in flight at the same time. Every job opens its own connections,
    /// so this is also the number of simultaneous logins per host.
    pub parallel: usize,
    /// Stop starting jobs after the first failure and cancel the running ones.
    pub fail_fast: bool,
    /// Filled in while the batch runs, for a progress display.
    pub progress: Option<Arc<BatchProgress>>,
}

impl Default for BatchOptions {
    fn default() -> Self {
        BatchOptions {
            parallel: 4,
            fail_fast: false,
            progress: None,
        }
    }
}

/// Live counters of a running batch.
#[derive(Debug, Default)]
pub struct BatchProgress {
    total: AtomicUsize,
    done: AtomicUsize,
    failed: AtomicUsize,
    /// Fed by every job's source stream, so it is the sum over the batch.
    bytes: Arc<AtomicU64>,
}

impl BatchProgress {
    pub fn new() -> Arc<BatchProgress> {
        Arc::default()
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    pub fn done(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> usize {
        self.failed.load(Ordering::Relaxed)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// What became of one job. `result` is `Err` when the source could not be
/// read at all (or an endpoint could not be opened); per-target outcomes are
/// inside the report.
#[derive(Debug)]
pub struct JobReport {
    /// Position in the list the batch was started with.
    pub index: usize,
    pub job: Job,
    pub result: Result<FanoutReport>,
}

impl JobReport {
    /// Every target delivered, and the checksum (if checked) matched.
    pub fn ok(&self) -> bool {
        match &self.result {
            Ok(r) => r.all_ok() && r.checked.as_ref().is_none_or(|c| c.ok()),
            Err(_) => false,
        }
    }

    /// Whether the job was stopped rather than failed.
    pub fn cancelled(&self) -> bool {
        match &self.result {
            Ok(r) => r
                .targets
                .iter()
                .any(|t| matches!(t.result, Err(Error::Cancelled))),
            Err(Error::Cancelled) => true,
            Err(_) => false,
        }
    }
}

/// Outcome of [`run`], in the order the jobs were given.
#[derive(Debug)]
pub struct BatchReport {
    pub jobs: Vec<JobReport>,
    pub elapsed: Duration,
    /// `fail_fast` stopped the batch before every job had run.
    pub stopped_early: bool,
}

impl BatchReport {
    pub fn all_ok(&self) -> bool {
        self.jobs.iter().all(JobReport::ok)
    }

    pub fn failures(&self) -> impl Iterator<Item = &JobReport> {
        self.jobs.iter().filter(|j| !j.ok())
    }
}

/// The files a batch writes, to refuse a second job on any of them: two
/// jobs on one file would share a `.mpt-part` and destroy each other's
/// upload. Mail targets are exempt, a mailbox can take the same attachment
/// twice.
#[derive(Debug, Default)]
pub struct Targets {
    seen: std::collections::HashMap<String, usize>,
}

impl Targets {
    /// Note the targets of job number `index` (1-based, for the message),
    /// or say which earlier job already writes one of them.
    pub fn note(&mut self, job: &Job, index: usize) -> Result<()> {
        for dst in &job.dsts {
            let Some(key) = key(dst, &job.src)? else {
                continue;
            };
            if let Some(first) = self.seen.insert(key, index) {
                return Err(Error::InvalidUrl(format!(
                    "jobs {first} and {index} write the same target {}",
                    dst.sibling(job.src.filename().unwrap_or(""))
                        .map(|l| l.to_string())
                        .unwrap_or_else(|_| dst.to_string())
                )));
            }
        }
        Ok(())
    }

    /// Forget the targets of a job that is over, so a later job may write
    /// them again (a server that runs jobs as they come in).
    pub fn release(&mut self, job: &Job) {
        for dst in &job.dsts {
            if let Ok(Some(key)) = key(dst, &job.src) {
                self.seen.remove(&key);
            }
        }
    }
}

/// What identifies the file a target writes: scheme, host, port and the
/// final path. `None` for a mail target, which is exempt.
fn key(dst: &Location, src: &Location) -> Result<Option<String>> {
    if dst.scheme().is_mail() {
        return Ok(None);
    }
    let path = dst.target_path(src.filename())?;
    Ok(Some(format!(
        "{}|{}|{}|{}",
        dst.scheme(),
        dst.host().unwrap_or(""),
        dst.port_or_default(),
        path
    )))
}

/// How [`prepare`] turns a job list into file jobs.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrepareOptions {
    /// A source pattern that matches nothing contributes no jobs instead
    /// of being an error.
    pub allow_empty: bool,
    /// A directory source stands for every file below it.
    pub recursive: bool,
    /// Leave the directories a tree needs uncreated (a dry run).
    pub no_mkdir: bool,
}

/// Patterns and trees turned into file jobs, and the directories a tree
/// needs created on the way. Jobs that are plain files pass through.
pub async fn prepare(
    jobs: Vec<Job>,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
    opts: &PrepareOptions,
) -> Result<Vec<Job>> {
    let jobs = expand::expand(jobs, open, opts.allow_empty).await?;
    if !opts.recursive {
        return Ok(jobs);
    }
    let tree = expand::recursive(jobs, open).await?;
    if !opts.no_mkdir {
        expand::create_dirs(&tree.dirs, open).await?;
    }
    Ok(tree.jobs)
}

/// Refuse a list in which two jobs would write the same file.
pub fn check_collisions(jobs: &[Job]) -> Result<()> {
    let mut targets = Targets::default();
    for (i, job) in jobs.iter().enumerate() {
        targets.note(job, i + 1)?;
    }
    Ok(())
}

/// Run every job, at most `opts.parallel` at a time.
///
/// `open` turns a location into an endpoint; it is called when a job starts,
/// not up front, so a long list does not hold a client per endpoint in
/// memory. `on_done` sees each report as soon as its job finishes, in
/// completion order; the returned report is in list order.
pub async fn run(
    jobs: Vec<Job>,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
    copy: &CopyOptions,
    opts: &BatchOptions,
    on_done: impl FnMut(&JobReport),
) -> BatchReport {
    if let Some(p) = &opts.progress {
        p.total.store(jobs.len(), Ordering::Relaxed);
    }
    run_stream(futures::stream::iter(jobs), open, copy, opts, on_done).await
}

/// [`run`] for jobs that arrive while the batch runs (a list read from a
/// pipe): each is started as soon as it is there and a slot is free, and
/// the batch ends when the stream does and the last job is done. The
/// progress total stays unknown (zero) unless the caller sets it.
pub async fn run_stream(
    jobs: impl Stream<Item = Job> + Unpin,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
    copy: &CopyOptions,
    opts: &BatchOptions,
    mut on_done: impl FnMut(&JobReport),
) -> BatchReport {
    let started = Instant::now();
    // A token of the batch's own, under the caller's: Ctrl-C stops everything
    // through the parent, fail-fast through this one.
    let stop = match &copy.cancel {
        Some(c) => c.child_token(),
        None => CancellationToken::new(),
    };
    let stopped_early = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let parallel = opts.parallel.max(1);
    info!(parallel, "batch");

    let mut reports: Vec<JobReport> = Vec::new();
    let mut running = jobs
        .enumerate()
        .map(|(index, job)| {
            let stop = stop.clone();
            let stopped_early = Arc::clone(&stopped_early);
            async move {
                if stop.is_cancelled() {
                    return JobReport {
                        index,
                        job,
                        result: Err(Error::Cancelled),
                    };
                }
                let mut per_job = copy.clone();
                per_job.cancel = Some(stop.clone());
                if let Some(p) = &opts.progress {
                    per_job.progress = Some(Progress::with_counter(Arc::clone(&p.bytes)));
                }
                let result = run_job(&job, open, &per_job).await;
                let report = JobReport { index, job, result };
                if opts.fail_fast && !report.ok() && !report.cancelled() {
                    warn!(job = index + 1, "failed, stopping the batch");
                    stopped_early.store(true, Ordering::Relaxed);
                    stop.cancel();
                }
                report
            }
        })
        .buffer_unordered(parallel);
    while let Some(report) = running.next().await {
        if let Some(p) = &opts.progress {
            p.done.fetch_add(1, Ordering::Relaxed);
            if !report.ok() {
                p.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
        on_done(&report);
        reports.push(report);
    }
    reports.sort_by_key(|r| r.index);
    BatchReport {
        jobs: reports,
        elapsed: started.elapsed(),
        stopped_early: stopped_early.load(Ordering::Relaxed),
    }
}

/// Run one job: open its endpoints and copy. This is what [`run`] does per
/// job; on its own it is for a caller that schedules jobs itself.
pub async fn run_job(
    job: &Job,
    open: &(dyn Fn(&Location) -> Result<Box<dyn Endpoint>> + Sync),
    copy: &CopyOptions,
) -> Result<FanoutReport> {
    let src = open(&job.src)?;
    let dsts = job.dsts.iter().map(open).collect::<Result<Vec<_>>>()?;
    let refs: Vec<&dyn Endpoint> = dsts.iter().map(|d| d.as_ref()).collect();
    copy_many(src.as_ref(), &refs, copy).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(src: &str, dsts: &[&str]) -> Job {
        Job {
            src: Location::parse(src).unwrap(),
            dsts: dsts.iter().map(|d| Location::parse(d).unwrap()).collect(),
        }
    }

    #[test]
    fn same_file_from_two_jobs_is_refused() {
        let jobs = vec![
            job("/tmp/a/x.bin", &["sftp://h/in/"]),
            job("/tmp/b/y.bin", &["sftp://h/in/"]),
            job("/tmp/c/x.bin", &["sftp://h/in/"]),
        ];
        let err = check_collisions(&jobs).unwrap_err().to_string();
        assert!(err.contains("jobs 1 and 3"), "{err}");
        assert!(err.contains("sftp://h/in/x.bin"), "{err}");
    }

    #[test]
    fn a_released_target_can_be_written_again() {
        let a = job("/tmp/a/x.bin", &["sftp://h/in/"]);
        let b = job("/tmp/b/x.bin", &["sftp://h/in/"]);
        let mut targets = Targets::default();
        targets.note(&a, 1).unwrap();
        assert!(targets.note(&b, 2).is_err());
        targets.release(&a);
        targets.note(&b, 2).unwrap();
    }

    #[test]
    fn explicit_file_targets_collide_too() {
        let jobs = vec![
            job("/tmp/a/x.bin", &["sftp://h/in/same.bin"]),
            job("/tmp/b/y.bin", &["sftp://h/in/same.bin"]),
        ];
        assert!(check_collisions(&jobs).is_err());
    }

    #[test]
    fn different_hosts_ports_and_mail_do_not_collide() {
        let jobs = vec![
            job("/tmp/a/x.bin", &["sftp://h/in/", "mailto:a@example.com"]),
            job(
                "/tmp/b/x.bin",
                &["sftp://h:2222/in/", "mailto:a@example.com"],
            ),
            job("/tmp/c/x.bin", &["sftp://other/in/"]),
        ];
        check_collisions(&jobs).unwrap();
    }

    #[tokio::test]
    async fn runs_every_job_and_keeps_list_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut jobs = Vec::new();
        for i in 0..10 {
            let src = dir.path().join(format!("src{i}.bin"));
            std::fs::write(&src, format!("payload {i}")).unwrap();
            let dst = dir.path().join(format!("out{i}"));
            std::fs::create_dir(&dst).unwrap();
            jobs.push(job(
                src.to_str().unwrap(),
                &[&format!("{}/", dst.display())],
            ));
        }
        // One source that does not exist: its job fails, the rest go through.
        jobs.push(job(
            dir.path().join("missing.bin").to_str().unwrap(),
            &[&format!("{}/", dir.path().display())],
        ));
        let open = |l: &Location| crate::protocols::open(l.clone());
        let progress = BatchProgress::new();
        let opts = BatchOptions {
            parallel: 3,
            progress: Some(Arc::clone(&progress)),
            ..Default::default()
        };
        let mut seen = 0;
        let report = run(jobs, &open, &CopyOptions::default(), &opts, |_| seen += 1).await;
        assert_eq!(seen, 11);
        assert_eq!(report.jobs.len(), 11);
        for (i, j) in report.jobs.iter().enumerate() {
            assert_eq!(j.index, i);
        }
        assert_eq!(report.failures().count(), 1);
        assert!(!report.jobs[10].ok());
        assert!(!report.stopped_early);
        assert_eq!(progress.done(), 11);
        assert_eq!(progress.failed(), 1);
        assert_eq!(
            progress.bytes(),
            (0..10)
                .map(|i| format!("payload {i}").len() as u64)
                .sum::<u64>()
        );
        for i in 0..10 {
            let got = std::fs::read(dir.path().join(format!("out{i}/src{i}.bin"))).unwrap();
            assert_eq!(got, format!("payload {i}").as_bytes());
        }
    }

    #[tokio::test]
    async fn a_stream_of_jobs_is_run_as_it_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let out = format!("{}/out/", dir.path().display());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Job>();
        let feeder = {
            let dir = dir.path().to_path_buf();
            let out = out.clone();
            tokio::spawn(async move {
                for i in 0..5 {
                    let src = dir.join(format!("s{i}.bin"));
                    std::fs::write(&src, format!("{i}")).unwrap();
                    tx.send(job(src.to_str().unwrap(), &[&out])).unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        };
        let open = |l: &Location| crate::protocols::open(l.clone());
        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
        let report = run_stream(
            stream,
            &open,
            &CopyOptions::default(),
            &BatchOptions::default(),
            |_| {},
        )
        .await;
        feeder.await.unwrap();
        assert_eq!(report.jobs.len(), 5);
        assert!(report.all_ok());
        for i in 0..5 {
            assert_eq!(
                std::fs::read(dir.path().join(format!("out/s{i}.bin"))).unwrap(),
                format!("{i}").as_bytes()
            );
        }
    }

    #[tokio::test]
    async fn fail_fast_stops_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let out = format!("{}/", dir.path().display());
        let mut jobs = vec![job(
            dir.path().join("missing.bin").to_str().unwrap(),
            &[&out],
        )];
        for i in 0..5 {
            let src = dir.path().join(format!("src{i}.bin"));
            std::fs::write(&src, "x").unwrap();
            jobs.push(job(src.to_str().unwrap(), &[&out]));
        }
        let open = |l: &Location| crate::protocols::open(l.clone());
        let opts = BatchOptions {
            parallel: 1,
            fail_fast: true,
            progress: None,
        };
        let report = run(jobs, &open, &CopyOptions::default(), &opts, |_| {}).await;
        assert!(report.stopped_early);
        assert!(!report.jobs[0].ok() && !report.jobs[0].cancelled());
        assert!(report.jobs[1..].iter().all(JobReport::cancelled));
    }
}
