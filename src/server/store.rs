//! Where the server keeps its jobs: in memory, with every change published
//! as an [`Event`], and optionally in a journal on disk so that a job the
//! server was stopped in the middle of runs again after a restart.
//!
//! The store is lock-only: nothing is awaited while it is held, so any
//! task may call in from anywhere.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::model::{
    ApiError, ByteProgress, Event, JobId, JobProgress, JobSnapshot, JobState, Submission,
    TransferCounts, TransferProgress, TransferSnapshot, TransferState,
};
use crate::batch::{Job, JobReport};
use crate::sign::{format_time, parse_time};
use crate::transfer::Progress;
use crate::{Error, Result};

/// One job as the store holds it.
struct JobEntry {
    submission: Submission,
    state: JobState,
    submitted_at: SystemTime,
    started_at: Option<SystemTime>,
    finished_at: Option<SystemTime>,
    attempt: u32,
    stopped_early: bool,
    error: Option<ApiError>,
    transfers: Vec<TransferEntry>,
    /// Fires when the job is cancelled (by a request, or by the server
    /// giving up on a drain); every copy of the job runs under a child.
    cancel: CancellationToken,
}

/// A transfer ready to run, with its endpoints as clients see them: the
/// `mpt://` reference that was submitted where there was one, else the
/// location with its password masked.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub job: Job,
    pub src: String,
    pub dsts: Vec<String>,
}

struct TransferEntry {
    src: String,
    dsts: Vec<String>,
    state: TransferState,
    started_at: Option<SystemTime>,
    finished_at: Option<SystemTime>,
    progress: Arc<Progress>,
    report: Option<serde_json::Value>,
    error: Option<ApiError>,
}

impl TransferEntry {
    fn snapshot(&self, id: &JobId, index: usize) -> TransferSnapshot {
        TransferSnapshot {
            index,
            id: format!("{id}:{index}"),
            src: self.src.clone(),
            dst: self.dsts.clone(),
            state: self.state,
            started_at: self.started_at.map(format_time),
            finished_at: self.finished_at.map(format_time),
            progress: ByteProgress {
                read: self.progress.read(),
                total: self.progress.total(),
            },
            report: self.report.clone(),
            error: self.error.clone(),
        }
    }
}

impl JobEntry {
    fn progress(&self) -> JobProgress {
        let mut counts = TransferCounts {
            total: self.transfers.len(),
            ..Default::default()
        };
        let mut bytes = 0;
        let mut total = Some(0);
        for t in &self.transfers {
            match t.state {
                TransferState::Queued => counts.queued += 1,
                TransferState::Running => counts.running += 1,
                TransferState::Done => counts.done += 1,
                TransferState::Failed => counts.failed += 1,
                TransferState::Cancelled => counts.cancelled += 1,
            }
            bytes += t.progress.read();
            total = match (total, t.progress.total()) {
                (Some(a), Some(b)) => Some(a + b),
                _ => None,
            };
        }
        JobProgress {
            bytes,
            total: total.filter(|_| !self.transfers.is_empty()),
            transfers: counts,
        }
    }

    fn snapshot(&self, id: &JobId, with_transfers: bool) -> JobSnapshot {
        JobSnapshot {
            id: id.clone(),
            kind: self.submission.kind,
            state: self.state,
            submitted_at: format_time(self.submitted_at),
            started_at: self.started_at.map(format_time),
            finished_at: self.finished_at.map(format_time),
            attempt: self.attempt,
            options: self.submission.options.clone(),
            stopped_early: self.stopped_early,
            error: self.error.clone(),
            progress: self.progress(),
            transfers: with_transfers.then(|| {
                self.transfers
                    .iter()
                    .enumerate()
                    .map(|(i, t)| t.snapshot(id, i))
                    .collect()
            }),
        }
    }
}

struct Inner {
    jobs: HashMap<JobId, JobEntry>,
    /// Submission order, oldest first.
    order: Vec<JobId>,
}

/// The jobs the server knows about.
pub struct Store {
    inner: Mutex<Inner>,
    events: broadcast::Sender<Event>,
    journal: Option<Journal>,
    /// How many jobs are not over yet, for a shutdown that waits.
    unfinished: watch::Sender<usize>,
}

/// A job the journal says was open when the server last stopped.
#[derive(Debug, Clone)]
pub struct Recovered {
    pub id: JobId,
    pub submitted_at: SystemTime,
    pub attempt: u32,
    pub submission: Submission,
}

impl Store {
    pub fn new(journal: Option<Journal>, events: broadcast::Sender<Event>) -> Store {
        Store {
            inner: Mutex::new(Inner {
                jobs: HashMap::new(),
                order: Vec::new(),
            }),
            events,
            journal,
            unfinished: watch::Sender::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Tell every subscriber. No receiver is no error: nobody is
    /// watching right now.
    pub fn publish(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn emit(&self, event: Event) {
        self.publish(event);
    }

    fn insert(&self, id: JobId, entry: JobEntry) {
        let mut inner = self.lock();
        inner.order.push(id.clone());
        inner.jobs.insert(id.clone(), entry);
        let n = inner.jobs.values().filter(|j| !j.state.is_final()).count();
        drop(inner);
        self.unfinished.send_replace(n);
        self.emit(Event::Queued { id });
    }

    /// Take a new job, journal it, and say which id it got.
    pub fn submit(&self, submission: Submission, cancel: CancellationToken) -> Result<JobId> {
        let id = JobId::new();
        let now = SystemTime::now();
        if let Some(j) = &self.journal {
            j.write(&Record::Submitted {
                id: id.clone(),
                at: format_time(now),
                attempt: 1,
                submission: submission.clone(),
            })?;
        }
        self.insert(
            id.clone(),
            JobEntry {
                submission,
                state: JobState::Queued,
                submitted_at: now,
                started_at: None,
                finished_at: None,
                attempt: 1,
                stopped_early: false,
                error: None,
                transfers: Vec::new(),
                cancel,
            },
        );
        Ok(id)
    }

    /// Put back a job the journal handed over; it is already in the file.
    pub fn recover(&self, r: Recovered, cancel: CancellationToken) {
        self.insert(
            r.id,
            JobEntry {
                submission: r.submission,
                state: JobState::Queued,
                submitted_at: r.submitted_at,
                started_at: None,
                finished_at: None,
                attempt: r.attempt,
                stopped_early: false,
                error: None,
                transfers: Vec::new(),
                cancel,
            },
        );
    }

    /// What the job asked for, and its cancellation token.
    pub fn submission(&self, id: &JobId) -> Option<(Submission, CancellationToken)> {
        let inner = self.lock();
        let j = inner.jobs.get(id)?;
        Some((j.submission.clone(), j.cancel.clone()))
    }

    pub fn set_preparing(&self, id: &JobId) {
        let mut inner = self.lock();
        if let Some(j) = inner.jobs.get_mut(id)
            && !j.state.is_final()
        {
            j.state = JobState::Preparing;
        }
    }

    /// Preparation is over: these are the transfers. Their progress
    /// counters are handed back for the copies to feed.
    pub fn start(&self, id: &JobId, jobs: Vec<Prepared>) -> Vec<Arc<Progress>> {
        let mut inner = self.lock();
        let Some(j) = inner.jobs.get_mut(id) else {
            return Vec::new();
        };
        j.state = JobState::Running;
        j.started_at = Some(SystemTime::now());
        j.transfers = jobs
            .into_iter()
            .map(|p| TransferEntry {
                src: p.src,
                dsts: p.dsts,
                state: TransferState::Queued,
                started_at: None,
                finished_at: None,
                progress: Progress::new(),
                report: None,
                error: None,
            })
            .collect();
        let counters = j
            .transfers
            .iter()
            .map(|t| Arc::clone(&t.progress))
            .collect();
        let n = j.transfers.len();
        drop(inner);
        self.emit(Event::Started {
            id: id.clone(),
            transfers: n,
        });
        counters
    }

    pub fn transfer_started(&self, id: &JobId, index: usize) {
        let mut inner = self.lock();
        if let Some(t) = inner
            .jobs
            .get_mut(id)
            .and_then(|j| j.transfers.get_mut(index))
        {
            t.state = TransferState::Running;
            t.started_at = Some(SystemTime::now());
        }
        drop(inner);
        self.emit(Event::TransferStarted {
            id: id.clone(),
            index,
        });
    }

    /// A transfer is over. The state comes from the report: cancelled beats
    /// failed beats done. `json` and `error` are the report and the failure
    /// as clients see them (see [`crate::report::fanout_json`] and
    /// [`transfer_error`]), rendered by the caller so that it can name the
    /// endpoints as they were submitted.
    pub fn transfer_done(
        &self,
        id: &JobId,
        report: &JobReport,
        json: Option<serde_json::Value>,
        error: Option<ApiError>,
    ) -> TransferState {
        let state = if report.cancelled() {
            TransferState::Cancelled
        } else if report.ok() {
            TransferState::Done
        } else {
            TransferState::Failed
        };
        let mut inner = self.lock();
        let Some(t) = inner
            .jobs
            .get_mut(id)
            .and_then(|j| j.transfers.get_mut(report.index))
        else {
            return state;
        };
        t.state = state;
        t.finished_at = Some(SystemTime::now());
        t.report = json;
        t.error = error;
        let snapshot = t.snapshot(id, report.index);
        drop(inner);
        self.emit(Event::TransferDone {
            id: id.clone(),
            index: report.index,
            state,
            transfer: Box::new(snapshot),
        });
        state
    }

    /// A transfer ended without a report (its task panicked): failed, with
    /// `error`, unless it is over already.
    pub fn transfer_lost(&self, id: &JobId, index: usize, error: ApiError) {
        let mut inner = self.lock();
        let Some(t) = inner
            .jobs
            .get_mut(id)
            .and_then(|j| j.transfers.get_mut(index))
            .filter(|t| !t.state.is_final())
        else {
            return;
        };
        t.state = TransferState::Failed;
        t.finished_at = Some(SystemTime::now());
        t.error = Some(error);
        let snapshot = t.snapshot(id, index);
        drop(inner);
        self.emit(Event::TransferDone {
            id: id.clone(),
            index,
            state: TransferState::Failed,
            transfer: Box::new(snapshot),
        });
    }

    pub fn set_stopped_early(&self, id: &JobId) {
        if let Some(j) = self.lock().jobs.get_mut(id) {
            j.stopped_early = true;
        }
    }

    /// The job is over. Its state follows its transfers: failed if one
    /// failed and `fail_fast` stopped the rest, else cancelled if any was
    /// (or none ran because the job was cancelled first), else failed if
    /// any failed, else done. `journal` is false for a job the server is
    /// abandoning at shutdown, which should run again after the restart.
    pub fn finish(&self, id: &JobId, journal: bool) -> Option<JobState> {
        let mut inner = self.lock();
        let j = inner.jobs.get_mut(id)?;
        if j.state.is_final() {
            return Some(j.state);
        }
        let states = j.transfers.iter().map(|t| t.state);
        let failed = states.clone().any(|s| s == TransferState::Failed);
        let unfinished = j.transfers.is_empty() || states.clone().any(|s| !s.is_final());
        // A job that stopped itself after a failure failed; one that was
        // stopped from outside was cancelled.
        let state = if failed && j.stopped_early {
            JobState::Failed
        } else if states.clone().any(|s| s == TransferState::Cancelled)
            || (unfinished && j.cancel.is_cancelled())
        {
            JobState::Cancelled
        } else if failed {
            JobState::Failed
        } else {
            JobState::Done
        };
        drop(inner);
        self.close(id, state, None, journal)
    }

    /// The job failed before any transfer ran.
    pub fn fail(&self, id: &JobId, error: ApiError, journal: bool) -> Option<JobState> {
        let state = if error.kind == "cancelled" {
            JobState::Cancelled
        } else {
            JobState::Failed
        };
        self.close(id, state, Some(error), journal)
    }

    fn close(
        &self,
        id: &JobId,
        state: JobState,
        error: Option<ApiError>,
        journal: bool,
    ) -> Option<JobState> {
        let now = SystemTime::now();
        let mut inner = self.lock();
        let j = inner.jobs.get_mut(id)?;
        if j.state.is_final() {
            return Some(j.state);
        }
        j.state = state;
        j.finished_at = Some(now);
        j.error = error;
        // Whatever is still queued did not run.
        for t in &mut j.transfers {
            if !t.state.is_final() {
                t.state = TransferState::Cancelled;
                t.finished_at = Some(now);
            }
        }
        let summary = j.snapshot(id, false);
        let n = inner.jobs.values().filter(|j| !j.state.is_final()).count();
        drop(inner);
        self.unfinished.send_replace(n);
        if journal
            && let Some(jr) = &self.journal
            && let Err(e) = jr.write(&Record::Done {
                id: id.clone(),
                at: format_time(now),
                state,
            })
        {
            warn!(%id, "journal: {e}");
        }
        self.emit(Event::Done {
            id: id.clone(),
            state,
            job: Box::new(summary),
        });
        Some(state)
    }

    /// Ask a job to stop. The state it was in comes back: a job that is
    /// already over is left as it is.
    pub fn cancel(&self, id: &JobId) -> Option<JobState> {
        let inner = self.lock();
        let j = inner.jobs.get(id)?;
        let state = j.state;
        if !state.is_final() {
            info!(%id, "cancelling");
            j.cancel.cancel();
        }
        Some(state)
    }

    pub fn snapshot(&self, id: &JobId, with_transfers: bool) -> Option<JobSnapshot> {
        let inner = self.lock();
        inner.jobs.get(id).map(|j| j.snapshot(id, with_transfers))
    }

    pub fn transfer(&self, id: &JobId, index: usize) -> Option<TransferSnapshot> {
        let inner = self.lock();
        inner
            .jobs
            .get(id)?
            .transfers
            .get(index)
            .map(|t| t.snapshot(id, index))
    }

    /// Job summaries, newest first, at most `limit`.
    pub fn list(&self, state: Option<JobState>, limit: usize) -> Vec<JobSnapshot> {
        let inner = self.lock();
        inner
            .order
            .iter()
            .rev()
            .filter_map(|id| inner.jobs.get(id).map(|j| (id, j)))
            .filter(|(_, j)| state.is_none_or(|s| j.state == s))
            .take(limit)
            .map(|(id, j)| j.snapshot(id, false))
            .collect()
    }

    /// Jobs by state, for the health check: (not started, in progress).
    pub fn counts(&self) -> (usize, usize) {
        let inner = self.lock();
        inner.jobs.values().fold((0, 0), |(q, r), j| match j.state {
            JobState::Queued => (q + 1, r),
            JobState::Preparing | JobState::Running => (q, r + 1),
            _ => (q, r),
        })
    }

    /// The bytes of every running job, for the progress ticker.
    pub fn running_progress(&self) -> Vec<(JobId, u64, Vec<TransferProgress>)> {
        let inner = self.lock();
        inner
            .jobs
            .iter()
            .filter(|(_, j)| j.state == JobState::Running)
            .map(|(id, j)| {
                let bytes = j.transfers.iter().map(|t| t.progress.read()).sum();
                let running = j
                    .transfers
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| t.state == TransferState::Running)
                    .map(|(index, t)| TransferProgress {
                        index,
                        read: t.progress.read(),
                        total: t.progress.total(),
                    })
                    .collect();
                (id.clone(), bytes, running)
            })
            .collect()
    }

    /// Forget finished jobs older than `retention`; returns how many.
    pub fn sweep(&self, retention: Duration) -> usize {
        let cutoff = SystemTime::now().checked_sub(retention);
        let mut inner = self.lock();
        let before = inner.jobs.len();
        inner.jobs.retain(|_, j| {
            !(j.state.is_final() && j.finished_at.is_some_and(|t| cutoff.is_some_and(|c| t < c)))
        });
        let jobs = &inner.jobs;
        let keep: Vec<JobId> = inner
            .order
            .iter()
            .filter(|id| jobs.contains_key(*id))
            .cloned()
            .collect();
        inner.order = keep;
        before - inner.jobs.len()
    }

    pub fn unfinished(&self) -> usize {
        *self.unfinished.borrow()
    }

    /// Resolves once no job is open.
    pub async fn drained(&self) {
        let mut rx = self.unfinished.subscribe();
        let _ = rx.wait_for(|n| *n == 0).await;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

/// Why a transfer failed, if it did: the source could not be read, the
/// checksum did not match, the source could not be deleted, or the first
/// target that did not take the file.
pub fn transfer_error(report: &JobReport) -> Option<ApiError> {
    match &report.result {
        Err(e) => Some(ApiError::from(e)),
        Ok(r) => {
            if let Some(c) = r.checked.as_ref().filter(|c| !c.ok()) {
                Some(ApiError::from(c.error()))
            } else if let Some(Err(e)) = &r.source_removed {
                Some(ApiError::new(
                    e.kind(),
                    format!("copied, but deleting the source failed: {e}"),
                ))
            } else {
                r.failures().next().map(|t| match &t.result {
                    Err(e) => ApiError::new(e.kind(), format!("{}: {e}", t.target)),
                    // Not expected: a failure has an error. Said rather
                    // than panicked over.
                    Ok(()) => ApiError::new("internal", format!("{}: not delivered", t.target)),
                })
            }
        }
    }
}

/// One line of the journal.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Record {
    Submitted {
        id: JobId,
        at: String,
        attempt: u32,
        submission: Submission,
    },
    Done {
        id: JobId,
        at: String,
        state: JobState,
    },
}

/// The journal: JSON Lines, one `submitted` record per job and one `done`
/// record when it is over. A `submitted` without its `done` is a job to
/// run again. The file is compacted, so that it holds only what is still
/// open, when it is opened and again whenever it has grown past
/// [`COMPACT_MIN`] and twice what it held after the last compaction.
pub struct Journal {
    path: PathBuf,
    file: Mutex<Appender>,
}

/// The journal's file, open for appending, and how big it is.
struct Appender {
    file: std::fs::File,
    size: u64,
    /// Compact once `size` exceeds this.
    compact_at: u64,
    /// The smallest `compact_at`; lowered by tests.
    compact_min: u64,
}

/// A journal is not compacted below this size: every submission is
/// appended in full (up to `max_body`), and rewriting a small file after
/// every few jobs would be wasted work.
const COMPACT_MIN: u64 = 16 << 20;

impl Journal {
    /// Open (or create) the journal at `path` and hand over the jobs it
    /// says are open, each with its attempt count raised by one.
    pub fn open(path: &Path) -> Result<(Journal, Vec<Recovered>)> {
        let mut open: Vec<Recovered> = Vec::new();
        let mut size = 0;
        if path.exists() {
            open = read_open(path)?;
            for r in &mut open {
                r.attempt += 1;
            }
            size = rewrite(path, &open)?;
            if !open.is_empty() {
                info!(
                    path = %path.display(),
                    jobs = open.len(),
                    "journal: jobs left open by the last run"
                );
            }
        }
        let file = open_append(path)?;
        #[cfg(not(unix))]
        crate::credentials::warn_if_world_readable(path);
        debug!(path = %path.display(), "journal open");
        Ok((
            Journal {
                path: path.to_path_buf(),
                file: Mutex::new(Appender {
                    file,
                    size,
                    compact_at: (2 * size).max(COMPACT_MIN),
                    compact_min: COMPACT_MIN,
                }),
            },
            open,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, record: &Record) -> Result<()> {
        let mut line =
            serde_json::to_string(record).map_err(|e| Error::Config(format!("journal: {e}")))?;
        line.push('\n');
        let mut a = self.file.lock().unwrap_or_else(|e| e.into_inner());
        a.file.write_all(line.as_bytes())?;
        a.file.sync_data()?;
        a.size += line.len() as u64;
        if a.size > a.compact_at {
            // The record is safely written; a compaction that fails costs
            // only the space, and is tried again once the file has grown
            // as much again.
            if let Err(e) = self.compact(&mut a) {
                warn!(path = %self.path.display(), "journal: cannot compact: {e}");
                a.compact_at = (2 * a.size).max(a.compact_min);
            }
        }
        Ok(())
    }

    /// Rewrite the file with only the open jobs, as [`Journal::open`] does,
    /// and carry on appending to the new one.
    fn compact(&self, a: &mut Appender) -> Result<()> {
        let open = read_open(&self.path)?;
        let size = rewrite(&self.path, &open)?;
        a.file = open_append(&self.path)?;
        debug!(
            before = a.size,
            after = size,
            jobs = open.len(),
            "journal compacted"
        );
        a.size = size;
        a.compact_at = (2 * size).max(a.compact_min);
        Ok(())
    }

    #[cfg(test)]
    fn set_compact_min(&self, min: u64) {
        let mut a = self.file.lock().unwrap();
        a.compact_min = min;
        a.compact_at = (2 * a.size).max(min);
    }
}

/// Replace the journal at `path` with one `submitted` record per job in
/// `open`, through a temporary file so a crash on the way loses nothing.
/// Returns the new file's size.
fn rewrite(path: &Path, open: &[Recovered]) -> Result<u64> {
    let tmp = path.with_extension("tmp");
    let mut size = 0;
    {
        let mut f = create_private(&tmp)?;
        for r in open {
            let mut line = serde_json::to_string(&Record::Submitted {
                id: r.id.clone(),
                at: format_time(r.submitted_at),
                attempt: r.attempt,
                submission: r.submission.clone(),
            })
            .map_err(|e| Error::Config(format!("journal: {e}")))?;
            line.push('\n');
            f.write_all(line.as_bytes())?;
            size += line.len() as u64;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(size)
}

/// The journal at `path`, opened for appending (created only its owner can
/// read).
fn open_append(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| Error::Config(format!("journal {}: cannot open: {e}", path.display())))
}

/// A new file that only its owner can read.
fn create_private(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

/// The jobs a journal leaves open, with the attempt it recorded.
/// A line that does not parse (the last one, cut short by a crash) is
/// skipped with a warning. Lines are split as bytes: a line cut in the
/// middle of a character (`München`, written unescaped) is not UTF-8,
/// and is skipped like any other broken line rather than failing the
/// whole file.
fn read_open(path: &Path) -> Result<Vec<Recovered>> {
    let bytes = std::fs::read(path)?;
    let mut open: HashMap<JobId, Recovered> = HashMap::new();
    let mut order: Vec<JobId> = Vec::new();
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.trim_ascii().is_empty() {
            continue;
        }
        match serde_json::from_slice::<Record>(line) {
            Ok(Record::Submitted {
                id,
                at,
                attempt,
                submission,
            }) => {
                let submitted_at = parse_time(&at).unwrap_or_else(|_| SystemTime::now());
                order.push(id.clone());
                open.insert(
                    id.clone(),
                    Recovered {
                        id,
                        submitted_at,
                        attempt,
                        submission,
                    },
                );
            }
            Ok(Record::Done { id, .. }) => {
                open.remove(&id);
            }
            Err(e) => warn!(
                path = %path.display(),
                line = i + 1,
                "journal: skipping a line that does not parse: {e}"
            ),
        }
    }
    Ok(order
        .into_iter()
        .filter_map(|id| open.remove(&id))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::jobs::JobSpec;
    use crate::server::model::{JobKind, JobOptions};
    use crate::{Location, transfer::FanoutReport};

    fn submission(src: &str, dst: &str) -> Submission {
        Submission {
            kind: JobKind::Single,
            specs: vec![JobSpec {
                src: src.into(),
                dsts: vec![dst.into()],
            }],
            options: JobOptions::default(),
        }
    }

    fn job(src: &str, dst: &str) -> Job {
        Job {
            src: Location::parse(src).unwrap(),
            dsts: vec![Location::parse(dst).unwrap()],
        }
    }

    fn prepared(src: &str, dst: &str) -> Prepared {
        Prepared {
            job: job(src, dst),
            src: src.into(),
            dsts: vec![dst.into()],
        }
    }

    fn ok_report(index: usize, job: Job) -> JobReport {
        JobReport {
            index,
            result: Ok(FanoutReport {
                source: job.src.to_string(),
                bytes_read: 3,
                elapsed: Duration::from_millis(1),
                targets: vec![crate::transfer::TargetReport {
                    target: job.dsts[0].to_string(),
                    bytes: 3,
                    elapsed: Duration::from_millis(1),
                    attempts: 1,
                    result: Ok(()),
                    sidecar: None,
                    signature: None,
                    skipped: false,
                }],
                digests: Vec::new(),
                checked: None,
                source_removed: None,
            }),
            job,
        }
    }

    #[test]
    fn a_job_walks_through_its_states_and_tells() {
        let (tx, mut rx) = broadcast::channel(64);
        let store = Store::new(None, tx);
        let id = store
            .submit(submission("/tmp/a", "/tmp/out/"), CancellationToken::new())
            .unwrap();
        assert_eq!(store.unfinished(), 1);
        assert_eq!(store.snapshot(&id, false).unwrap().state, JobState::Queued);
        store.set_preparing(&id);
        let counters = store.start(
            &id,
            vec![
                prepared("/tmp/a", "/tmp/out/"),
                prepared("/tmp/b", "/tmp/out/"),
            ],
        );
        assert_eq!(counters.len(), 2);
        let snap = store.snapshot(&id, true).unwrap();
        assert_eq!(snap.state, JobState::Running);
        assert_eq!(snap.progress.transfers.queued, 2);
        assert_eq!(snap.transfers.as_ref().unwrap()[1].id, format!("{id}:1"));

        store.transfer_started(&id, 0);
        assert_eq!(
            store.transfer_done(
                &id,
                &ok_report(0, job("/tmp/a", "/tmp/out/")),
                Some(serde_json::json!({"ok": true})),
                None,
            ),
            TransferState::Done
        );
        let failed = JobReport {
            index: 1,
            job: job("/tmp/b", "/tmp/out/"),
            result: Err(Error::Remote("gone".into())),
        };
        let error = transfer_error(&failed);
        assert_eq!(
            store.transfer_done(&id, &failed, None, error),
            TransferState::Failed
        );
        assert_eq!(store.finish(&id, true), Some(JobState::Failed));
        assert_eq!(store.unfinished(), 0);
        let snap = store.snapshot(&id, true).unwrap();
        assert!(snap.finished_at.is_some());
        let t = &snap.transfers.unwrap();
        assert!(t[0].report.is_some());
        assert_eq!(t[1].error.as_ref().unwrap().kind, "remote");

        let mut kinds = Vec::new();
        while let Ok(e) = rx.try_recv() {
            kinds.push(
                serde_json::to_value(&e).unwrap()["event"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(
            kinds,
            [
                "queued",
                "started",
                "transfer_started",
                "transfer_done",
                "transfer_done",
                "done"
            ]
        );
        // Finishing twice changes nothing.
        assert_eq!(store.finish(&id, true), Some(JobState::Failed));
    }

    #[test]
    fn cancelling_fires_the_token_and_queued_transfers_never_run() {
        let (tx, _rx) = broadcast::channel(64);
        let store = Store::new(None, tx);
        let token = CancellationToken::new();
        let id = store
            .submit(submission("/tmp/a", "/tmp/out/"), token.clone())
            .unwrap();
        store.start(&id, vec![prepared("/tmp/a", "/tmp/out/")]);
        assert_eq!(store.cancel(&id), Some(JobState::Running));
        assert!(token.is_cancelled());
        assert_eq!(store.finish(&id, true), Some(JobState::Cancelled));
        assert_eq!(
            store.transfer(&id, 0).unwrap().state,
            TransferState::Cancelled
        );
        // Over already: cancelling again is a no-op that reports the state.
        assert_eq!(store.cancel(&id), Some(JobState::Cancelled));
        assert_eq!(store.cancel(&JobId::new()), None);
    }

    #[test]
    fn listing_is_newest_first_and_filtered() {
        let (tx, _rx) = broadcast::channel(64);
        let store = Store::new(None, tx);
        let a = store
            .submit(submission("/tmp/a", "/tmp/out/"), CancellationToken::new())
            .unwrap();
        let b = store
            .submit(submission("/tmp/b", "/tmp/out/"), CancellationToken::new())
            .unwrap();
        store.fail(&a, ApiError::new("io", "nope"), true);
        let all = store.list(None, 10);
        assert_eq!(all.iter().map(|j| &j.id).collect::<Vec<_>>(), [&b, &a]);
        assert!(all.iter().all(|j| j.transfers.is_none()));
        assert_eq!(store.list(Some(JobState::Failed), 10).len(), 1);
        assert_eq!(store.list(None, 1).len(), 1);
        assert_eq!(store.counts(), (1, 0));
        assert_eq!(store.sweep(Duration::from_secs(3600)), 0);
        assert_eq!(store.sweep(Duration::ZERO), 1);
        assert!(store.snapshot(&a, false).is_none());
        assert!(store.snapshot(&b, false).is_some());
    }

    #[test]
    fn the_journal_is_compacted_while_the_server_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.jsonl");
        let (tx, _rx) = broadcast::channel(1024);
        let (journal, _) = Journal::open(&path).unwrap();
        journal.set_compact_min(2048);
        let store = Store::new(Some(journal), tx);
        let left = store
            .submit(
                submission("/tmp/left", "/tmp/out/"),
                CancellationToken::new(),
            )
            .unwrap();
        let mut largest = 0;
        for _ in 0..200 {
            let id = store
                .submit(submission("/tmp/a", "/tmp/out/"), CancellationToken::new())
                .unwrap();
            store.finish(&id, true);
            largest = largest.max(std::fs::metadata(&path).unwrap().len());
        }
        // 200 finished jobs are about 50 KiB of records; the file never
        // grew far past the threshold.
        assert!(largest < 8192, "{largest}");
        drop(store);
        let (_journal, open) = Journal::open(&path).unwrap();
        assert_eq!(open.iter().map(|r| &r.id).collect::<Vec<_>>(), [&left]);
        assert_eq!(open[0].attempt, 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn the_journal_hands_back_what_was_left_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.jsonl");
        let (tx, _rx) = broadcast::channel(64);
        let (journal, open) = Journal::open(&path).unwrap();
        assert!(open.is_empty());
        let store = Store::new(Some(journal), tx.clone());
        let done = store
            .submit(submission("/tmp/a", "/tmp/out/"), CancellationToken::new())
            .unwrap();
        let left = store
            .submit(submission("/tmp/b", "/tmp/out/"), CancellationToken::new())
            .unwrap();
        let abandoned = store
            .submit(submission("/tmp/c", "/tmp/out/"), CancellationToken::new())
            .unwrap();
        store.finish(&done, true);
        store.finish(&abandoned, false);
        drop(store);
        // A crash in the middle of a write leaves half a line behind.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"t\":\"done\",\"id\":\"")
            .unwrap();
        // And one cut in the middle of a character is not UTF-8 at all.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n{\"t\":\"submitted\",\"id\":\"M\xc3")
            .unwrap();

        let (_journal, open) = Journal::open(&path).unwrap();
        let ids: Vec<&JobId> = open.iter().map(|r| &r.id).collect();
        assert_eq!(ids, [&left, &abandoned]);
        assert!(open.iter().all(|r| r.attempt == 2));
        assert_eq!(open[0].submission.specs[0].src, "/tmp/b");
        // Compacted: the done job and the broken line are gone.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(!text.contains(done.as_str()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
