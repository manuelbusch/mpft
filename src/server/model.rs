//! What the API talks about: jobs, their transfers, the options a request
//! may set, and what a snapshot or an event looks like on the wire.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::batch::jobs::{JobSpec, JsonJob, OneOrMany};
use crate::transfer::{CacheMode, CopyOptions};
use crate::{Error, HashAlgo, Result};

/// A job's identifier: 16 random bytes as 32 hex digits. Random rather
/// than counted, so an id survives a restart and cannot be guessed.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(String);

impl JobId {
    pub fn new() -> JobId {
        JobId(hex::encode(rand::random::<[u8; 16]>()))
    }

    /// An id from a path segment, if it has the right shape.
    pub fn parse(s: &str) -> Option<JobId> {
        (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| JobId(s.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        JobId::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JobId({})", self.0)
    }
}

/// One transfer, or a batch of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Single,
    Batch,
}

/// Where a job is in its life: `queued → preparing → running → done |
/// failed | cancelled`. `preparing` resolves the URLs, expands patterns and
/// trees and checks the targets; a job that fails there has no transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Preparing,
    Running,
    Done,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn is_final(self) -> bool {
        matches!(
            self,
            JobState::Done | JobState::Failed | JobState::Cancelled
        )
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JobState::Queued => "queued",
            JobState::Preparing => "preparing",
            JobState::Running => "running",
            JobState::Done => "done",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        })
    }
}

impl std::str::FromStr for JobState {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        Ok(match s {
            "queued" => JobState::Queued,
            "preparing" => JobState::Preparing,
            "running" => JobState::Running,
            "done" => JobState::Done,
            "failed" => JobState::Failed,
            "cancelled" => JobState::Cancelled,
            other => return Err(format!("unknown state '{other}'")),
        })
    }
}

/// Where one transfer of a job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
}

impl TransferState {
    pub fn is_final(self) -> bool {
        !matches!(self, TransferState::Queued | TransferState::Running)
    }
}

/// What a request may set per job. Everything is optional; what is not
/// given comes from the server's own settings (its flags and `[defaults]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct JobOptions {
    /// Transfers of this job in flight at once (a batch), capped by the
    /// server's `parallel`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel: Option<usize>,
    /// Stop the batch after the first failed transfer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    /// Checksum algorithm: `sha256`, `sha512`, `blake3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_existing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_source: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atomic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<bool>,
    /// Hold the payload in memory (needed for `retries`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// Inactivity timeout in seconds, `0` for none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// A source pattern that matches nothing is fine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_empty: Option<bool>,
    /// A directory source stands for every file below it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursive: Option<bool>,
}

impl JobOptions {
    /// Refuse what cannot work before the job is accepted.
    pub fn validate(&self) -> Result<()> {
        if self.parallel == Some(0) {
            return Err(Error::invalid_option("parallel", "must be at least 1"));
        }
        if let Some(h) = &self.hash {
            HashAlgo::parse(h).map_err(|e| Error::invalid_option("hash", e))?;
        }
        if self.retries.is_some_and(|r| r > 0) && self.cache != Some(true) {
            return Err(Error::invalid_option(
                "retries",
                "retries need the payload in memory: set cache = true",
            ));
        }
        if self.resume == Some(true) && self.atomic == Some(false) {
            return Err(Error::invalid_option(
                "resume",
                "resuming needs atomic transfers (there is no partial file otherwise)",
            ));
        }
        Ok(())
    }

    /// The options of a copy: the server's, with what the job set laid over.
    /// `cache_limit` bounds the memory cache when the job switches it on.
    pub fn apply(&self, base: &CopyOptions, cache_limit: u64) -> Result<CopyOptions> {
        self.validate()?;
        let mut out = base.clone();
        if let Some(h) = &self.hash {
            out.hash = Some(HashAlgo::parse(h).map_err(|e| Error::invalid_option("hash", e))?);
        }
        if let Some(v) = self.check {
            out.check = v;
        }
        if let Some(v) = self.skip_existing {
            out.skip_existing = v;
        }
        if let Some(v) = self.delete_source {
            out.delete_source = v;
        }
        if let Some(v) = self.atomic {
            out.atomic = v;
        }
        if let Some(v) = self.resume {
            out.resume = v;
        }
        match self.cache {
            Some(true) if out.cache == CacheMode::Stream => {
                out.cache = CacheMode::Memory { limit: cache_limit };
            }
            Some(false) => out.cache = CacheMode::Stream,
            _ => {}
        }
        if let Some(r) = self.retries {
            out.retries = r;
        }
        if let Some(t) = self.timeout {
            out.tee.send_timeout = (t > 0).then(|| std::time::Duration::from_secs(t));
        }
        if out.retries > 0 && out.cache == CacheMode::Stream {
            return Err(Error::invalid_option(
                "retries",
                "retries need the payload in memory: set cache = true",
            ));
        }
        // A signer wants a checksum; the job may not switch the hash off,
        // but the server's signer must not be left without one either.
        if out.sign.is_some() && out.hash.is_none() {
            out.hash = Some(HashAlgo::Sha256);
        }
        Ok(out)
    }
}

/// `POST /v1/jobs`: one source, one or more targets.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitJob {
    pub src: String,
    #[serde(alias = "dsts")]
    pub dst: OneOrMany,
    #[serde(default)]
    pub options: JobOptions,
}

/// `POST /v1/batches` as JSON: a list of jobs and options for all of them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBatch {
    pub jobs: Vec<JsonJob>,
    #[serde(default)]
    pub options: JobOptions,
}

/// What was accepted: the specs as given (URLs, unresolved) and the
/// options. This is what the journal keeps, and what a restart re-runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    pub kind: JobKind,
    pub specs: Vec<JobSpec>,
    #[serde(default)]
    pub options: JobOptions,
}

impl Submission {
    /// Every URL the submission names, sources first.
    pub fn urls(&self) -> Vec<&str> {
        self.specs
            .iter()
            .flat_map(|j| std::iter::once(j.src.as_str()).chain(j.dsts.iter().map(String::as_str)))
            .collect()
    }
}

/// An error on the wire: a stable `kind` (see [`Error::kind`]) and the
/// message a person reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub kind: String,
    pub message: String,
}

impl ApiError {
    pub fn new(kind: impl Into<String>, message: impl fmt::Display) -> ApiError {
        ApiError {
            kind: kind.into(),
            message: message.to_string(),
        }
    }
}

impl ApiError {
    /// An error as a client may see it. What a configuration error or a
    /// credential provider says is for the operator (it names files,
    /// profile URLs, commands): that goes to the log, and the client is
    /// told which profile to ask about. `url` is what was being resolved.
    pub fn client_safe(e: &Error, url: &str) -> ApiError {
        let profile = crate::config::profile_name(url)
            .map(|n| format!("profile '{n}'"))
            .unwrap_or_else(|| "the endpoint".to_string());
        match e {
            Error::Config(_) => {
                tracing::warn!(%url, "refused: {e}");
                ApiError::new(
                    e.kind(),
                    format!("{profile} is misconfigured; see the server log"),
                )
            }
            Error::Auth(_) => {
                tracing::warn!(%url, "refused: {e}");
                ApiError::new(
                    e.kind(),
                    format!("credentials for {profile} could not be fetched; see the server log"),
                )
            }
            other => ApiError::from(other),
        }
    }
}

impl From<&Error> for ApiError {
    fn from(e: &Error) -> Self {
        ApiError::new(e.kind(), e)
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError::from(&e)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Bytes so far and, once known, the size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteProgress {
    pub read: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// How many transfers of a job are in which state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferCounts {
    pub total: usize,
    pub queued: usize,
    pub running: usize,
    pub done: usize,
    pub failed: usize,
    pub cancelled: usize,
}

/// A job's progress: the bytes of every transfer added up, the size when
/// every transfer knows its own, and the transfers by state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobProgress {
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    pub transfers: TransferCounts,
}

/// One transfer as `GET /v1/jobs/{id}/transfers/{index}` returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferSnapshot {
    /// Position in the job, from 0.
    pub index: usize,
    /// `<job id>:<index>`.
    pub id: String,
    /// The source as it was submitted: the `mpt://` reference (with the
    /// matched file in place of a pattern), or a full URL with its
    /// password masked.
    pub src: String,
    /// The targets, likewise.
    pub dst: Vec<String>,
    pub state: TransferState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    pub progress: ByteProgress,
    /// The copy's report once it is over, in the `--json` shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<serde_json::Value>,
    /// Why it failed, if it did: the source could not be read, or a target
    /// (see the report for which) did not take it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

/// A job as `GET /v1/jobs/{id}` returns it. The list of jobs leaves
/// `transfers` out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobSnapshot {
    pub id: JobId,
    pub kind: JobKind,
    pub state: JobState,
    pub submitted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// 1 the first time; one more for every restart that re-ran the job.
    pub attempt: u32,
    pub options: JobOptions,
    /// `fail_fast` stopped the job before every transfer had run.
    pub stopped_early: bool,
    /// Why the job failed before any transfer ran (a URL that does not
    /// resolve, a pattern that matches nothing, a target another job
    /// writes). Transfers carry their own errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    pub progress: JobProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfers: Option<Vec<TransferSnapshot>>,
}

/// Progress of one running transfer, for the `progress` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferProgress {
    pub index: usize,
    pub read: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// What a WebSocket client sees. Every event names its job, so one stream
/// can carry every job's events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Sent once when a client connects: where things stand.
    Snapshot {
        job: Box<JobSnapshot>,
    },
    Queued {
        id: JobId,
    },
    /// Preparation is over; this many transfers will run.
    Started {
        id: JobId,
        transfers: usize,
    },
    TransferStarted {
        id: JobId,
        index: usize,
    },
    /// Bytes moved since the last one, four times a second at most, only
    /// while something changes.
    Progress {
        id: JobId,
        bytes: u64,
        transfers: Vec<TransferProgress>,
    },
    TransferDone {
        id: JobId,
        index: usize,
        state: TransferState,
        transfer: Box<TransferSnapshot>,
    },
    /// The job is over; `job` is its summary (no transfers).
    Done {
        id: JobId,
        state: JobState,
        job: Box<JobSnapshot>,
    },
}

impl Event {
    /// The job the event is about.
    pub fn job_id(&self) -> &JobId {
        match self {
            Event::Snapshot { job } => &job.id,
            Event::Queued { id }
            | Event::Started { id, .. }
            | Event::TransferStarted { id, .. }
            | Event::Progress { id, .. }
            | Event::TransferDone { id, .. }
            | Event::Done { id, .. } => id,
        }
    }
}

/// Turn the JSON forms of a request into the specs a job runs.
pub fn specs_of(jobs: Vec<JsonJob>) -> Result<Vec<JobSpec>> {
    jobs.into_iter()
        .enumerate()
        .map(|(i, j)| {
            j.into_spec()
                .map_err(|e| Error::InvalidUrl(format!("job {}: {e}", i + 1)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_random_hex_and_round_trip() {
        let a = JobId::new();
        let b = JobId::new();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 32);
        assert_eq!(JobId::parse(a.as_str()), Some(a.clone()));
        assert_eq!(JobId::parse(&a.as_str().to_uppercase()), Some(a));
        assert!(JobId::parse("short").is_none());
        assert!(JobId::parse(&"g".repeat(32)).is_none());
    }

    #[test]
    fn options_are_checked_and_laid_over_the_base() {
        let base = CopyOptions::default();
        let opts: JobOptions = serde_json::from_str(
            r#"{"hash": "sha256", "cache": true, "retries": 2, "timeout": 0, "skip_existing": true}"#,
        )
        .unwrap();
        let copy = opts.apply(&base, 1024).unwrap();
        assert_eq!(copy.hash, Some(HashAlgo::Sha256));
        assert_eq!(copy.cache, CacheMode::Memory { limit: 1024 });
        assert_eq!(copy.retries, 2);
        assert!(copy.tee.send_timeout.is_none());
        assert!(copy.skip_existing);

        let bad: JobOptions = serde_json::from_str(r#"{"retries": 1}"#).unwrap();
        assert!(bad.validate().is_err(), "retries without cache");
        let bad: JobOptions = serde_json::from_str(r#"{"hash": "crc"}"#).unwrap();
        assert!(bad.validate().is_err());
        let bad: JobOptions = serde_json::from_str(r#"{"parallel": 0}"#).unwrap();
        assert!(bad.validate().is_err());
        assert!(serde_json::from_str::<JobOptions>(r#"{"colour": 1}"#).is_err());
    }

    #[test]
    fn empty_options_serialize_to_nothing() {
        assert_eq!(serde_json::to_string(&JobOptions::default()).unwrap(), "{}");
    }

    #[test]
    fn a_submission_lists_its_urls() {
        let s = Submission {
            kind: JobKind::Batch,
            specs: vec![
                JobSpec {
                    src: "a".into(),
                    dsts: vec!["b".into(), "c".into()],
                },
                JobSpec {
                    src: "d".into(),
                    dsts: vec!["e".into()],
                },
            ],
            options: JobOptions::default(),
        };
        assert_eq!(s.urls(), vec!["a", "b", "c", "d", "e"]);
        let text = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Submission>(&text).unwrap(), s);
    }

    #[test]
    fn operator_errors_are_kept_from_the_client() {
        let e = ApiError::client_safe(
            &Error::Config("profile 'p' points at /secret/place".into()),
            "mpt://p/x",
        );
        assert_eq!(e.kind, "config");
        assert!(!e.message.contains("/secret"), "{}", e.message);
        assert!(e.message.contains("profile 'p'"), "{}", e.message);
        let e = ApiError::client_safe(
            &Error::Auth("password of profile 'p': `op read x`".into()),
            "mpt://p/",
        );
        assert!(!e.message.contains("op read"), "{}", e.message);
        let e = ApiError::client_safe(&Error::Remote("gone".into()), "mpt://p/");
        assert_eq!(e.message, "remote error: gone");
    }

    #[test]
    fn events_are_tagged() {
        let e = Event::TransferStarted {
            id: JobId::parse(&"a".repeat(32)).unwrap(),
            index: 3,
        };
        let text = serde_json::to_string(&e).unwrap();
        assert!(text.starts_with(r#"{"event":"transfer_started""#), "{text}");
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), e);
    }
}
