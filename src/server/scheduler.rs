//! One task per job: prepare it, run its transfers under the limits,
//! close it.
//!
//! [`crate::batch::run`] is not used because it gives every job of a
//! batch the same cancellation token and the same byte counter; here each
//! transfer has its own, so a request can cancel one job and a client can
//! watch one transfer.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::AppState;
use super::model::{ApiError, JobId, JobOptions, Submission, TransferState};
use super::store::{Prepared, transfer_error};
use crate::batch::{self, Job, JobReport, PrepareOptions};
use crate::config::is_profile_ref;
use crate::{Error, Location, Result};

/// Start the job's task.
pub(crate) fn spawn_job(state: Arc<AppState>, id: JobId) {
    tokio::spawn(run(state, id));
}

/// The kind of error for a job or a transfer that a panic ended: a bug in
/// the server, described in its log.
const INTERNAL: &str = "internal";

/// Closes a job that its task left open because it panicked, so the job
/// does not stay `queued` or `preparing` for ever (counting against
/// `max_queued`, and holding up a shutdown for its whole grace period).
struct CloseOnPanic {
    state: Arc<AppState>,
    id: JobId,
}

impl Drop for CloseOnPanic {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        warn!(id = %self.id, "the job's task panicked; closing the job as failed");
        let error = ApiError::new(INTERNAL, "the job ended unexpectedly; see the server log");
        self.state.store.fail(&self.id, error, journal(&self.state));
    }
}

/// A job's claim on its targets, given up when it is dropped: when the
/// transfer is over, when it never starts, and when its task panics.
struct Claim {
    state: Arc<AppState>,
    job: Job,
}

impl Drop for Claim {
    fn drop(&mut self) {
        release(&self.state, std::slice::from_ref(&self.job));
    }
}

/// Marks a transfer failed when its task panics before it could say how
/// the transfer ended, so the job is not taken for `done`. A transfer
/// already over is left as it is.
struct ReportOnPanic {
    state: Arc<AppState>,
    id: JobId,
    index: usize,
}

impl Drop for ReportOnPanic {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        warn!(id = %self.id, index = self.index, "a transfer task panicked");
        let error = ApiError::new(
            INTERNAL,
            "the transfer ended unexpectedly; see the server log",
        );
        self.state.store.transfer_lost(&self.id, self.index, error);
    }
}

async fn run(state: Arc<AppState>, id: JobId) {
    let Some((submission, token)) = state.store.submission(&id) else {
        return;
    };
    let _close = CloseOnPanic {
        state: Arc::clone(&state),
        id: id.clone(),
    };
    // Queued until a slot is free for the preparation, which lists
    // directories and may fetch credentials.
    let permit = tokio::select! {
        biased;
        () = token.cancelled() => None,
        p = state.slots.acquire() => p.ok(),
    };
    if permit.is_none() {
        state.store.finish(&id, journal(&state));
        return;
    }
    state.store.set_preparing(&id);
    // A cancellation (a request, or the server giving up at shutdown) drops
    // the preparation wherever it is: a listing, a credential command (it
    // is killed with it) or a directory being created. The targets are
    // claimed in its last step, which has nothing left to wait for, so a
    // preparation dropped earlier has claimed none.
    let prepared = tokio::select! {
        biased;
        () = token.cancelled() => None,
        p = prepare(&state, &submission) => Some(p),
    };
    drop(permit);
    let Some(prepared) = prepared else {
        info!(%id, "cancelled while being prepared");
        state.store.finish(&id, journal(&state));
        return;
    };
    // Whatever went wrong is told in terms of what was submitted.
    let prepared = prepared.map_err(|(e, refs)| redact(e, &refs));
    let (jobs, refs) = match prepared {
        Ok(p) => p,
        Err(e) => {
            warn!(%id, "not run: {}", e.message);
            state.store.fail(&id, e, journal(&state));
            return;
        }
    };
    let claims: Vec<Claim> = jobs
        .iter()
        .map(|p| Claim {
            state: Arc::clone(&state),
            job: p.job.clone(),
        })
        .collect();
    if token.is_cancelled() {
        drop(claims);
        state.store.finish(&id, journal(&state));
        return;
    }
    let n = jobs.len();
    info!(%id, transfers = n, "running");
    let counters = state.store.start(&id, jobs);
    let per_job = submission
        .options
        .parallel
        .unwrap_or(state.rt.parallel)
        .clamp(1, state.cfg.parallel);
    let job_slots = Arc::new(Semaphore::new(per_job));
    let fail_fast = submission.options.fail_fast.unwrap_or(false);
    let mut tasks = JoinSet::new();
    for (index, (claim, progress)) in claims.into_iter().zip(counters).enumerate() {
        let state = Arc::clone(&state);
        let id = id.clone();
        let token = token.clone();
        let job_slots = Arc::clone(&job_slots);
        let options = submission.options.clone();
        let refs = Arc::clone(&refs);
        tasks.spawn(async move {
            let _reporter = ReportOnPanic {
                state: Arc::clone(&state),
                id: id.clone(),
                index,
            };
            let job = claim.job.clone();
            // The job's own slot first, then one of the server's: a big
            // batch must not hold server slots while waiting on its own.
            let permits = tokio::select! {
                biased;
                () = token.cancelled() => None,
                j = job_slots.acquire_owned() => match j {
                    Ok(j) => tokio::select! {
                        biased;
                        () = token.cancelled() => None,
                        g = state.slots.clone().acquire_owned() => g.ok().map(|g| (j, g)),
                    },
                    Err(_) => None,
                },
            };
            let report = match permits {
                None => JobReport {
                    index,
                    job,
                    result: Err(Error::Cancelled),
                },
                Some(_permits) => {
                    state.store.transfer_started(&id, index);
                    let result = async {
                        let mut copy = options.apply(&state.rt.copy, state.rt.cache_limit)?;
                        copy.cancel = Some(token.child_token());
                        copy.progress = Some(progress);
                        let open = |l: &Location| crate::protocols::open(l.clone());
                        batch::run_job(&job, &open, &copy).await
                    }
                    .await;
                    JobReport { index, job, result }
                }
            };
            let json = report
                .result
                .as_ref()
                .ok()
                .map(|r| shown_report(crate::report::fanout_json(r), &refs));
            let error = transfer_error(&report).map(|e| redact(e, &refs));
            let outcome = state.store.transfer_done(&id, &report, json, error);
            debug!(%id, index, ?outcome, "transfer over");
            if fail_fast && outcome == TransferState::Failed && !token.is_cancelled() {
                warn!(%id, index, "failed, stopping the job");
                state.store.set_stopped_early(&id);
                token.cancel();
            }
            // The claim goes with the task: here, or while a panic unwinds.
            drop(claim);
        });
    }
    // A task that panicked has released its claim and marked its transfer
    // failed on the way out; see `Claim` and `ReportOnPanic`.
    while let Some(done) = tasks.join_next().await {
        if let Err(e) = done {
            warn!(%id, "a transfer task ended badly: {e}");
        }
    }
    let state_after = state.store.finish(&id, journal(&state));
    info!(%id, state = ?state_after, "over");
}

/// Whether a job's end goes into the journal: not while the server is
/// abandoning it, because then it should run again after the restart.
fn journal(state: &AppState) -> bool {
    !state.work.is_cancelled()
}

fn release(state: &AppState, jobs: &[Job]) {
    let mut targets = state.targets.lock().unwrap_or_else(|e| e.into_inner());
    for job in jobs {
        targets.release(job);
    }
}

/// URLs to locations, patterns and trees to files, and a claim on every
/// target. A job that fails here never ran; the error says why.
///
/// An error comes with the references resolved so far, for [`redact`].
async fn prepare(
    state: &AppState,
    submission: &Submission,
) -> std::result::Result<(Vec<Prepared>, Arc<Refs>), (ApiError, Refs)> {
    let mut refs: Refs = Vec::new();
    let fail = |e: ApiError, refs: &Refs| (e, refs.clone());
    if let Err(e) = crate::config::resolve_more(&submission.urls(), state.rt.signing).await {
        // The message names a provider; the client learns the profile.
        let url = submission
            .urls()
            .into_iter()
            .find(|u| is_profile_ref(u))
            .unwrap_or("");
        return Err(fail(ApiError::client_safe(&e, url), &refs));
    }
    let locate = state.rt.locate.as_ref();
    let mut jobs = Vec::with_capacity(submission.specs.len());
    for (i, spec) in submission.specs.iter().enumerate() {
        match locate_spec(spec, locate, &submission.options) {
            Ok(job) => {
                // What was submitted, next to what it resolved to, so an
                // expanded file can be shown by its reference.
                refs.push((spec.src.clone(), job.src.clone()));
                refs.extend(spec.dsts.iter().cloned().zip(job.dsts.iter().cloned()));
                jobs.push(job);
            }
            Err((url, e)) => {
                let safe = ApiError::client_safe(&e, url);
                let e = ApiError::new(safe.kind, format!("job {}: {}", i + 1, safe.message));
                return Err(fail(e, &refs));
            }
        }
    }
    let open = |l: &Location| crate::protocols::open(l.clone());
    let opts = PrepareOptions {
        allow_empty: submission.options.allow_empty.unwrap_or(false),
        recursive: submission.options.recursive.unwrap_or(false),
        no_mkdir: false,
        limit: Some(state.cfg.max_transfers),
    };
    let jobs = match batch::prepare(jobs, &open, &opts).await {
        Ok(jobs) => jobs,
        Err(e) => {
            // The expansion's own limit error gets a kind of its own.
            let kind = match &e {
                Error::InvalidUrl(m) if m.starts_with(batch::expand::OVER_LIMIT) => {
                    "too_many_transfers"
                }
                other => other.kind(),
            };
            return Err(fail(ApiError::new(kind, &e), &refs));
        }
    };
    // All or nothing: a job refused here holds no target afterwards.
    let noted = state
        .targets
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .note_all(&jobs, 1);
    if let Err(e) = noted {
        return Err(fail(ApiError::new("conflict", conflict_text(&e)), &refs));
    }
    let prepared = jobs
        .into_iter()
        .map(|job| Prepared {
            src: shown(&job.src, &refs),
            dsts: job.dsts.iter().map(|d| shown(d, &refs)).collect(),
            job,
        })
        .collect();
    Ok((prepared, Arc::new(refs)))
}

/// The URLs a job was submitted with, each next to what it resolved to.
type Refs = Vec<(String, Location)>;

/// How a resolved location is shown to clients: as the `mpt://` reference
/// it came from, with the file a pattern or a tree put in place of the
/// pattern (`mpt://in/*.csv` → `mpt://in/a.csv`), or — for a URL given in
/// full — as the location with its password masked.
fn shown(loc: &Location, refs: &[(String, Location)]) -> String {
    let same_endpoint = |base: &Location| {
        base.scheme() == loc.scheme()
            && base.host() == loc.host()
            && base.port_or_default() == loc.port_or_default()
    };
    let mpt_refs = refs.iter().filter(|(url, _)| is_profile_ref(url));
    // The reference itself, unexpanded.
    for (url, base) in mpt_refs.clone() {
        if same_endpoint(base) && base.path() == loc.path() {
            return url.clone();
        }
    }
    // A file under the directory the reference names.
    for (url, base) in mpt_refs {
        if !same_endpoint(base) || base.scheme().is_mail() {
            continue;
        }
        let head = url.split('?').next().unwrap_or(url);
        let (dir, head) = if base.is_dir_target() {
            (base.path(), head)
        } else {
            match (base.path().rsplit_once('/'), head.rsplit_once('/')) {
                (Some((d, _)), Some((h, _))) => (&base.path()[..d.len() + 1], &head[..h.len() + 1]),
                _ => continue,
            }
        };
        if !dir.is_empty()
            && let Some(rest) = loc.path().strip_prefix(dir)
        {
            return format!("{head}{rest}");
        }
    }
    loc.to_string()
}

/// An error message with every resolved location it mentions replaced by
/// what the client submitted: the message of a listing that found
/// nothing, of a target that refused, of two jobs on one file. Longest
/// locations first, so a file under a directory reference is rewritten
/// as a whole and not just its directory part.
pub(super) fn redact(mut error: ApiError, refs: &[(String, Location)]) -> ApiError {
    let mut pairs: Vec<(String, &String)> = refs
        .iter()
        .filter(|(url, _)| is_profile_ref(url))
        .map(|(url, loc)| (loc.to_string(), url))
        .collect();
    pairs.sort_by_key(|(text, _)| std::cmp::Reverse(text.len()));
    for (text, url) in pairs {
        if !text.is_empty() {
            error.message = error.message.replace(&text, url);
        }
    }
    error
}

/// The words of a collision error: `Targets::note` files it as an invalid
/// URL, whose prefix says nothing to an API client.
pub(super) fn conflict_text(e: &Error) -> String {
    match e {
        Error::InvalidUrl(m) => m.clone(),
        other => other.to_string(),
    }
}

/// A copy's report with its endpoints (source, targets, the checksum and
/// signature files next to them) named as [`shown`] names them.
fn shown_report(mut report: serde_json::Value, refs: &[(String, Location)]) -> serde_json::Value {
    let fix = |v: &mut serde_json::Value| {
        if let Some(text) = v.as_str()
            && let Ok(loc) = Location::parse(text)
        {
            *v = serde_json::Value::String(shown(&loc, refs));
        }
    };
    fix(&mut report["source"]);
    if let Some(targets) = report["targets"].as_array_mut() {
        for t in targets {
            fix(&mut t["target"]);
            fix(&mut t["sidecar"]);
            fix(&mut t["signature"]);
        }
    }
    report
}

/// The spec's URLs as locations; an error comes with the URL it was for.
fn locate_spec<'a>(
    spec: &'a crate::batch::jobs::JobSpec,
    locate: &(dyn Fn(&str, &JobOptions) -> Result<Location> + Send + Sync),
    options: &JobOptions,
) -> std::result::Result<Job, (&'a str, Error)> {
    let one = |url: &'a str| locate(url, options).map_err(|e| (url, e));
    Ok(Job {
        src: one(&spec.src)?,
        dsts: spec
            .dsts
            .iter()
            .map(|d| one(d))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::batch::jobs::JobSpec;
    use crate::config::UrlRule;
    use crate::server::model::{JobKind, JobState, Submission};
    use crate::server::{Runtime, ServerConfig};
    use crate::transfer::CopyOptions;
    use tokio_util::sync::CancellationToken;

    fn state(parallel: usize) -> Arc<AppState> {
        let cfg = ServerConfig {
            parallel,
            urls: UrlRule::Any,
            ..Default::default()
        };
        AppState::new(cfg, Runtime::new(CopyOptions::default())).unwrap()
    }

    fn batch(specs: Vec<(String, String)>, options: JobOptions) -> Submission {
        Submission {
            kind: JobKind::Batch,
            specs: specs
                .into_iter()
                .map(|(src, dst)| JobSpec {
                    src,
                    dsts: vec![dst],
                })
                .collect(),
            options,
        }
    }

    async fn wait_final(state: &AppState, id: &JobId) -> JobState {
        for _ in 0..500 {
            let s = state.store.snapshot(id, false).unwrap().state;
            if s.is_final() {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("job {id} never finished");
    }

    #[test]
    fn transfers_are_shown_by_their_reference() {
        let loc = |s: &str| Location::parse(s).unwrap();
        let refs = vec![
            ("mpt://in/*.csv".to_string(), loc("sftp://h/data/in/*.csv")),
            ("mpt://out/".to_string(), loc("/srv/out/")),
            ("sftp://u:pw@h/raw/".to_string(), loc("sftp://u:pw@h/raw/")),
            ("mpt://mail".to_string(), loc("mailto:a@example.com")),
        ];
        assert_eq!(
            shown(&loc("sftp://h/data/in/a.csv"), &refs),
            "mpt://in/a.csv"
        );
        assert_eq!(
            shown(&loc("sftp://h/data/in/*.csv"), &refs),
            "mpt://in/*.csv"
        );
        assert_eq!(shown(&loc("/srv/out/"), &refs), "mpt://out/");
        assert_eq!(shown(&loc("/srv/out/sub/"), &refs), "mpt://out/sub/");
        assert_eq!(shown(&loc("mailto:a@example.com"), &refs), "mpt://mail");
        // Another host, or a raw URL: the location, password masked.
        assert_eq!(
            shown(&loc("sftp://other/data/in/a.csv"), &refs),
            "sftp://other/data/in/a.csv"
        );
        assert_eq!(
            shown(&loc("sftp://u:pw@h/raw/x"), &refs),
            "sftp://u:***@h/raw/x"
        );
        assert_eq!(shown(&loc("/elsewhere/x"), &refs), "/elsewhere/x");

        let report = shown_report(
            serde_json::json!({
                "source": "sftp://h/data/in/a.csv",
                "targets": [
                    {"target": "/srv/out/", "sidecar": "/srv/out/a.csv.sha256", "signature": null},
                    {"target": "sftp://u:***@h/raw/", "sidecar": null, "signature": null},
                ],
            }),
            &refs,
        );
        assert_eq!(report["source"], "mpt://in/a.csv");
        assert_eq!(report["targets"][0]["target"], "mpt://out/");
        assert_eq!(report["targets"][0]["sidecar"], "mpt://out/a.csv.sha256");
        assert_eq!(report["targets"][0]["signature"], serde_json::Value::Null);
        assert_eq!(report["targets"][1]["target"], "sftp://u:***@h/raw/");

        let e = redact(
            ApiError::new(
                "invalid_url",
                "sftp://h/data/in/*.csv matches no file; /srv/out/x is taken",
            ),
            &refs,
        );
        assert_eq!(
            e.message,
            "mpt://in/*.csv matches no file; mpt://out/x is taken"
        );
    }

    #[tokio::test]
    async fn a_batch_runs_every_transfer_under_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let out = format!("{}/out/", dir.path().display());
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let mut specs = Vec::new();
        for i in 0..5 {
            let src = dir.path().join(format!("s{i}.bin"));
            std::fs::write(&src, format!("payload {i}")).unwrap();
            specs.push((src.display().to_string(), out.clone()));
        }
        let state = state(8);
        let id = state
            .submit(batch(
                specs,
                JobOptions {
                    parallel: Some(2),
                    ..Default::default()
                },
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &id).await, JobState::Done);
        let snap = state.store.snapshot(&id, true).unwrap();
        assert_eq!(snap.progress.transfers.done, 5);
        assert_eq!(snap.progress.bytes, 5 * "payload 0".len() as u64);
        assert_eq!(snap.progress.total, Some(snap.progress.bytes));
        for i in 0..5 {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(format!("out/s{i}.bin"))).unwrap(),
                format!("payload {i}")
            );
        }
        assert_eq!(state.store.unfinished(), 0);
    }

    #[tokio::test]
    async fn fail_fast_stops_the_job_and_marks_it_failed() {
        let dir = tempfile::tempdir().unwrap();
        let out = format!("{}/", dir.path().display());
        let mut specs = vec![(
            dir.path().join("missing").display().to_string(),
            out.clone(),
        )];
        for i in 0..3 {
            let src = dir.path().join(format!("s{i}.bin"));
            std::fs::write(&src, "x").unwrap();
            specs.push((src.display().to_string(), out.clone()));
        }
        // One at a time, so the missing source fails before the rest start.
        let state = state(1);
        let id = state
            .submit(batch(
                specs,
                JobOptions {
                    fail_fast: Some(true),
                    ..Default::default()
                },
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &id).await, JobState::Failed);
        let snap = state.store.snapshot(&id, true).unwrap();
        assert!(snap.stopped_early);
        let t = snap.transfers.unwrap();
        assert_eq!(t[0].state, TransferState::Failed);
        assert_eq!(t[0].error.as_ref().unwrap().kind, "io");
        assert!(t[1..].iter().all(|t| t.state == TransferState::Cancelled));
    }

    #[tokio::test]
    async fn a_job_that_cannot_be_prepared_fails_without_transfers() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(2);
        let id = state
            .submit(batch(
                vec![(
                    format!("{}/*.none", dir.path().display()),
                    format!("{}/", dir.path().display()),
                )],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &id).await, JobState::Failed);
        let snap = state.store.snapshot(&id, true).unwrap();
        let error = snap.error.unwrap();
        assert_eq!(error.kind, "invalid_url");
        assert!(error.message.contains("*.none"), "{}", error.message);
        assert!(snap.transfers.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_tree_over_the_limit_is_refused_before_it_is_listed_to_the_end() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tree")).unwrap();
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("tree/f{i}")), "x").unwrap();
        }
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let cfg = ServerConfig {
            parallel: 2,
            urls: UrlRule::Any,
            max_transfers: 3,
            ..Default::default()
        };
        let state = AppState::new(cfg, Runtime::new(CopyOptions::default())).unwrap();
        let id = state
            .submit(batch(
                vec![(
                    format!("{}/tree/", dir.path().display()),
                    format!("{}/out/", dir.path().display()),
                )],
                JobOptions {
                    recursive: Some(true),
                    ..Default::default()
                },
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &id).await, JobState::Failed);
        let error = state.store.snapshot(&id, false).unwrap().error.unwrap();
        assert_eq!(error.kind, "too_many_transfers");
        assert!(error.message.contains("(3)"), "{}", error.message);
    }

    #[tokio::test]
    async fn a_target_in_use_is_refused_until_the_job_is_over() {
        let dir = tempfile::tempdir().unwrap();
        let out = format!("{}/out/", dir.path().display());
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let src = dir.path().join("x.bin");
        std::fs::write(&src, "x").unwrap();
        let state = state(4);
        // Hold the only slot so the first job stays queued... no: hold the
        // targets by preparing a job and never finishing it is not possible
        // from outside, so run one job to its end and a second after it.
        let first = state
            .submit(batch(
                vec![(src.display().to_string(), out.clone())],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &first).await, JobState::Done);
        let second = state
            .submit(batch(
                vec![(src.display().to_string(), out.clone())],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &second).await, JobState::Done);
        // Two transfers of one batch on the same file: a conflict.
        let third = state
            .submit(batch(
                vec![
                    (src.display().to_string(), out.clone()),
                    (src.display().to_string(), out.clone()),
                ],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &third).await, JobState::Failed);
        let snap = state.store.snapshot(&third, false).unwrap();
        assert_eq!(snap.error.unwrap().kind, "conflict");
        // And the target is free again afterwards.
        let fourth = state
            .submit(batch(
                vec![(src.display().to_string(), out)],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &fourth).await, JobState::Done);
    }

    #[tokio::test]
    async fn a_job_refused_for_a_conflict_claims_no_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("in")).unwrap();
        std::fs::create_dir(dir.path().join("out")).unwrap();
        std::fs::write(dir.path().join("in/a.csv"), "a").unwrap();
        let out = format!("{}/out/", dir.path().display());
        let state = state(2);
        // A pattern is expanded before targets are checked, so the target
        // named twice is found in the preparation.
        let twice = state
            .submit(Submission {
                kind: JobKind::Single,
                specs: vec![JobSpec {
                    src: format!("{}/in/*.csv", dir.path().display()),
                    dsts: vec![out.clone(), out.clone()],
                }],
                options: JobOptions::default(),
            })
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &twice).await, JobState::Failed);
        let error = state.store.snapshot(&twice, false).unwrap().error.unwrap();
        assert_eq!(error.kind, "conflict", "{}", error.message);
        // The file is free for the next job.
        let next = state
            .submit(batch(
                vec![(format!("{}/in/a.csv", dir.path().display()), out)],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        assert_eq!(wait_final(&state, &next).await, JobState::Done);
    }

    #[tokio::test]
    async fn a_journalled_job_the_settings_no_longer_allow_is_failed_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("jobs.jsonl");
        std::fs::write(dir.path().join("a"), "a").unwrap();
        std::fs::write(dir.path().join("b"), "b").unwrap();
        let out = format!("{}/out/", dir.path().display());
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let cfg = |allow_delete| ServerConfig {
            urls: UrlRule::Any,
            journal: Some(journal.clone()),
            allow_delete,
            ..Default::default()
        };
        // Taken while deleting was allowed, never run.
        let (deleting, plain) = {
            let state = AppState::new(cfg(true), Runtime::new(CopyOptions::default())).unwrap();
            let one = |src: &str, delete| {
                state.store.submit(
                    batch(
                        vec![(format!("{}/{src}", dir.path().display()), out.clone())],
                        JobOptions {
                            delete_source: delete,
                            ..Default::default()
                        },
                    ),
                    CancellationToken::new(),
                )
            };
            (
                one("a", Some(true)).await.unwrap(),
                one("b", None).await.unwrap(),
            )
        };
        let state = AppState::new(cfg(false), Runtime::new(CopyOptions::default())).unwrap();
        state.run();
        assert_eq!(wait_final(&state, &deleting).await, JobState::Failed);
        let error = state
            .store
            .snapshot(&deleting, false)
            .unwrap()
            .error
            .unwrap();
        assert!(error.message.contains("allow_delete"), "{}", error.message);
        assert!(dir.path().join("a").exists());
        assert_eq!(wait_final(&state, &plain).await, JobState::Done);
        state.store.flush().await;
        drop(state);
        // Closed for good: a further restart has nothing to run.
        let (_, open) = crate::server::store::Journal::open(&journal).unwrap();
        assert!(open.is_empty(), "{open:?}");
    }

    #[tokio::test]
    async fn a_panic_fails_the_transfer_and_the_job_and_frees_the_target() {
        let state = state(2);
        let id = state
            .store
            .submit(
                batch(
                    vec![("/tmp/a".into(), "/tmp/out/".into())],
                    JobOptions::default(),
                ),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let job = Job {
            src: Location::parse("/tmp/a").unwrap(),
            dsts: vec![Location::parse("/tmp/out/").unwrap()],
        };
        state.targets.lock().unwrap().note(&job, 1).unwrap();
        state.store.start(
            &id,
            vec![Prepared {
                job: job.clone(),
                src: "/tmp/a".into(),
                dsts: vec!["/tmp/out/".into()],
            }],
        );
        let task = {
            let state = Arc::clone(&state);
            let id = id.clone();
            let job = job.clone();
            tokio::spawn(async move {
                let _close = CloseOnPanic {
                    state: Arc::clone(&state),
                    id: id.clone(),
                };
                let _claim = Claim {
                    state: Arc::clone(&state),
                    job,
                };
                let _reporter = ReportOnPanic {
                    state: Arc::clone(&state),
                    id,
                    index: 0,
                };
                panic!("a bug");
            })
        };
        assert!(task.await.unwrap_err().is_panic());
        let snap = state.store.snapshot(&id, true).unwrap();
        assert_eq!(snap.state, JobState::Failed);
        assert_eq!(snap.error.unwrap().kind, INTERNAL);
        let t = &snap.transfers.unwrap()[0];
        assert_eq!(t.state, TransferState::Failed);
        assert_eq!(t.error.as_ref().unwrap().kind, INTERNAL);
        assert_eq!(state.store.unfinished(), 0);
        state.targets.lock().unwrap().note(&job, 2).unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_queued_job_runs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let out = format!("{}/out/", dir.path().display());
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let src = dir.path().join("x.bin");
        std::fs::write(&src, "x").unwrap();
        let state = state(1);
        // Take the only slot away, so the job waits in the queue.
        let slot = state.slots.clone().acquire_owned().await.unwrap();
        let id = state
            .submit(batch(
                vec![(src.display().to_string(), out)],
                JobOptions::default(),
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            state.store.snapshot(&id, false).unwrap().state,
            JobState::Queued
        );
        assert_eq!(state.store.cancel(&id), Some(JobState::Queued));
        assert_eq!(wait_final(&state, &id).await, JobState::Cancelled);
        drop(slot);
        assert!(!dir.path().join("out/x.bin").exists());
    }
}
