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
use super::store::Prepared;
use crate::batch::{self, Job, JobReport, PrepareOptions};
use crate::config::PROFILE_PREFIX;
use crate::{Error, Location, Result};

/// Start the job's task.
pub(crate) fn spawn_job(state: Arc<AppState>, id: JobId) {
    tokio::spawn(run(state, id));
}

async fn run(state: Arc<AppState>, id: JobId) {
    let Some((submission, token)) = state.store.submission(&id) else {
        return;
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
    let prepared = prepare(&state, &submission).await;
    drop(permit);
    let (jobs, refs) = match prepared {
        Ok(p) => p,
        Err(e) => {
            warn!(%id, "not run: {}", e.message);
            state.store.fail(&id, e, journal(&state));
            return;
        }
    };
    if token.is_cancelled() {
        release(
            &state,
            &jobs.iter().map(|p| p.job.clone()).collect::<Vec<_>>(),
        );
        state.store.finish(&id, journal(&state));
        return;
    }
    let n = jobs.len();
    info!(%id, transfers = n, "running");
    let plain: Vec<Job> = jobs.iter().map(|p| p.job.clone()).collect();
    let counters = state.store.start(&id, jobs);
    let jobs = plain;
    let per_job = submission
        .options
        .parallel
        .unwrap_or(state.rt.parallel)
        .clamp(1, state.cfg.parallel);
    let job_slots = Arc::new(Semaphore::new(per_job));
    let fail_fast = submission.options.fail_fast.unwrap_or(false);
    let mut tasks = JoinSet::new();
    for (index, (job, progress)) in jobs.into_iter().zip(counters).enumerate() {
        let state = Arc::clone(&state);
        let id = id.clone();
        let token = token.clone();
        let job_slots = Arc::clone(&job_slots);
        let options = submission.options.clone();
        let refs = Arc::clone(&refs);
        tasks.spawn(async move {
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
            let outcome = state.store.transfer_done(&id, &report, json);
            debug!(%id, index, ?outcome, "transfer over");
            if fail_fast && outcome == TransferState::Failed && !token.is_cancelled() {
                warn!(%id, index, "failed, stopping the job");
                state.store.set_stopped_early(&id);
                token.cancel();
            }
            report.job
        });
    }
    while let Some(done) = tasks.join_next().await {
        match done {
            Ok(job) => release(&state, std::slice::from_ref(&job)),
            Err(e) => warn!(%id, "a transfer task ended badly: {e}"),
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
async fn prepare(
    state: &AppState,
    submission: &Submission,
) -> std::result::Result<(Vec<Prepared>, Arc<Refs>), ApiError> {
    crate::config::resolve_more(&submission.urls(), state.rt.signing).await?;
    let jobs = submission
        .specs
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            locate_spec(spec, state.rt.locate.as_ref(), &submission.options)
                .map_err(|e| ApiError::new(e.kind(), format!("job {}: {e}", i + 1)))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let open = |l: &Location| crate::protocols::open(l.clone());
    let opts = PrepareOptions {
        allow_empty: submission.options.allow_empty.unwrap_or(false),
        recursive: submission.options.recursive.unwrap_or(false),
        no_mkdir: false,
    };
    // What was submitted, next to what it resolved to, so an expanded
    // file can be shown by its reference.
    let refs: Refs = submission
        .specs
        .iter()
        .zip(&jobs)
        .flat_map(|(spec, job)| {
            std::iter::once((spec.src.clone(), job.src.clone()))
                .chain(spec.dsts.iter().cloned().zip(job.dsts.iter().cloned()))
        })
        .collect();
    let jobs = batch::prepare(jobs, &open, &opts).await?;
    let mut targets = state.targets.lock().unwrap_or_else(|e| e.into_inner());
    for (i, job) in jobs.iter().enumerate() {
        if let Err(e) = targets.note(job, i + 1) {
            for earlier in &jobs[..i] {
                targets.release(earlier);
            }
            return Err(ApiError::new(
                "conflict",
                format!("a target is already being written: {e}"),
            ));
        }
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
    let mpt_refs = refs
        .iter()
        .filter(|(url, _)| url.starts_with(PROFILE_PREFIX));
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

fn locate_spec(
    spec: &crate::batch::jobs::JobSpec,
    locate: &(dyn Fn(&str, &JobOptions) -> Result<Location> + Send + Sync),
    options: &JobOptions,
) -> Result<Job> {
    Ok(Job {
        src: locate(&spec.src, options)?,
        dsts: spec
            .dsts
            .iter()
            .map(|d| locate(d, options))
            .collect::<Result<Vec<_>>>()?,
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
            .unwrap();
        assert_eq!(wait_final(&state, &id).await, JobState::Failed);
        let snap = state.store.snapshot(&id, true).unwrap();
        assert_eq!(snap.error.unwrap().kind, "invalid_url");
        assert!(snap.transfers.unwrap().is_empty());
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
            .unwrap();
        assert_eq!(wait_final(&state, &first).await, JobState::Done);
        let second = state
            .submit(batch(
                vec![(src.display().to_string(), out.clone())],
                JobOptions::default(),
            ))
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
            .unwrap();
        assert_eq!(wait_final(&state, &fourth).await, JobState::Done);
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
