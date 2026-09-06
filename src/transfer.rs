//! The generic copy pipeline: receiver → ByteStream → one or many senders.

use std::time::{Duration, Instant, SystemTime};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use std::sync::Arc;

use crate::hash::{DigestHandle, HashAlgo, hashing, parse_sidecar, sidecar_content_at};
use crate::sign::{Signer, Verifier};
use crate::stream::{Counted, MemoryCache, TeeOptions, tee};
use crate::{Endpoint, Error, Result, SendMeta};

/// How the payload is held while it is delivered to the targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Stream through: constant memory, every target receives the same chunks
    /// as they arrive; the slowest target sets the pace. Not replayable.
    Stream,
    /// Hold the whole payload in memory (up to `limit` bytes, otherwise an
    /// error — never the disk). Replayable: enables retries and a known size.
    Memory { limit: u64 },
}

/// Live counters of a running copy, so a caller can show progress without
/// the pipeline having to know what a terminal is.
#[derive(Debug)]
pub struct Progress {
    /// The very counter the source stream feeds, shared rather than copied.
    read: Arc<std::sync::atomic::AtomicU64>,
    /// `u64::MAX` until the size is known, and if it cannot be known.
    total: std::sync::atomic::AtomicU64,
}

impl Default for Progress {
    fn default() -> Self {
        Progress {
            read: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            total: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }
}

impl Progress {
    pub fn new() -> Arc<Progress> {
        Arc::new(Progress::default())
    }

    /// A progress whose byte counter someone else holds too, so several
    /// copies can add up into one figure (a batch).
    pub fn with_counter(read: Arc<std::sync::atomic::AtomicU64>) -> Arc<Progress> {
        Arc::new(Progress {
            read,
            total: std::sync::atomic::AtomicU64::new(u64::MAX),
        })
    }

    /// Bytes read from the source so far.
    pub fn read(&self) -> u64 {
        self.read.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.read)
    }

    /// Total size, once the source has been asked for it.
    pub fn total(&self) -> Option<u64> {
        match self.total.load(std::sync::atomic::Ordering::Relaxed) {
            u64::MAX => None,
            v => Some(v),
        }
    }

    fn set_total(&self, size: Option<u64>) {
        self.total.store(
            size.unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Options for [`copy_many`].
#[derive(Clone)]
pub struct CopyOptions {
    pub cache: CacheMode,
    /// Additional attempts per target after a failure. Only valid with
    /// [`CacheMode::Memory`]; a stream cannot be replayed.
    pub retries: u32,
    pub tee: TeeOptions,
    /// Compute this checksum while streaming and place `<name>.<ext>` next to
    /// every target (mail targets get it as a second attachment).
    pub hash: Option<HashAlgo>,
    /// Read a checksum file next to the source (`<name>.b3|.sha256|.sha512`)
    /// and verify the transferred content against it.
    pub check: bool,
    /// Sign the checksum file (requires `hash`); writes `<sidecar>.sig|.asc`.
    pub sign: Option<Arc<dyn Signer>>,
    /// With `check`: require a valid signature over the source's checksum
    /// file from one of the trusted keys.
    pub verify: Option<Arc<dyn Verifier>>,
    /// Upload to `<name>.mpt-part` and rename it into place afterwards, so
    /// that the final name never denotes an incomplete file. Ignored by
    /// targets that cannot rename (http, s3, mail). Default `true`.
    pub atomic: bool,
    /// Stops the transfer when it fires: running sends are dropped, partial
    /// files are removed and every unfinished target reports [`Error::Cancelled`].
    pub cancel: Option<CancellationToken>,
    /// Filled in while the source is read, for a progress display.
    pub progress: Option<Arc<Progress>>,
    /// Continue an interrupted transfer: whatever of `<name>.mpt-part` is
    /// already on the target stays, and only the rest is sent. Needs `atomic`
    /// (there is no partial file otherwise) and a target that can append.
    pub resume: bool,
}

impl std::fmt::Debug for CopyOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyOptions")
            .field("cache", &self.cache)
            .field("retries", &self.retries)
            .field("tee", &self.tee)
            .field("hash", &self.hash)
            .field("check", &self.check)
            .field("sign", &self.sign.as_ref().map(|s| s.identity()))
            .field("verify", &self.verify.as_ref().map(|v| v.format()))
            .finish()
    }
}

impl Default for CopyOptions {
    fn default() -> Self {
        CopyOptions {
            cache: CacheMode::Stream,
            retries: 0,
            tee: TeeOptions::default(),
            hash: None,
            check: false,
            sign: None,
            verify: None,
            atomic: true,
            cancel: None,
            progress: None,
            resume: false,
        }
    }
}

/// Result of `--check`: the expected digest from the source's checksum file
/// against what was actually transferred.
#[derive(Debug, Clone)]
pub struct CheckReport {
    pub algo: HashAlgo,
    pub expected: String,
    pub actual: String,
    /// Identity of the trusted key that signed the source's checksum file
    /// (only with `verify`).
    pub signer: Option<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.expected.eq_ignore_ascii_case(&self.actual)
    }

    pub fn error(&self) -> Error {
        Error::ChecksumMismatch {
            algo: self.algo.label(),
            expected: self.expected.clone(),
            actual: self.actual.clone(),
        }
    }
}

/// Summary of a completed 1:1 copy.
#[derive(Debug, Clone)]
pub struct CopyReport {
    pub source: String,
    pub target: String,
    /// Bytes actually transferred.
    pub bytes: u64,
    pub elapsed: Duration,
}

/// Outcome for one target of a fan-out copy.
#[derive(Debug)]
pub struct TargetReport {
    pub target: String,
    /// Bytes the target consumed (may be less than the source size on failure).
    pub bytes: u64,
    pub elapsed: Duration,
    pub attempts: u32,
    pub result: Result<()>,
    /// Location of the checksum file written next to the target, if any.
    pub sidecar: Option<String>,
    /// Location of the detached signature written next to the checksum file, if any.
    pub signature: Option<String>,
}

/// Outcome of [`copy_many`].
#[derive(Debug)]
pub struct FanoutReport {
    pub source: String,
    /// Bytes read from the source.
    pub bytes_read: u64,
    pub elapsed: Duration,
    pub targets: Vec<TargetReport>,
    /// Digests computed over the source stream (empty unless `hash`/`check` was set).
    pub digests: Vec<(HashAlgo, String)>,
    /// Outcome of `check`, if requested.
    pub checked: Option<CheckReport>,
}

impl FanoutReport {
    pub fn all_ok(&self) -> bool {
        self.targets.iter().all(|t| t.result.is_ok())
    }

    pub fn failures(&self) -> impl Iterator<Item = &TargetReport> {
        self.targets.iter().filter(|t| t.result.is_err())
    }
}

/// Copy the resource at `src` to `dst`.
///
/// The source must be able to receive and the destination must be able to send;
/// otherwise a descriptive [`Error::UnsupportedOperation`] is returned before
/// any connection is made.
pub async fn copy(src: &dyn Endpoint, dst: &dyn Endpoint) -> Result<CopyReport> {
    let mut report = copy_many(src, &[dst], &CopyOptions::default()).await?;
    let target = report.targets.remove(0);
    target.result?;
    if let Some(c) = &report.checked
        && !c.ok()
    {
        return Err(c.error());
    }
    Ok(CopyReport {
        source: report.source,
        target: target.target,
        bytes: target.bytes,
        elapsed: report.elapsed,
    })
}

/// Read `src` once and deliver it to every endpoint in `dsts` concurrently.
///
/// Direction errors (a source that cannot receive, a target that cannot send)
/// are reported before any connection is made. A failing target does not stop
/// the others; each target's outcome is in the returned report. `Err` is only
/// returned when the source itself cannot be read.
pub async fn copy_many(
    src: &dyn Endpoint,
    dsts: &[&dyn Endpoint],
    opts: &CopyOptions,
) -> Result<FanoutReport> {
    if dsts.is_empty() {
        return Err(Error::InvalidUrl("no target given".into()));
    }
    if opts.sign.is_some() && opts.hash.is_none() {
        return Err(Error::invalid_option(
            "sign",
            "signing needs a checksum (set hash)",
        ));
    }
    if opts.verify.is_some() && !opts.check {
        return Err(Error::invalid_option(
            "verify",
            "signature verification needs check",
        ));
    }
    if opts.retries > 0 && opts.cache == CacheMode::Stream {
        return Err(Error::invalid_option(
            "retries",
            "retries need the memory cache (a stream cannot be replayed)",
        ));
    }
    let receiver = src.receiver()?;
    let senders = dsts
        .iter()
        .map(|d| d.sender())
        .collect::<Result<Vec<_>>>()?;

    let started = Instant::now();
    let size = receiver.size().await?;
    if let Some(p) = &opts.progress {
        p.set_total(size);
    }
    let mut meta = SendMeta {
        size,
        ..Default::default()
    };
    if let Some(name) = src.location().filename() {
        meta.set_filename(name)?;
    }
    info!(source = %src.location(), targets = dsts.len(), size = ?size, cache = ?opts.cache, hash = ?opts.hash, check = opts.check, "copy");

    // Checksum file next to the source (for `check`), found before anything is transferred.
    let expected = if opts.check {
        Some(find_source_checksum(src, opts.verify.as_deref()).await?)
    } else {
        None
    };
    let mut algos: Vec<HashAlgo> = opts.hash.into_iter().collect();
    if let Some((algo, _, _)) = &expected
        && !algos.contains(algo)
    {
        algos.push(*algo);
    }

    let body = receiver.receive().await?;
    // With a progress display the read counter *is* its counter: one atomic,
    // watched from outside while the copy runs.
    let (body, read_count) = match &opts.progress {
        Some(p) => (Counted::with_counter(body, p.counter()), p.counter()),
        None => Counted::new(body),
    };
    let (body, handles) = hashing(body, &algos);
    let body: crate::ByteStream = Box::pin(body);
    if let Some(algo) = opts.hash {
        meta.digest = handles.iter().find(|h| h.algo() == algo).cloned();
    }
    meta.signer = opts.sign.clone();

    // Atomic finish: upload to `<name>.mpt-part` and rename it into place, so
    // a partial file never appears under the final name.
    let mut plans: Vec<Option<PartPlan>> = dsts
        .iter()
        .zip(&senders)
        .map(|(dst, sender)| part_plan(*dst, *sender, &meta, opts.atomic))
        .collect::<Result<Vec<_>>>()?;
    if opts.resume {
        for plan in plans.iter_mut().flatten() {
            plan.resume_from = resume_offset(plan, size).await;
        }
    }
    let jobs: Vec<Job> = dsts
        .iter()
        .zip(&senders)
        .zip(&plans)
        .map(|((dst, sender), plan)| {
            Ok(Job {
                dst: *dst,
                sender: match plan {
                    Some(p) => p.ep.sender()?,
                    None => *sender,
                },
                meta: match plan {
                    Some(p) => {
                        let mut m = meta.clone();
                        m.set_filename(&p.part)?;
                        m
                    }
                    None => meta.clone(),
                },
                plan: plan.as_ref(),
                keep_partial: opts.resume,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let targets = match opts.cache {
        CacheMode::Memory { limit } => {
            let cache = MemoryCache::from_stream(body, limit).await?;
            meta.size = Some(cache.len());
            // The exact size is only known once everything is buffered.
            let mut jobs = jobs;
            for job in &mut jobs {
                job.meta.size = Some(cache.len());
            }
            debug!(bytes = cache.len(), "payload cached in memory");
            let running = jobs.iter().map(|job| {
                let cache = &cache;
                async move {
                    let t = Instant::now();
                    let mut attempts = 0;
                    let mut bytes;
                    let result = loop {
                        attempts += 1;
                        let reader = crate::stream::Skip::new(cache.reader(), job.skip());
                        let (reader, count) = Counted::new(reader);
                        let r =
                            cancellable(opts.cancel.as_ref(), job.send(Box::pin(reader))).await;
                        bytes = count.load(std::sync::atomic::Ordering::Relaxed);
                        match r {
                            Ok(()) => break Ok(()),
                            Err(Error::Cancelled) => break Err(Error::Cancelled),
                            Err(e) if attempts <= opts.retries => {
                                warn!(target = %job.dst.location(), attempt = attempts, "send failed, retrying: {e}");
                                tokio::time::sleep(Duration::from_secs(attempts as u64)).await;
                            }
                            Err(e) => break Err(e),
                        }
                    };
                    let result = finalize(job, result).await;
                    TargetReport { target: job.dst.location().to_string(), bytes, elapsed: t.elapsed(), attempts, result, sidecar: None, signature: None }
                }
            });
            futures::future::join_all(running).await
        }
        CacheMode::Stream => {
            let (readers, driver) = if dsts.len() == 1 {
                (vec![body], None)
            } else {
                let (readers, driver) = tee(body, dsts.len(), opts.tee);
                (readers, Some(driver))
            };
            let running = jobs.iter().zip(readers).map(|(job, reader)| async move {
                let t = Instant::now();
                // Each target skips what it already has, so one shared stream
                // can serve targets that are at different points.
                let reader = crate::stream::Skip::new(reader, job.skip());
                let (reader, count) = Counted::new(reader);
                let result = cancellable(opts.cancel.as_ref(), job.send(Box::pin(reader))).await;
                let result = finalize(job, result).await;
                TargetReport {
                    target: job.dst.location().to_string(),
                    bytes: count.load(std::sync::atomic::Ordering::Relaxed),
                    elapsed: t.elapsed(),
                    attempts: 1,
                    result,
                    sidecar: None,
                    signature: None,
                }
            });
            let targets = futures::future::join_all(running).await;
            if let Some(driver) = driver {
                match driver.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(Error::Io(e)),
                    Err(e) => {
                        return Err(Error::Io(std::io::Error::other(format!(
                            "tee driver panicked: {e}"
                        ))));
                    }
                }
            }
            targets
        }
    };

    let mut targets = targets;
    let digests: Vec<(HashAlgo, String)> = handles
        .iter()
        .filter_map(|h| h.get().map(|v| (h.algo(), v)))
        .collect();

    // Checksum sidecar next to every target that received the file.
    if let Some(algo) = opts.hash {
        match digests.iter().find(|(a, _)| *a == algo) {
            Some((_, hex)) => {
                for (t, dst) in targets.iter_mut().zip(dsts) {
                    if t.result.is_err() || dst.location().scheme().is_mail() {
                        continue;
                    }
                    match write_sidecar(*dst, algo, hex, &meta, opts.sign.as_deref()).await {
                        Ok((path, sig)) => {
                            t.sidecar = Some(path);
                            t.signature = sig;
                        }
                        Err(e) => {
                            t.result = Err(Error::Remote(format!(
                                "file transferred, but writing the checksum file failed: {e}"
                            )));
                        }
                    }
                }
            }
            None => warn!("source was not read to the end; no checksum files written"),
        }
    }

    let checked = expected.map(|(algo, exp, signer)| CheckReport {
        algo,
        expected: exp,
        actual: digests
            .iter()
            .find(|(a, _)| *a == algo)
            .map(|(_, v)| v.clone())
            .unwrap_or_default(),
        signer,
    });
    if let Some(c) = &checked {
        if c.ok() {
            info!(algo = %c.algo, "checksum verified");
        } else {
            warn!(algo = %c.algo, expected = %c.expected, actual = %c.actual, "CHECKSUM MISMATCH");
        }
    }

    Ok(FanoutReport {
        source: src.location().to_string(),
        bytes_read: read_count.load(std::sync::atomic::Ordering::Relaxed),
        elapsed: started.elapsed(),
        targets,
        digests,
        checked,
    })
}

/// Run `fut`, but give up as soon as `cancel` fires. The future is dropped,
/// which closes whatever connection it was using.
async fn cancellable<F: std::future::Future<Output = Result<()>>>(
    cancel: Option<&CancellationToken>,
    fut: F,
) -> Result<()> {
    match cancel {
        None => fut.await,
        Some(token) => {
            tokio::select! {
                biased;
                () = token.cancelled() => Err(Error::Cancelled),
                r = fut => r,
            }
        }
    }
}

/// Suffix of the temporary file an atomic transfer writes to.
pub const PART_SUFFIX: &str = ".mpt-part";

/// What one target needs: where the bytes go, and how to finish.
struct Job<'a> {
    dst: &'a dyn Endpoint,
    sender: &'a dyn crate::Sender,
    meta: SendMeta,
    plan: Option<&'a PartPlan>,
    /// Whether an interrupted upload is worth keeping for a later `--resume`.
    keep_partial: bool,
}

impl Job<'_> {
    /// Bytes of the payload this target already has.
    fn skip(&self) -> u64 {
        self.plan.map(|p| p.resume_from).unwrap_or(0)
    }

    /// Send the payload, or the rest of it when the target is resuming.
    async fn send(&self, body: crate::ByteStream) -> Result<()> {
        match self.skip() {
            0 => self.sender.send(body, &self.meta).await,
            offset => self.sender.append(body, &self.meta, offset).await,
        }
    }
}

/// The temporary file of an atomic transfer.
struct PartPlan {
    ep: Box<dyn Endpoint>,
    part: String,
    final_name: String,
    /// How much of the part file is already there (0 = start from the top).
    resume_from: u64,
}

/// Decide whether this target gets a `.mpt-part` file, and open an endpoint
/// for it. Targets that cannot rename (http, s3, mail) send directly.
fn part_plan(
    dst: &dyn Endpoint,
    sender: &dyn crate::Sender,
    meta: &SendMeta,
    atomic: bool,
) -> Result<Option<PartPlan>> {
    if !atomic || !sender.supports_rename() || dst.location().scheme().is_mail() {
        return Ok(None);
    }
    let final_name = target_filename(dst, meta);
    let part = format!("{final_name}{PART_SUFFIX}");
    let loc = dst.location().sibling(&part)?;
    debug!(%loc, "uploading to a temporary file");
    Ok(Some(PartPlan {
        ep: crate::protocols::open(loc)?,
        part,
        final_name,
        resume_from: 0,
    }))
}

/// How much of this target's part file is worth keeping: what is already
/// there, as long as the target can append and the payload is longer.
///
/// A part file that is at least as large as the source is not resumable —
/// it may be a leftover of something else — so it is written again.
async fn resume_offset(plan: &PartPlan, size: Option<u64>) -> u64 {
    let Ok(sender) = plan.ep.sender() else {
        return 0;
    };
    if !sender.supports_append() {
        debug!(part = %plan.part, "the target cannot append; sending the whole payload");
        return 0;
    }
    let existing = match plan.ep.sender().unwrap().existing_size(&plan.part).await {
        Ok(Some(n)) => n,
        Ok(None) => return 0,
        Err(e) => {
            debug!(part = %plan.part, "cannot tell how much arrived: {e}");
            return 0;
        }
    };
    match size {
        Some(total) if existing >= total => {
            warn!(
                part = %plan.part,
                existing, total,
                "the partial file is not shorter than the payload; starting again"
            );
            0
        }
        _ if existing == 0 => 0,
        _ => {
            info!(part = %plan.part, offset = existing, "resuming");
            existing
        }
    }
}

/// Move the `.mpt-part` file into place, or clean it up after a failure.
async fn finalize(job: &Job<'_>, result: Result<()>) -> Result<()> {
    let Some(plan) = job.plan else {
        return result;
    };
    let sender = job.dst.sender()?;
    match result {
        Ok(()) => match sender.rename(&plan.part, &plan.final_name).await {
            Ok(()) => {
                debug!(part = %plan.part, name = %plan.final_name, "renamed into place");
                Ok(())
            }
            Err(e) => {
                let _ = sender.remove(&plan.part).await;
                Err(Error::Remote(format!(
                    "upload finished, but renaming {} to {} failed: {e} \
                     (is another transfer writing the same file?)",
                    plan.part, plan.final_name
                )))
            }
        },
        // A transfer that is meant to be resumable keeps what arrived; every
        // other failure takes its leftovers with it.
        Err(e) if job.keep_partial => {
            info!(
                part = %plan.part,
                "keeping the partial file; --resume continues from it"
            );
            Err(e)
        }
        Err(e) => {
            if let Err(cleanup) = sender.remove(&plan.part).await {
                warn!(part = %plan.part, "could not remove the partial file: {cleanup}");
            }
            Err(e)
        }
    }
}

/// Effective file name on the target (directory targets take the source name).
fn target_filename(dst: &dyn Endpoint, meta: &SendMeta) -> String {
    if dst.location().is_dir_target() {
        meta.filename_or("payload").to_string()
    } else {
        dst.location()
            .filename()
            .map(String::from)
            .unwrap_or_else(|| meta.filename_or("payload").to_string())
    }
}

/// Write `<name>.<ext>` next to the transferred file (and `<name>.<ext>.sig|.asc`
/// when a signer is given); returns their locations.
async fn write_sidecar(
    dst: &dyn Endpoint,
    algo: HashAlgo,
    hex: &str,
    meta: &SendMeta,
    signer: Option<&dyn Signer>,
) -> Result<(String, Option<String>)> {
    let name = target_filename(dst, meta);
    let sidecar = algo.sidecar_name(&name);
    let loc = dst.location().sibling(&sidecar)?;
    // A signed checksum file records when it was signed, so a verifier can
    // judge the signer's validity at that moment and refuse an old one.
    let content = sidecar_content_at(hex, &name, signer.map(|_| SystemTime::now()));
    let ep = crate::protocols::open(loc.clone())?;
    let sidecar_meta = SendMeta::from_filename(&sidecar)?.with_size(content.len() as u64);
    ep.sender()?
        .send(
            Box::pin(std::io::Cursor::new(content.clone())),
            &sidecar_meta,
        )
        .await?;
    debug!(%loc, "checksum file written");

    let mut signature = None;
    if let Some(signer) = signer {
        let sig = signer.sign(content.as_bytes()).await?;
        let sig_name = signer.format().signature_name(&sidecar);
        let sig_loc = dst.location().sibling(&sig_name)?;
        let ep = crate::protocols::open(sig_loc.clone())?;
        let sig_meta = SendMeta::from_filename(&sig_name)?.with_size(sig.len() as u64);
        ep.sender()?
            .send(Box::pin(std::io::Cursor::new(sig)), &sig_meta)
            .await?;
        debug!(%sig_loc, "signature written");
        signature = Some(sig_loc.to_string());
    }
    Ok((loc.to_string(), signature))
}

/// Refuse a signature that is older than `policy.max_signature_age`, so an
/// old checksum file cannot be replayed in place of the current one.
fn check_signature_age(signed_at: Option<SystemTime>, max: Option<Duration>) -> Result<()> {
    let Some(max) = max else {
        return Ok(());
    };
    let Some(at) = signed_at else {
        return Err(Error::Signature(format!(
            "the checksum file carries no '{}' line, so its age cannot be judged \
             (policy.max_signature_age is {})",
            crate::hash::SIGNED_AT.trim(),
            fmt_age(max)
        )));
    };
    // A signature from the future is left to the verifier to judge.
    let age = SystemTime::now().duration_since(at).unwrap_or_default();
    if age > max {
        return Err(Error::Signature(format!(
            "the checksum file was signed {} ago ({}), longer than the {} the policy allows",
            fmt_age(age),
            crate::sign::format_time(at),
            fmt_age(max)
        )));
    }
    Ok(())
}

/// A span in the largest unit that still says something, for messages.
fn fmt_age(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=99 => format!("{s}s"),
        100..=5999 => format!("{}m", s / 60),
        6000..=172_799 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// Read a small sibling file of the source (checksum file, signature).
async fn read_sibling(src: &dyn Endpoint, name: &str, limit: u64) -> Result<Vec<u8>> {
    let loc = src.location().sibling(name)?;
    let ep = crate::protocols::open(loc)?;
    let stream = ep.receiver()?.receive().await?;
    crate::stream::read_to_vec(stream, limit).await
}

/// Look for `<name>.b3`, `.sha256`, `.sha512` next to the source and parse it.
/// With a verifier, the matching `.sig`/`.asc` must exist and be valid; the
/// signer's identity is returned as the third element.
async fn find_source_checksum(
    src: &dyn Endpoint,
    verifier: Option<&dyn Verifier>,
) -> Result<(HashAlgo, String, Option<String>)> {
    let name = src
        .location()
        .filename()
        .ok_or_else(|| {
            Error::InvalidUrl(
                "check: the source has no file name to look up a checksum file for".into(),
            )
        })?
        .to_string();
    let mut tried = Vec::new();
    for algo in HashAlgo::ALL {
        let sidecar = algo.sidecar_name(&name);
        let loc = src.location().sibling(&sidecar)?;
        tried.push(loc.to_string());
        let ep = crate::protocols::open(loc.clone())?;
        let stream = match ep.receiver()?.receive().await {
            Ok(s) => s,
            Err(e) => {
                debug!(%loc, "no checksum file: {e}");
                continue;
            }
        };
        let text = match crate::stream::read_to_vec(stream, 8192).await {
            Ok(v) => String::from_utf8_lossy(&v).into_owned(),
            Err(e) => {
                debug!(%loc, "unreadable checksum file: {e}");
                continue;
            }
        };
        let Some((hex, _)) = parse_sidecar(&text) else {
            return Err(Error::Remote(format!(
                "check: {loc} is not a valid checksum file"
            )));
        };
        info!(%loc, algo = %algo, "checksum file found");
        let mut signer = None;
        if let Some(v) = verifier {
            let sig_name = v.format().signature_name(&sidecar);
            let sig = read_sibling(src, &sig_name, 64 * 1024).await.map_err(|e| {
                Error::Signature(format!(
                    "check: no {} signature {sig_name} next to the source: {e}",
                    v.format().label()
                ))
            })?;
            // Judge the signer as it stood when it signed, not as it stands
            // now: a key that has expired since then still signed validly.
            let signed_at = crate::hash::parse_signed_at(&text);
            check_signature_age(signed_at, crate::policy::policy().max_signature_age)?;
            let who = v.verify_at(
                text.as_bytes(),
                &sig,
                signed_at.unwrap_or_else(SystemTime::now),
            )?;
            info!(%who, signed_at = ?signed_at.map(crate::sign::format_time), "checksum file signature verified");
            signer = Some(who);
        }
        return Ok((algo, hex, signer));
    }
    Err(Error::Remote(format!(
        "check: no checksum file next to the source (tried {})",
        tried.join(", ")
    )))
}

#[allow(dead_code)]
fn _assert_handle_is_send(_: DigestHandle) {}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fanout_local(mode: CacheMode) {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.bin");
        let data: Vec<u8> = (0..500_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(&src_path, &data).unwrap();

        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let d1 = crate::open(&format!("{}/a/", dir.path().display())).unwrap();
        let d2 = crate::open(&format!("{}/b/", dir.path().display())).unwrap();
        // A file target whose parent cannot be created (a regular file in the way).
        std::fs::write(dir.path().join("blocker"), b"x").unwrap();
        let d3 = crate::open(&format!("{}/blocker/c/", dir.path().display())).unwrap();

        let opts = CopyOptions {
            cache: mode,
            retries: if mode == CacheMode::Stream { 0 } else { 1 },
            tee: TeeOptions {
                chunk_size: 8192,
                capacity: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let report = copy_many(
            src.as_ref(),
            &[d1.as_ref(), d2.as_ref(), d3.as_ref()],
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(report.bytes_read, data.len() as u64);
        assert_eq!(report.targets.len(), 3);
        assert!(report.targets[0].result.is_ok());
        assert!(report.targets[1].result.is_ok());
        assert!(report.targets[2].result.is_err());
        assert!(!report.all_ok());
        assert_eq!(report.failures().count(), 1);
        assert_eq!(report.targets[0].bytes, data.len() as u64);
        assert_eq!(std::fs::read(dir.path().join("a/src.bin")).unwrap(), data);
        assert_eq!(std::fs::read(dir.path().join("b/src.bin")).unwrap(), data);
    }

    #[tokio::test]
    async fn fanout_stream_mode_isolates_failures() {
        fanout_local(CacheMode::Stream).await;
    }

    #[tokio::test]
    async fn fanout_memory_mode_isolates_failures() {
        fanout_local(CacheMode::Memory { limit: 1 << 20 }).await;
    }

    /// A source that yields `good` bytes and then fails, to model a transfer
    /// that dies halfway through.
    struct FailingSource {
        loc: crate::Location,
        good: usize,
    }

    struct FailingReader {
        left: usize,
    }

    impl tokio::io::AsyncRead for FailingReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.left == 0 {
                return std::task::Poll::Ready(Err(std::io::Error::other("source died")));
            }
            let n = self.left.min(buf.remaining());
            buf.put_slice(&vec![b'x'; n]);
            self.left -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[async_trait::async_trait]
    impl crate::Receiver for FailingSource {
        async fn receive(&self) -> Result<crate::ByteStream> {
            Ok(Box::pin(FailingReader { left: self.good }))
        }
        async fn list(&self) -> Result<Vec<crate::Entry>> {
            Ok(Vec::new())
        }
    }

    impl Endpoint for FailingSource {
        fn location(&self) -> &crate::Location {
            &self.loc
        }
        fn as_receiver(&self) -> Option<&dyn crate::Receiver> {
            Some(self)
        }
        fn as_sender(&self) -> Option<&dyn crate::Sender> {
            None
        }
    }

    #[tokio::test]
    async fn atomic_transfer_leaves_no_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.bin");
        std::fs::write(&src_path, vec![7u8; 1000]).unwrap();
        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let dst = crate::open(&format!("{}/out/", dir.path().display())).unwrap();

        let report = copy_many(src.as_ref(), &[dst.as_ref()], &CopyOptions::default())
            .await
            .unwrap();
        assert!(report.all_ok());
        assert_eq!(
            std::fs::read(dir.path().join("out/src.bin")).unwrap().len(),
            1000
        );
        assert!(!dir.path().join("out/src.bin.mpt-part").exists());
    }

    #[tokio::test]
    async fn a_broken_transfer_leaves_nothing_under_the_final_name() {
        let dir = tempfile::tempdir().unwrap();
        let src = FailingSource {
            loc: crate::Location::parse("/nowhere/src.bin").unwrap(),
            good: 4096,
        };
        let dst = crate::open(&format!("{}/out/", dir.path().display())).unwrap();

        let report = copy_many(&src, &[dst.as_ref()], &CopyOptions::default())
            .await
            .unwrap();
        assert!(report.targets[0].result.is_err());
        assert!(
            !dir.path().join("out/src.bin").exists(),
            "an incomplete file must not appear under the final name"
        );
        assert!(!dir.path().join("out/src.bin.mpt-part").exists());

        // Without the atomic finish an incomplete file stays behind under the
        // final name — which is exactly what the .mpt-part detour avoids.
        let opts = CopyOptions {
            atomic: false,
            ..Default::default()
        };
        let report = copy_many(&src, &[dst.as_ref()], &opts).await.unwrap();
        assert!(report.targets[0].result.is_err());
        let left = std::fs::read(dir.path().join("out/src.bin")).unwrap();
        assert!(
            left.len() < 4096 + 1,
            "the leftover file holds at most what was transferred"
        );
    }

    /// A source that keeps trickling bytes, so a transfer can be interrupted.
    struct SlowSource {
        loc: crate::Location,
    }

    #[async_trait::async_trait]
    impl crate::Receiver for SlowSource {
        async fn receive(&self) -> Result<crate::ByteStream> {
            let s = futures::stream::unfold(0usize, |i| async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Some((
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(&[7u8; 1024])),
                    i + 1,
                ))
            });
            Ok(Box::pin(tokio_util::io::StreamReader::new(s)))
        }
        async fn list(&self) -> Result<Vec<crate::Entry>> {
            Ok(Vec::new())
        }
    }

    impl Endpoint for SlowSource {
        fn location(&self) -> &crate::Location {
            &self.loc
        }
        fn as_receiver(&self) -> Option<&dyn crate::Receiver> {
            Some(self)
        }
        fn as_sender(&self) -> Option<&dyn crate::Sender> {
            None
        }
    }

    #[tokio::test]
    async fn cancelling_removes_the_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = SlowSource {
            loc: crate::Location::parse("/nowhere/src.bin").unwrap(),
        };
        let dst = crate::open(&format!("{}/out/", dir.path().display())).unwrap();
        let cancel = CancellationToken::new();
        let opts = CopyOptions {
            cancel: Some(cancel.clone()),
            ..Default::default()
        };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            cancel.cancel();
        });

        let report = tokio::time::timeout(
            Duration::from_secs(10),
            copy_many(&src, &[dst.as_ref()], &opts),
        )
        .await
        .expect("cancellation must end the copy")
        .unwrap();

        assert!(
            matches!(report.targets[0].result, Err(Error::Cancelled)),
            "{:?}",
            report.targets[0].result
        );
        assert!(!dir.path().join("out/src.bin").exists());
        assert!(
            !dir.path().join("out/src.bin.mpt-part").exists(),
            "the partial file must be cleaned up"
        );
    }

    #[tokio::test]
    async fn memory_limit_is_enforced_without_disk() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.bin");
        std::fs::write(&src_path, vec![0u8; 20_000]).unwrap();
        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let dst = crate::open(&format!("{}/out/", dir.path().display())).unwrap();
        let opts = CopyOptions {
            cache: CacheMode::Memory { limit: 10_000 },
            ..Default::default()
        };
        let err = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
        assert!(!dir.path().join("out").exists());
    }

    async fn hash_sidecar(mode: CacheMode) {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("payload.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 7) as u8).collect();
        std::fs::write(&src_path, &data).unwrap();
        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let d1 = crate::open(&format!("{}/a/", dir.path().display())).unwrap();
        let d2 = crate::open(&format!("{}/b/renamed.bin", dir.path().display())).unwrap();
        let opts = CopyOptions {
            cache: mode,
            hash: Some(HashAlgo::Blake3),
            ..Default::default()
        };
        let report = copy_many(src.as_ref(), &[d1.as_ref(), d2.as_ref()], &opts)
            .await
            .unwrap();
        assert!(report.all_ok(), "{:?}", report.targets);
        let expected = crate::hash::digest_bytes(HashAlgo::Blake3, &data);
        assert_eq!(report.digests, vec![(HashAlgo::Blake3, expected.clone())]);
        let s1 = std::fs::read_to_string(dir.path().join("a/payload.bin.b3")).unwrap();
        assert_eq!(s1, format!("{expected}  payload.bin\n"));
        let s2 = std::fs::read_to_string(dir.path().join("b/renamed.bin.b3")).unwrap();
        assert_eq!(s2, format!("{expected}  renamed.bin\n"));
        assert!(
            report.targets[0]
                .sidecar
                .as_deref()
                .unwrap()
                .ends_with("a/payload.bin.b3")
        );
    }

    #[tokio::test]
    async fn hash_sidecar_stream_mode() {
        hash_sidecar(CacheMode::Stream).await;
    }

    #[tokio::test]
    async fn hash_sidecar_memory_mode() {
        hash_sidecar(CacheMode::Memory { limit: 1 << 20 }).await;
    }

    #[tokio::test]
    async fn check_against_source_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("in.bin");
        let data = vec![7u8; 50_000];
        std::fs::write(&src_path, &data).unwrap();
        let good = crate::hash::digest_bytes(HashAlgo::Sha256, &data);
        std::fs::write(
            dir.path().join("in.bin.sha256"),
            format!("{good}  in.bin\n"),
        )
        .unwrap();

        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let dst = crate::open(&format!("{}/out/", dir.path().display())).unwrap();
        let opts = CopyOptions {
            check: true,
            ..Default::default()
        };
        let report = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap();
        let c = report.checked.unwrap();
        assert!(c.ok());
        assert_eq!(c.algo, HashAlgo::Sha256);
        assert!(
            report.targets[0].sidecar.is_none(),
            "check alone writes no sidecar"
        );

        // Tampered checksum file → mismatch reported, `copy` turns it into an error.
        std::fs::write(
            dir.path().join("in.bin.sha256"),
            format!("{}  in.bin\n", "0".repeat(64)),
        )
        .unwrap();
        let report = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap();
        assert!(!report.checked.unwrap().ok());

        // No checksum file at all → explicit error.
        std::fs::remove_file(dir.path().join("in.bin.sha256")).unwrap();
        let err = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no checksum file"), "{err}");
    }

    #[cfg(feature = "sign-ssh")]
    #[test]
    fn old_signatures_are_refused_when_the_policy_says_so() {
        let hour = Duration::from_secs(3600);
        let ago = |d: Duration| Some(SystemTime::now() - d);
        // No limit: anything goes, with or without a timestamp.
        assert!(check_signature_age(ago(hour * 100), None).is_ok());
        assert!(check_signature_age(None, None).is_ok());
        // Inside the limit.
        assert!(check_signature_age(ago(hour), Some(hour * 24)).is_ok());
        // Too old.
        let err = check_signature_age(ago(hour * 50), Some(hour * 24))
            .unwrap_err()
            .to_string();
        assert!(err.contains("2d ago") && err.contains("24h"), "{err}");
        // Without a signing time the age cannot be judged at all.
        let err = check_signature_age(None, Some(hour))
            .unwrap_err()
            .to_string();
        assert!(err.contains("mpt-signed-at"), "{err}");
        // A clock that runs behind must not turn into a huge age.
        assert!(check_signature_age(Some(SystemTime::now() + hour), Some(hour)).is_ok());
    }

    #[tokio::test]
    async fn a_resumed_copy_sends_only_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
        let src_path = dir.path().join("data.bin");
        std::fs::write(&src_path, &payload).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        // What an interrupted transfer left behind.
        std::fs::write(out.join("data.bin.mpt-part"), &payload[..10_000]).unwrap();

        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let dst = crate::open(&format!("{}/", out.display())).unwrap();
        let opts = CopyOptions {
            resume: true,
            hash: Some(HashAlgo::Sha256),
            ..Default::default()
        };
        let report = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap();
        assert!(report.all_ok(), "{:?}", report.targets);
        assert_eq!(
            report.targets[0].bytes, 20_000,
            "only the missing part travels"
        );
        assert_eq!(report.bytes_read, 30_000, "but the source is read in full");
        assert_eq!(std::fs::read(out.join("data.bin")).unwrap(), payload);
        // The checksum covers the whole file, not just what was sent.
        assert_eq!(
            report.digests[0].1,
            crate::hash::digest_bytes(HashAlgo::Sha256, &payload)
        );
        assert!(!out.join("data.bin.mpt-part").exists());

        // A leftover that is not shorter than the payload is not resumable.
        std::fs::remove_file(out.join("data.bin")).unwrap();
        std::fs::write(out.join("data.bin.mpt-part"), vec![0u8; 30_000]).unwrap();
        let report = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap();
        assert_eq!(report.targets[0].bytes, 30_000, "written from the top");
        assert_eq!(std::fs::read(out.join("data.bin")).unwrap(), payload);
    }

    #[tokio::test]
    async fn without_resume_the_partial_file_is_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![7u8; 5_000];
        let src_path = dir.path().join("data.bin");
        std::fs::write(&src_path, &payload).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("data.bin.mpt-part"), vec![9u8; 1_000]).unwrap();

        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let dst = crate::open(&format!("{}/", out.display())).unwrap();
        let report = copy_many(src.as_ref(), &[dst.as_ref()], &CopyOptions::default())
            .await
            .unwrap();
        assert!(report.all_ok());
        assert_eq!(report.targets[0].bytes, 5_000);
        assert_eq!(std::fs::read(out.join("data.bin")).unwrap(), payload);
    }

    #[tokio::test]
    async fn sign_sidecar_and_verify_on_check() {
        use crate::sign::{SignFormat, SignSpec, VerifySpec};
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "ci@example.com",
                "-f",
            ])
            .arg(&key)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("skipping: ssh-keygen not available");
            return;
        }
        let signers = dir.path().join("allowed_signers");
        std::fs::write(
            &signers,
            format!(
                "ci@example.com {}",
                std::fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap()
            ),
        )
        .unwrap();

        let src_path = dir.path().join("data.bin");
        std::fs::write(&src_path, vec![3u8; 10_000]).unwrap();
        let src = crate::open(src_path.to_str().unwrap()).unwrap();
        let dst = crate::open(&format!("{}/out/", dir.path().display())).unwrap();
        let signer = crate::sign::load_signer(&SignSpec {
            format: SignFormat::Ssh,
            key: Some(key),
            passphrase: None,
        })
        .await
        .unwrap();
        let opts = CopyOptions {
            hash: Some(HashAlgo::Sha256),
            sign: Some(signer),
            ..Default::default()
        };
        let report = copy_many(src.as_ref(), &[dst.as_ref()], &opts)
            .await
            .unwrap();
        assert!(report.all_ok(), "{:?}", report.targets);
        let sig_path = dir.path().join("out/data.bin.sha256.sig");
        assert!(sig_path.exists());
        assert!(
            report.targets[0]
                .signature
                .as_deref()
                .unwrap()
                .ends_with("data.bin.sha256.sig")
        );

        // The signed checksum file says when it was signed.
        let text = std::fs::read_to_string(dir.path().join("out/data.bin.sha256")).unwrap();
        let signed_at = crate::hash::parse_signed_at(&text).expect("signing time");
        assert!(
            SystemTime::now().duration_since(signed_at).unwrap() < Duration::from_secs(60),
            "{text}"
        );

        // Copy back with check + verify: signature must be accepted.
        let verifier = crate::sign::load_verifier(&VerifySpec::SshAllowedSigners(signers)).unwrap();
        let out_file = crate::open(dir.path().join("out/data.bin").to_str().unwrap()).unwrap();
        let back = crate::open(&format!("{}/back/", dir.path().display())).unwrap();
        let opts = CopyOptions {
            check: true,
            verify: Some(verifier.clone()),
            ..Default::default()
        };
        let report = copy_many(out_file.as_ref(), &[back.as_ref()], &opts)
            .await
            .unwrap();
        let c = report.checked.unwrap();
        assert!(c.ok());
        assert!(c.signer.as_deref().unwrap().starts_with("ci@example.com"));

        // Tampered checksum file → signature invalid → error before any transfer.
        let sidecar = dir.path().join("out/data.bin.sha256");
        let mut text = std::fs::read_to_string(&sidecar).unwrap();
        text.replace_range(0..1, "0");
        std::fs::write(&sidecar, text).unwrap();
        let err = copy_many(out_file.as_ref(), &[back.as_ref()], &opts)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err}");
        assert!(!dir.path().join("back2").exists());

        // Missing signature → error.
        std::fs::remove_file(&sig_path).unwrap();
        let err = copy_many(out_file.as_ref(), &[back.as_ref()], &opts)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no OpenSSH signature"), "{err}");

        // sign without hash is rejected up front.
        let bad = CopyOptions {
            sign: Some(dummy_signer()),
            ..Default::default()
        };
        assert!(matches!(
            copy_many(src.as_ref(), &[dst.as_ref()], &bad)
                .await
                .unwrap_err(),
            Error::InvalidOption { .. }
        ));
        // verify without check likewise.
        let bad = CopyOptions {
            verify: Some(verifier),
            ..Default::default()
        };
        assert!(matches!(
            copy_many(src.as_ref(), &[dst.as_ref()], &bad)
                .await
                .unwrap_err(),
            Error::InvalidOption { .. }
        ));
    }

    #[cfg(feature = "sign-ssh")]
    fn dummy_signer() -> Arc<dyn Signer> {
        struct Dummy;
        #[async_trait::async_trait]
        impl Signer for Dummy {
            fn format(&self) -> crate::sign::SignFormat {
                crate::sign::SignFormat::Ssh
            }
            fn identity(&self) -> String {
                "dummy".into()
            }
            async fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
        }
        Arc::new(Dummy)
    }

    #[tokio::test]
    async fn retries_require_cache() {
        let dir = tempfile::tempdir().unwrap();
        let src = crate::open(dir.path().to_str().unwrap()).unwrap();
        let opts = CopyOptions {
            retries: 2,
            ..Default::default()
        };
        assert!(matches!(
            copy_many(src.as_ref(), &[src.as_ref()], &opts)
                .await
                .unwrap_err(),
            Error::InvalidOption { .. }
        ));
    }
}
