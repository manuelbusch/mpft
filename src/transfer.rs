//! The generic copy pipeline: receiver → ByteStream → one or many senders.

use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

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

/// Options for [`copy_many`].
#[derive(Debug, Clone, Copy)]
pub struct CopyOptions {
    pub cache: CacheMode,
    /// Additional attempts per target after a failure. Only valid with
    /// [`CacheMode::Memory`]; a stream cannot be replayed.
    pub retries: u32,
    pub tee: TeeOptions,
}

impl Default for CopyOptions {
    fn default() -> Self {
        CopyOptions {
            cache: CacheMode::Stream,
            retries: 0,
            tee: TeeOptions::default(),
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
}

/// Outcome of [`copy_many`].
#[derive(Debug)]
pub struct FanoutReport {
    pub source: String,
    /// Bytes read from the source.
    pub bytes_read: u64,
    pub elapsed: Duration,
    pub targets: Vec<TargetReport>,
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
    let mut meta = SendMeta {
        size,
        ..Default::default()
    };
    if let Some(name) = src.location().filename() {
        meta.filename = Some(name.to_string());
    }
    info!(source = %src.location(), targets = dsts.len(), size = ?size, cache = ?opts.cache, "copy");

    let body = receiver.receive().await?;
    let (body, read_count) = Counted::new(body);
    let body: crate::ByteStream = Box::pin(body);

    let targets = match opts.cache {
        CacheMode::Memory { limit } => {
            let cache = MemoryCache::from_stream(body, limit).await?;
            meta.size = Some(cache.len());
            debug!(bytes = cache.len(), "payload cached in memory");
            let jobs = dsts.iter().zip(&senders).map(|(dst, sender)| {
                let cache = &cache;
                let meta = &meta;
                async move {
                    let t = Instant::now();
                    let mut attempts = 0;
                    let mut bytes;
                    let result = loop {
                        attempts += 1;
                        let (reader, count) = Counted::new(cache.reader());
                        let r = sender.send(Box::pin(reader), meta).await;
                        bytes = count.load(std::sync::atomic::Ordering::Relaxed);
                        match r {
                            Ok(()) => break Ok(()),
                            Err(e) if attempts <= opts.retries => {
                                warn!(target = %dst.location(), attempt = attempts, "send failed, retrying: {e}");
                                tokio::time::sleep(Duration::from_secs(attempts as u64)).await;
                            }
                            Err(e) => break Err(e),
                        }
                    };
                    TargetReport { target: dst.location().to_string(), bytes, elapsed: t.elapsed(), attempts, result }
                }
            });
            futures::future::join_all(jobs).await
        }
        CacheMode::Stream => {
            let (readers, driver) = if dsts.len() == 1 {
                (vec![body], None)
            } else {
                let (readers, driver) = tee(body, dsts.len(), opts.tee);
                (readers, Some(driver))
            };
            let jobs = dsts
                .iter()
                .zip(&senders)
                .zip(readers)
                .map(|((dst, sender), reader)| {
                    let meta = &meta;
                    async move {
                        let t = Instant::now();
                        let (reader, count) = Counted::new(reader);
                        let result = sender.send(Box::pin(reader), meta).await;
                        TargetReport {
                            target: dst.location().to_string(),
                            bytes: count.load(std::sync::atomic::Ordering::Relaxed),
                            elapsed: t.elapsed(),
                            attempts: 1,
                            result,
                        }
                    }
                });
            let targets = futures::future::join_all(jobs).await;
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

    Ok(FanoutReport {
        source: src.location().to_string(),
        bytes_read: read_count.load(std::sync::atomic::Ordering::Relaxed),
        elapsed: started.elapsed(),
        targets,
    })
}

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
            },
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
