//! The generic copy pipeline: receiver → ByteStream → sender.

use std::time::{Duration, Instant};

use tracing::info;

use crate::{Endpoint, Result, SendMeta};

/// Summary of a completed copy.
#[derive(Debug, Clone)]
pub struct CopyReport {
    pub source: String,
    pub target: String,
    /// Bytes actually transferred.
    pub bytes: u64,
    pub elapsed: Duration,
}

/// Copy the resource at `src` to `dst`.
///
/// The source must be able to receive and the destination must be able to send;
/// otherwise a descriptive [`crate::Error::UnsupportedOperation`] is returned
/// before any connection is made.
pub async fn copy(src: &dyn Endpoint, dst: &dyn Endpoint) -> Result<CopyReport> {
    let receiver = src.receiver()?;
    let sender = dst.sender()?;

    let started = Instant::now();
    let size = receiver.size().await?;
    let mut meta = SendMeta {
        size,
        ..Default::default()
    };
    if let Some(name) = src.location().filename() {
        meta.filename = Some(name.to_string());
    }

    info!(source = %src.location(), target = %dst.location(), size = ?size, "copy");
    let body = receiver.receive().await?;
    let (counted, count) = crate::stream::Counted::new(body);
    sender.send(Box::pin(counted), &meta).await?;

    Ok(CopyReport {
        source: src.location().to_string(),
        target: dst.location().to_string(),
        bytes: count.load(std::sync::atomic::Ordering::Relaxed),
        elapsed: started.elapsed(),
    })
}
