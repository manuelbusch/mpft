use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Result;

/// A boxed, sendable async byte source. Every protocol produces and consumes this.
pub type ByteStream = Pin<Box<dyn AsyncRead + Send + 'static>>;

/// Box any async reader into a [`ByteStream`].
pub fn boxed<R: AsyncRead + Send + 'static>(reader: R) -> ByteStream {
    Box::pin(reader)
}

/// Read a whole stream into memory, refusing to exceed `max` bytes.
pub async fn read_to_vec(mut stream: ByteStream, max: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut limited = (&mut stream).take(max + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() as u64 > max {
        return Err(crate::Error::Io(std::io::Error::other(format!(
            "payload exceeds the configured limit of {max} bytes"
        ))));
    }
    Ok(buf)
}

/// Spool a stream into an anonymous temporary file so that its size is known
/// and it can be re-read. Used by protocols that need the length up front (SCP).
pub async fn spool_to_tempfile(mut stream: ByteStream) -> Result<(tokio::fs::File, u64)> {
    let std_file = tempfile::tempfile()?;
    let mut file = tokio::fs::File::from_std(std_file);
    let n = tokio::io::copy(&mut stream, &mut file).await?;
    file.flush().await?;
    file.rewind_start().await?;
    Ok((file, n))
}

trait RewindExt {
    async fn rewind_start(&mut self) -> std::io::Result<()>;
}

impl RewindExt for tokio::fs::File {
    async fn rewind_start(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncSeekExt;
        self.seek(std::io::SeekFrom::Start(0)).await.map(|_| ())
    }
}

/// Copy a stream into any async writer and return the number of bytes written.
pub async fn pipe<W: AsyncWrite + Unpin>(mut stream: ByteStream, writer: &mut W) -> Result<u64> {
    let n = tokio::io::copy(&mut stream, writer).await?;
    writer.flush().await?;
    Ok(n)
}

/// A reader that keeps an arbitrary guard value alive for as long as the
/// stream is being read (e.g. an SSH session that owns the channel).
pub struct Guarded<R, G> {
    inner: R,
    _guard: G,
}

impl<R, G> Guarded<R, G> {
    pub fn new(inner: R, guard: G) -> Self {
        Guarded {
            inner,
            _guard: guard,
        }
    }
}

impl<R: AsyncRead + Unpin, G: Unpin> AsyncRead for Guarded<R, G> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Counts the bytes that pass through a reader (shared via an atomic so the
/// caller can read the total after the stream has been consumed).
pub struct Counted<R> {
    inner: R,
    count: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<R> Counted<R> {
    pub fn new(inner: R) -> (Self, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        (
            Counted {
                inner,
                count: count.clone(),
            },
            count,
        )
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &res {
            let n = (buf.filled().len() - before) as u64;
            self.count
                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }
        res
    }
}
