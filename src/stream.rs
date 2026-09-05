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

// ---------------------------------------------------------------------------
// Fan-out: one source stream, many readers, constant memory, no disk.
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Tuning for [`tee`].
#[derive(Debug, Clone, Copy)]
pub struct TeeOptions {
    /// Bytes read from the source per chunk. Default 64 KiB.
    pub chunk_size: usize,
    /// Chunks buffered per reader before the source is paused. Default 16.
    pub capacity: usize,
    /// How long a reader may leave its queue full before it is dropped from
    /// the fan-out. `None` waits forever, which lets one stalled target hold
    /// up all the others. Default 30 seconds.
    pub send_timeout: Option<std::time::Duration>,
}

impl Default for TeeOptions {
    fn default() -> Self {
        TeeOptions {
            chunk_size: 64 * 1024,
            capacity: 16,
            send_timeout: Some(std::time::Duration::from_secs(30)),
        }
    }
}

/// Split `body` into `n` independent readers that all see the same bytes.
///
/// A driver task (spawned, returned as the `JoinHandle`) reads chunks from the
/// source and hands each chunk, as a reference-counted [`Bytes`], to every
/// reader through a bounded channel. Nothing is copied and nothing touches the
/// disk; memory use is about `capacity × chunk_size` regardless of `n`. The
/// slowest reader dictates the pace (backpressure). A reader that is dropped
/// early is silently removed; the others keep receiving. A read error on the
/// source is delivered to every remaining reader and returned by the driver.
///
/// A reader whose queue stays full for `opts.send_timeout` is dropped from the
/// fan-out and sees a `TimedOut` error, so one stalled target cannot stop the
/// remaining ones.
pub fn tee(
    mut body: ByteStream,
    n: usize,
    opts: TeeOptions,
) -> (Vec<ByteStream>, JoinHandle<std::io::Result<()>>) {
    let capacity = opts.capacity.max(1);
    let chunk_size = opts.chunk_size.max(1024);
    let send_timeout = opts.send_timeout;
    let mut senders: Vec<(mpsc::Sender<std::io::Result<Bytes>>, Arc<AtomicBool>)> =
        Vec::with_capacity(n);
    let mut readers: Vec<ByteStream> = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, mut rx) = mpsc::channel::<std::io::Result<Bytes>>(capacity);
        // Set when the driver gives up on this reader, so that closing the
        // channel reports an error instead of a clean end of stream.
        let stalled = Arc::new(AtomicBool::new(false));
        senders.push((tx, Arc::clone(&stalled)));
        let mut ended = false;
        let stream = futures::stream::poll_fn(move |cx| {
            if ended {
                return std::task::Poll::Ready(None);
            }
            match rx.poll_recv(cx) {
                std::task::Poll::Ready(None) => {
                    ended = true;
                    std::task::Poll::Ready(if stalled.load(Ordering::Relaxed) {
                        Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "target did not accept data for {:?}",
                                send_timeout.unwrap_or_default()
                            ),
                        )))
                    } else {
                        None
                    })
                }
                other => other,
            }
        });
        readers.push(Box::pin(tokio_util::io::StreamReader::new(stream)));
    }

    let driver = tokio::spawn(async move {
        let mut buf = bytes::BytesMut::with_capacity(chunk_size);
        loop {
            buf.reserve(chunk_size);
            let n = match tokio::io::AsyncReadExt::read_buf(&mut body, &mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    // io::Error is not Clone: rebuild it for every reader.
                    for (tx, _) in &senders {
                        let _ = tx
                            .send(Err(std::io::Error::new(e.kind(), e.to_string())))
                            .await;
                    }
                    return Err(e);
                }
            };
            if n == 0 {
                return Ok(()); // EOF: dropping the senders closes every reader
            }
            let chunk = buf.split().freeze();
            let mut alive = Vec::with_capacity(senders.len());
            for (tx, stalled) in senders.drain(..) {
                let sent = match send_timeout {
                    // A target that will not take a chunk within the timeout is
                    // dropped, so it cannot hold up the others.
                    Some(t) => match tx.send_timeout(Ok(chunk.clone()), t).await {
                        Ok(()) => true,
                        Err(mpsc::error::SendTimeoutError::Timeout(_)) => {
                            tracing::warn!("tee: dropping a target that stalled for {t:?}");
                            stalled.store(true, Ordering::Relaxed);
                            false
                        }
                        Err(mpsc::error::SendTimeoutError::Closed(_)) => false,
                    },
                    // A closed receiver means that target gave up; drop it, keep the rest.
                    None => tx.send(Ok(chunk.clone())).await.is_ok(),
                };
                if sent {
                    alive.push((tx, stalled));
                }
            }
            senders = alive;
            if senders.is_empty() {
                tracing::debug!("tee: all readers gone, stopping source read");
                return Ok(());
            }
        }
    });

    (readers, driver)
}

/// The complete payload held in memory, readable any number of times.
#[derive(Debug, Clone)]
pub struct MemoryCache(Bytes);

impl MemoryCache {
    /// Read the whole stream into memory, failing (without touching the disk)
    /// if it exceeds `limit` bytes.
    pub async fn from_stream(body: ByteStream, limit: u64) -> Result<Self> {
        let data = read_to_vec(body, limit).await?;
        Ok(MemoryCache(Bytes::from(data)))
    }

    pub fn from_bytes(data: impl Into<Bytes>) -> Self {
        MemoryCache(data.into())
    }

    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn bytes(&self) -> &Bytes {
        &self.0
    }

    /// A fresh reader over the cached bytes (cheap: shares the buffer).
    pub fn reader(&self) -> ByteStream {
        Box::pin(std::io::Cursor::new(self.0.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[tokio::test]
    async fn tee_delivers_identical_bytes_to_all_readers() {
        let data = payload(1_000_003);
        let (readers, driver) = tee(
            boxed(std::io::Cursor::new(data.clone())),
            3,
            TeeOptions {
                chunk_size: 4096,
                capacity: 2,
                ..Default::default()
            },
        );
        let mut tasks = Vec::new();
        for mut r in readers {
            tasks.push(async move {
                let mut v = Vec::new();
                r.read_to_end(&mut v).await.unwrap();
                v
            });
        }
        let results = futures::future::join_all(tasks).await;
        driver.await.unwrap().unwrap();
        for v in results {
            assert!(v == data);
        }
    }

    #[tokio::test]
    async fn tee_drops_a_reader_that_stops_accepting_data() {
        let data = payload(300_000);
        let (mut readers, driver) = tee(
            boxed(std::io::Cursor::new(data.clone())),
            2,
            TeeOptions {
                chunk_size: 1024,
                capacity: 1,
                send_timeout: Some(std::time::Duration::from_millis(150)),
            },
        );
        let mut stalled = readers.pop().unwrap();
        let mut healthy = readers.pop().unwrap();

        // The healthy reader finishes even though the other never reads a byte.
        let mut got = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            healthy.read_to_end(&mut got),
        )
        .await
        .expect("a stalled target must not block the others")
        .unwrap();
        assert!(got == data);
        driver.await.unwrap().unwrap();

        // The stalled reader is told that it was dropped, rather than seeing a
        // short but seemingly complete stream.
        let mut rest = Vec::new();
        let err = stalled.read_to_end(&mut rest).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert!(rest.len() < data.len());
    }

    #[tokio::test]
    async fn tee_survives_dropped_reader_and_slow_reader() {
        let data = payload(300_000);
        let (mut readers, driver) = tee(
            boxed(std::io::Cursor::new(data.clone())),
            3,
            TeeOptions {
                chunk_size: 1024,
                capacity: 1,
                ..Default::default()
            },
        );
        let slow = readers.pop().unwrap();
        let fast = readers.pop().unwrap();
        let dropped = readers.pop().unwrap();
        drop(dropped);

        let fast_task = async move {
            let mut r = fast;
            let mut v = Vec::new();
            r.read_to_end(&mut v).await.unwrap();
            v
        };
        let slow_task = async move {
            let mut r = slow;
            let mut v = Vec::new();
            let mut buf = [0u8; 700];
            loop {
                let n = r.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                v.extend_from_slice(&buf[..n]);
                tokio::time::sleep(std::time::Duration::from_micros(50)).await;
            }
            v
        };
        let (a, b) = tokio::join!(fast_task, slow_task);
        driver.await.unwrap().unwrap();
        assert!(a == data);
        assert!(b == data);
    }

    #[tokio::test]
    async fn tee_propagates_source_error() {
        struct Failing(usize);
        impl AsyncRead for Failing {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.0 == 0 {
                    return std::task::Poll::Ready(Err(std::io::Error::other("boom")));
                }
                self.0 -= 1;
                buf.put_slice(&[1u8; 100]);
                std::task::Poll::Ready(Ok(()))
            }
        }
        let (readers, driver) = tee(boxed(Failing(3)), 2, TeeOptions::default());
        for mut r in readers {
            let mut v = Vec::new();
            let err = r.read_to_end(&mut v).await.unwrap_err();
            assert_eq!(v.len(), 300);
            assert!(err.to_string().contains("boom"));
        }
        assert!(driver.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn memory_cache_limit_and_replay() {
        let data = payload(10_000);
        let err = MemoryCache::from_stream(boxed(std::io::Cursor::new(data.clone())), 9_999)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds"));

        let cache = MemoryCache::from_stream(boxed(std::io::Cursor::new(data.clone())), 10_000)
            .await
            .unwrap();
        assert_eq!(cache.len(), 10_000);
        for _ in 0..3 {
            let mut v = Vec::new();
            cache.reader().read_to_end(&mut v).await.unwrap();
            assert!(v == data);
        }
    }
}

// ---------------------------------------------------------------------------
// Inactivity timeout for async streams.
// ---------------------------------------------------------------------------

/// Wraps a reader/writer and fails with `TimedOut` when no progress happens
/// for `timeout` (each successful read or write resets the clock).
pub struct Idle<S> {
    inner: S,
    timeout: std::time::Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<S> Idle<S> {
    pub fn new(inner: S, timeout: std::time::Duration) -> Self {
        Idle {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    /// `None` means no inactivity limit (a deadline far in the future).
    pub fn maybe(inner: S, timeout: Option<std::time::Duration>) -> Self {
        Idle::new(
            inner,
            timeout.unwrap_or(std::time::Duration::from_secs(365 * 24 * 3600)),
        )
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    fn reset(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout;
        self.sleep.as_mut().reset(deadline);
    }

    fn check_deadline(&mut self, cx: &mut std::task::Context<'_>) -> std::io::Result<()> {
        use std::future::Future;
        if self.sleep.as_mut().poll(cx).is_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no data for {:?} (inactivity timeout)", self.timeout),
            ));
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Idle<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            std::task::Poll::Pending => {
                self.check_deadline(cx)?;
                std::task::Poll::Pending
            }
            ready => {
                self.reset();
                ready
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Idle<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            std::task::Poll::Pending => {
                self.check_deadline(cx)?;
                std::task::Poll::Pending
            }
            ready => {
                self.reset();
                ready
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            std::task::Poll::Pending => {
                self.check_deadline(cx)?;
                std::task::Poll::Pending
            }
            ready => ready,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            std::task::Poll::Pending => {
                self.check_deadline(cx)?;
                std::task::Poll::Pending
            }
            ready => ready,
        }
    }
}

#[cfg(test)]
mod idle_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn idle_reader_times_out_when_stalled() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut r = Idle::new(rx, std::time::Duration::from_millis(100));
        tokio::io::AsyncWriteExt::write_all(&mut tx, b"abc")
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(r.read(&mut buf).await.unwrap(), 3);
        // Nothing more is written; the read must fail with TimedOut instead of hanging.
        let err = r.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
