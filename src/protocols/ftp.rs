//! `ftp://` and `ftps://` (explicit AUTH TLS by default, `?tls=implicit` for
//! port-990 style implicit TLS) via suppaftp.

use async_trait::async_trait;
use secrecy::ExposeSecret;
use suppaftp::list::{File as FtpFile, ListParser};
use suppaftp::tokio::{
    AsyncRustlsConnector, AsyncRustlsFtpStream, AsyncRustlsStream, TransferStream,
};
use suppaftp::types::{FileType, Mode};
use suppaftp::{FtpError, Status};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tracing::{debug, warn};

use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, Scheme, SendMeta, Sender,
    stream,
};

type Ftp = AsyncRustlsFtpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsMode {
    Plain,
    Explicit,
    Implicit,
}

pub struct FtpEndpoint {
    loc: Location,
    tls: TlsMode,
    insecure: bool,
    passive: bool,
    nat_workaround: bool,
    /// Deadline for connecting and logging in, and for saying goodbye:
    /// `?timeout=`, or 30 s where that is 0.
    timeout: std::time::Duration,
    /// Inactivity limit for the data connection and for the replies on the
    /// control channel; `None` (`?timeout=0`) disables it.
    idle: Option<std::time::Duration>,
    /// How many logins this endpoint has attempted, so a password broker
    /// can tell the reconnects apart.
    logins: std::sync::atomic::AtomicU32,
}

impl FtpEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        loc.host_required()?;
        let tls = match loc.scheme() {
            Scheme::Ftp => TlsMode::Plain,
            _ => match loc.opt("tls").map(|s| s.to_ascii_lowercase()).as_deref() {
                None | Some("explicit") | Some("auth") => TlsMode::Explicit,
                Some("implicit") => TlsMode::Implicit,
                Some(other) => {
                    return Err(Error::invalid_option(
                        "tls",
                        format!("expected explicit|implicit, got '{other}'"),
                    ));
                }
            },
        };
        let timeout = loc.timeout_or(std::time::Duration::from_secs(30))?;
        Ok(FtpEndpoint {
            timeout,
            idle: loc.timeout()?,
            insecure: loc.opt_bool("insecure")?.unwrap_or(false),
            passive: loc.opt_bool("passive")?.unwrap_or(true),
            nat_workaround: loc.opt_bool("nat")?.unwrap_or(false),
            loc,
            tls,
            logins: std::sync::atomic::AtomicU32::new(0),
        })
    }

    fn port(&self) -> u16 {
        match (self.loc.port(), self.tls) {
            (Some(p), _) => p,
            (None, TlsMode::Implicit) => 990,
            (None, _) => 21,
        }
    }

    /// Connect, negotiate TLS and log in, bounded by the `timeout` option
    /// (default 30 s) so that a stalled handshake fails instead of hanging,
    /// and retried as often as `connect_retries` allows.
    async fn connect(&self) -> Result<Ftp> {
        crate::protocols::with_connect_retries(self.loc.connect_retries()?, "ftp connect", || {
            self.connect_once()
        })
        .await
    }

    async fn connect_once(&self) -> Result<Ftp> {
        let host = self.loc.host_required()?;
        tokio::time::timeout(self.timeout, self.connect_inner(host))
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "ftp: connecting to {}:{} timed out after {:?}",
                        crate::location::bracket_host(host),
                        self.port(),
                        self.timeout
                    ),
                ))
            })?
    }

    async fn connect_inner(&self, host: &str) -> Result<Ftp> {
        let addr = (host, self.port());
        debug!(host, port = self.port(), tls = ?self.tls, "ftp connect");
        let mut ftp = match self.tls {
            TlsMode::Plain => Ftp::connect(addr).await.map_err(ftp_err)?,
            TlsMode::Explicit => {
                let connector = self.connector()?;
                Ftp::connect(addr)
                    .await
                    .map_err(ftp_err)?
                    .into_secure(connector, host)
                    .await
                    .map_err(ftp_err)?
            }
            TlsMode::Implicit => {
                let connector = self.connector()?;
                Ftp::connect_secure_implicit(addr, connector, host)
                    .await
                    .map_err(ftp_err)?
            }
        };
        let user = self.loc.username().unwrap_or("anonymous");
        // Fetched for this login only and dropped with it: behind a relay
        // the password comes from the client every time.
        let attempt = self
            .logins
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let pass = self.loc.login_password(attempt).await?;
        let pass = pass
            .as_ref()
            .map(|p| p.expose_secret())
            .unwrap_or("anonymous@");
        ftp.login(user, pass).await.map_err(|e| match e {
            FtpError::UnexpectedResponse(r) if r.status == Status::NotLoggedIn => {
                Error::Auth(format!("ftp login failed for '{user}'"))
            }
            other => ftp_err(other),
        })?;
        ftp.transfer_type(FileType::Binary).await.map_err(ftp_err)?;
        ftp.set_mode(if self.passive {
            Mode::Passive
        } else {
            Mode::Active
        });
        ftp.set_passive_nat_workaround(self.nat_workaround);
        Ok(ftp)
    }

    /// Bound a control-channel command by the endpoint timeout so a server
    /// that stops answering yields an error instead of a hang.
    async fn ctl<T, F>(&self, what: &str, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = std::result::Result<T, FtpError>>,
    {
        ctl_timeout(self.idle, what, fut).await
    }

    /// Log out, but never wait longer than the connect deadline for it: the
    /// work is done, and a server that does not answer QUIT changes nothing.
    async fn quit(&self, mut ftp: Ftp) {
        quit_within(self.timeout, &mut ftp).await;
    }

    fn connector(&self) -> Result<AsyncRustlsConnector> {
        let cfg = crate::tls::client_config(self.insecure)?;
        Ok(AsyncRustlsConnector::from(
            tokio_rustls::TlsConnector::from(cfg),
        ))
    }

    fn remote_path(&self) -> &str {
        self.loc.path()
    }
}

async fn ctl_timeout<T, F>(timeout: Option<std::time::Duration>, what: &str, fut: F) -> Result<T>
where
    F: std::future::Future<Output = std::result::Result<T, FtpError>>,
{
    let Some(timeout) = timeout else {
        return fut.await.map_err(ftp_err);
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r.map_err(ftp_err),
        Err(_) => Err(Error::Remote(format!(
            "ftp: no reply to {what} within {timeout:?}"
        ))),
    }
}

async fn quit_within(deadline: std::time::Duration, ftp: &mut Ftp) {
    match tokio::time::timeout(deadline, ftp.quit()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!("ftp QUIT: {e}"),
        Err(_) => debug!("ftp QUIT: no reply within {deadline:?}"),
    }
}

fn ftp_err(e: FtpError) -> Error {
    match e {
        FtpError::UnexpectedResponse(r) => Error::Remote(format!(
            "ftp: {} {}",
            r.status.code(),
            String::from_utf8_lossy(&r.body).trim()
        )),
        other => Error::transport("ftp", other),
    }
}

/// Whether the server refused a command with a permanent (5xx) reply. For
/// SIZE that means "no such file", "not a plain file" or "not supported",
/// which one being up to the server: in each case the size is unknown.
fn refused_for_good(e: &Error) -> bool {
    matches!(e, Error::Remote(m) if m.starts_with("ftp: 5"))
}

/// RNFR/RNTO and DELE on one control connection.
struct FtpRenamer<'a> {
    ep: &'a FtpEndpoint,
    ftp: &'a mut Ftp,
}

#[async_trait]
impl crate::protocols::Renamer for FtpRenamer<'_> {
    async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        self.ep.ctl("RNFR/RNTO", self.ftp.rename(from, to)).await
    }

    async fn remove(&mut self, path: &str) -> Result<()> {
        self.ep.ctl("DELE", self.ftp.rm(path)).await
    }
}

impl Endpoint for FtpEndpoint {
    fn location(&self) -> &Location {
        &self.loc
    }
    fn as_receiver(&self) -> Option<&dyn Receiver> {
        Some(self)
    }
    fn as_sender(&self) -> Option<&dyn Sender> {
        Some(self)
    }
}

/// Download stream. At EOF it completes the transfer (`finish`: waits for the
/// server's 226/250 reply) and checks the byte count against `SIZE`, so a
/// truncated transfer surfaces as an error instead of a short file.
struct FtpReader {
    stream: Option<stream::Idle<TransferStream<AsyncRustlsStream>>>,
    ftp: Option<Ftp>,
    /// For the reply that completes the transfer; `None` waits for it.
    idle: Option<std::time::Duration>,
    /// For QUIT.
    timeout: std::time::Duration,
    expected: Option<u64>,
    received: u64,
    finishing:
        Option<std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>>,
    done: bool,
}

impl FtpReader {
    fn start_finish(&mut self) {
        let stream = self.stream.take();
        let mut ftp = self.ftp.take();
        let expected = self.expected;
        let received = self.received;
        let (idle, timeout) = (self.idle, self.timeout);
        self.finishing = Some(Box::pin(async move {
            let result = match stream {
                Some(s) => ctl_timeout(idle, "transfer completion", s.into_inner().finish())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string())),
                None => Ok(()),
            };
            if let Some(mut ftp) = ftp.take() {
                quit_within(timeout, &mut ftp).await;
            }
            result?;
            if let Some(exp) = expected
                && exp != received
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("ftp: transfer truncated: received {received} of {exp} bytes"),
                ));
            }
            Ok(())
        }));
    }
}

impl Drop for FtpReader {
    fn drop(&mut self) {
        // Reader dropped before EOF (e.g. the target failed): close what is
        // left, in a task of its own since Drop cannot wait, and bounded, so
        // a server that does not answer cannot keep that task alive.
        if let (Some(stream), Some(mut ftp)) = (self.stream.take(), self.ftp.take()) {
            let Ok(rt) = tokio::runtime::Handle::try_current() else {
                debug!("ftp: an abandoned download is closed with its connection");
                return;
            };
            let timeout = self.timeout;
            rt.spawn(async move {
                let finish = stream.into_inner().finish();
                if let Err(e) = ctl_timeout(Some(timeout), "transfer completion", finish).await {
                    warn!("ftp: closing abandoned download: {e}");
                }
                quit_within(timeout, &mut ftp).await;
            });
        }
    }
}

impl AsyncRead for FtpReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if self.done {
            return Poll::Ready(Ok(()));
        }
        if let Some(fut) = self.finishing.as_mut() {
            return match fut.as_mut().poll(cx) {
                Poll::Ready(r) => {
                    self.done = true;
                    self.finishing = None;
                    Poll::Ready(r)
                }
                Poll::Pending => Poll::Pending,
            };
        }
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let before = buf.filled().len();
        match std::pin::Pin::new(stream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n == 0 {
                    self.start_finish();
                    return self.poll_read(cx, buf);
                }
                self.received += n as u64;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[async_trait]
impl Receiver for FtpEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        let mut ftp = self.connect().await?;
        let expected = self
            .ctl("SIZE", ftp.size(self.remote_path()))
            .await
            .ok()
            .map(|s| s as u64);
        let stream = self
            .ctl("RETR", ftp.retr_as_stream(self.remote_path()))
            .await?;
        Ok(stream::boxed(FtpReader {
            stream: Some(stream::Idle::maybe(stream, self.idle)),
            ftp: Some(ftp),
            idle: self.idle,
            timeout: self.timeout,
            expected,
            received: 0,
            finishing: None,
            done: false,
        }))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        let mut ftp = self.connect().await?;
        let path = self.remote_path();
        let path_arg = if path.is_empty() || path == "/" {
            None
        } else {
            Some(path)
        };

        let files: Vec<FtpFile> = match self.ctl("MLSD", ftp.mlsd(path_arg)).await {
            Ok(lines) => lines
                .iter()
                .filter_map(|l| ListParser::parse_mlsd(l).ok())
                .collect(),
            Err(e) => {
                debug!("MLSD unavailable ({e}); falling back to LIST");
                let lines = self.ctl("LIST", ftp.list(path_arg)).await?;
                lines
                    .iter()
                    .filter_map(|l| {
                        ListParser::parse_posix(l)
                            .or_else(|_| ListParser::parse_dos(l))
                            .ok()
                    })
                    .collect()
            }
        };
        self.quit(ftp).await;

        let mut out: Vec<Entry> = files
            .into_iter()
            .filter(|f| f.name() != "." && f.name() != "..")
            .map(|f| Entry {
                name: f.name().to_string(),
                size: if f.is_directory() {
                    None
                } else {
                    Some(f.size() as u64)
                },
                is_dir: f.is_directory(),
                modified: Some(f.modified()),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn size(&self) -> Result<Option<u64>> {
        let mut ftp = self.connect().await?;
        let size = self.ctl("SIZE", ftp.size(self.remote_path())).await;
        self.quit(ftp).await;
        match size {
            Ok(n) => Ok(Some(n as u64)),
            Err(e) if refused_for_good(&e) => {
                debug!("ftp SIZE: size unknown ({e})");
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl Sender for FtpEndpoint {
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let mut ftp = self.connect().await?;
        let target = self.loc.target_path(meta.filename.as_deref())?;
        debug!(%target, "ftp upload");
        let up = self.ctl("STOR", ftp.put_with_stream(&target)).await?;
        let mut up = stream::Idle::maybe(up, self.idle);
        let written = stream::pipe(body, &mut up).await?;
        up.shutdown().await?;
        // Drain the server's TLS close_notify before the socket is closed. Closing
        // with unread data in the receive buffer makes the kernel send RST instead
        // of FIN, and a RST discards whatever the server has not yet read — the
        // upload would be silently truncated under load.
        let mut sink = [0u8; 1024];
        loop {
            match tokio::io::AsyncReadExt::read(&mut up, &mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        self.ctl("transfer completion", up.into_inner().finish())
            .await?;
        // Verify the server really stored everything (SIZE may be unsupported).
        if let Ok(remote) = self.ctl("SIZE", ftp.size(&target)).await
            && remote as u64 != written
        {
            self.quit(ftp).await;
            return Err(Error::Remote(format!(
                "ftp: upload incomplete: server stored {remote} of {written} bytes for {target}"
            )));
        }
        self.quit(ftp).await;
        Ok(())
    }

    /// Whether CWD into the path succeeds. A permanent refusal means it is
    /// no directory, or none this login may enter, which a file cannot be
    /// written into either.
    async fn is_dir(&self) -> Result<bool> {
        let mut ftp = self.connect().await?;
        let cwd = self.ctl("CWD", ftp.cwd(self.remote_path())).await;
        self.quit(ftp).await;
        match cwd {
            Ok(()) => Ok(true),
            Err(e) if refused_for_good(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn supports_rename(&self) -> bool {
        true
    }

    fn supports_append(&self) -> bool {
        true
    }

    async fn existing_size(&self, name: &str) -> Result<Option<u64>> {
        let mut ftp = self.connect().await?;
        let path = self.loc.sibling(name)?.path().to_string();
        let size = self.ctl("SIZE", ftp.size(&path)).await;
        self.quit(ftp).await;
        match size {
            Ok(n) => Ok(Some(n as u64)),
            // SIZE fails for a file that is not there, which is the answer.
            Err(e) if refused_for_good(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn append(&self, body: ByteStream, meta: &SendMeta, offset: u64) -> Result<()> {
        let mut ftp = self.connect().await?;
        let target = self.loc.target_path(meta.filename.as_deref())?;
        debug!(%target, offset, "ftp resume (APPE)");
        let up = self.ctl("APPE", ftp.append_with_stream(&target)).await?;
        let mut up = stream::Idle::maybe(up, self.idle);
        let written = stream::pipe(body, &mut up).await?;
        up.shutdown().await?;
        let mut sink = [0u8; 1024];
        loop {
            match tokio::io::AsyncReadExt::read(&mut up, &mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        self.ctl("transfer completion", up.into_inner().finish())
            .await?;
        if let Ok(remote) = self.ctl("SIZE", ftp.size(&target)).await
            && remote as u64 != offset + written
        {
            self.quit(ftp).await;
            return Err(Error::Remote(format!(
                "ftp: resume incomplete: server holds {remote} of {} bytes for {target}",
                offset + written
            )));
        }
        self.quit(ftp).await;
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = self.loc.sibling(from)?.path().to_string();
        let to = self.loc.sibling(to)?.path().to_string();
        let mut ftp = self.connect().await?;
        // RNTO fails on most servers when the target exists. The old file is
        // moved aside rather than deleted, so a failed rename loses nothing.
        let res = crate::protocols::replace_aside(
            &mut FtpRenamer {
                ep: self,
                ftp: &mut ftp,
            },
            &from,
            &to,
        )
        .await;
        self.quit(ftp).await;
        res
    }

    fn supports_remove(&self) -> bool {
        true
    }

    async fn remove(&self, name: &str) -> Result<()> {
        let path = self.loc.sibling(name)?.path().to_string();
        let mut ftp = self.connect().await?;
        let res = self.ctl("DELE", ftp.rm(path.as_str())).await;
        self.quit(ftp).await;
        res
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    async fn mkdir_all(&self) -> Result<()> {
        let dir = self.loc.parent()?.path().to_string();
        let mut ftp = self.connect().await?;
        // MKD one component at a time; a failure usually means it is there
        // already, which CWD at the end settles either way.
        let mut path = String::new();
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            path.push('/');
            path.push_str(part);
            let _ = self.ctl("MKD", ftp.mkdir(path.as_str())).await;
        }
        let res = self
            .ctl("CWD", ftp.cwd(dir.as_str()))
            .await
            .map_err(|e| Error::Remote(format!("ftp: cannot create {dir}: {e}")));
        self.quit(ftp).await;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timeout_zero_leaves_only_the_connect_deadline() {
        let ep = FtpEndpoint::new(Location::parse("ftp://h/x?timeout=0").unwrap()).unwrap();
        assert_eq!(ep.idle, None);
        assert_eq!(ep.timeout, Duration::from_secs(30));
        let ep = FtpEndpoint::new(Location::parse("ftp://h/x?timeout=5").unwrap()).unwrap();
        assert_eq!(ep.idle, Some(Duration::from_secs(5)));
        assert_eq!(ep.timeout, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_reply_is_waited_for_as_long_as_the_timeout_says() {
        let slow = || async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok::<_, FtpError>(7)
        };
        assert_eq!(ctl_timeout(None, "SIZE", slow()).await.unwrap(), 7);
        let err = ctl_timeout(Some(Duration::from_secs(30)), "SIZE", slow())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no reply to SIZE"), "{err}");
        assert!(err.is_transient());
    }
}
