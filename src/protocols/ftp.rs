//! `ftp://` and `ftps://` (explicit AUTH TLS by default, `?tls=implicit` for
//! port-990 style implicit TLS) via suppaftp.

use async_trait::async_trait;
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
        Ok(FtpEndpoint {
            insecure: loc.opt_bool("insecure")?.unwrap_or(false),
            passive: loc.opt_bool("passive")?.unwrap_or(true),
            nat_workaround: loc.opt_bool("nat")?.unwrap_or(false),
            loc,
            tls,
        })
    }

    fn port(&self) -> u16 {
        match (self.loc.port(), self.tls) {
            (Some(p), _) => p,
            (None, TlsMode::Implicit) => 990,
            (None, _) => 21,
        }
    }

    async fn connect(&self) -> Result<Ftp> {
        let host = self.loc.host_required()?;
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
        let pass = self.loc.password().unwrap_or("anonymous@");
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

/// Download stream that completes the transfer (`finish` + `QUIT`) when dropped.
struct FtpReader {
    stream: Option<TransferStream<AsyncRustlsStream>>,
    ftp: Option<Ftp>,
}

impl Drop for FtpReader {
    fn drop(&mut self) {
        if let (Some(stream), Some(mut ftp)) = (self.stream.take(), self.ftp.take()) {
            tokio::spawn(async move {
                if let Err(e) = stream.finish().await {
                    warn!("ftp: finishing download: {e}");
                }
                let _ = ftp.quit().await;
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
        match self.stream.as_mut() {
            Some(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

#[async_trait]
impl Receiver for FtpEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        let mut ftp = self.connect().await?;
        let stream = ftp
            .retr_as_stream(self.remote_path())
            .await
            .map_err(ftp_err)?;
        Ok(stream::boxed(FtpReader {
            stream: Some(stream),
            ftp: Some(ftp),
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

        let files: Vec<FtpFile> = match ftp.mlsd(path_arg).await {
            Ok(lines) => lines
                .iter()
                .filter_map(|l| ListParser::parse_mlsd(l).ok())
                .collect(),
            Err(e) => {
                debug!("MLSD unavailable ({e}); falling back to LIST");
                let lines = ftp.list(path_arg).await.map_err(ftp_err)?;
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
        let _ = ftp.quit().await;

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
        let size = ftp.size(self.remote_path()).await.ok().map(|s| s as u64);
        let _ = ftp.quit().await;
        Ok(size)
    }
}

#[async_trait]
impl Sender for FtpEndpoint {
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let mut ftp = self.connect().await?;
        let target = self.loc.target_path(meta.filename.as_deref());
        debug!(%target, "ftp upload");
        let mut up = ftp.put_with_stream(&target).await.map_err(ftp_err)?;
        let result = stream::pipe(body, &mut up).await;
        up.shutdown().await.ok();
        up.finish().await.map_err(ftp_err)?;
        result?;
        let _ = ftp.quit().await;
        Ok(())
    }
}
