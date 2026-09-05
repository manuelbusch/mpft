//! `scp://` — the classic SCP protocol spoken over an SSH exec channel.
//!
//! No maintained Rust crate implements SCP on top of russh, so the (small)
//! protocol is implemented here:
//!
//! * upload:   `scp -t <target>` — we act as the source: wait for ACK, send
//!   `C<mode> <size> <name>\n`, wait for ACK, send bytes, send `\0`, wait for ACK.
//! * download: `scp -f <path>` — we act as the sink: send `\0`, read the
//!   `C...` header, send `\0`, read exactly `size` bytes, send `\0`.
//!
//! ACK bytes: `\0` ok, `\x01` warning + text line, `\x02` fatal + text line.

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use russh::ChannelStream;
use russh::client::{Handle, Msg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use super::{ClientHandler, SshConfig, shell_quote, ssh_err};
use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, SendMeta, Sender, stream,
};

pub struct ScpEndpoint {
    loc: Location,
    cfg: SshConfig,
}

impl ScpEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        let cfg = SshConfig::from_location(&loc)?;
        Ok(ScpEndpoint { loc, cfg })
    }

    async fn exec(&self, command: &str) -> Result<(Handle<ClientHandler>, ChannelStream<Msg>)> {
        let handle = self.cfg.connect().await?;
        let channel = handle.channel_open_session().await.map_err(ssh_err)?;
        debug!(%command, "scp exec");
        channel.exec(false, command).await.map_err(ssh_err)?;
        Ok((handle, channel.into_stream()))
    }

    fn remote_path(&self) -> String {
        let p = self.loc.path();
        p.strip_prefix("/~/")
            .map(String::from)
            .unwrap_or_else(|| p.to_string())
    }
}

impl Endpoint for ScpEndpoint {
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

/// Read one ACK byte; `\x01`/`\x02` are followed by a message line.
async fn read_ack<S: AsyncRead + Unpin>(s: &mut S) -> Result<()> {
    let mut b = [0u8; 1];
    let n = s.read(&mut b).await?;
    if n == 0 {
        return Err(Error::Remote(
            "scp: connection closed by remote (is scp installed on the server?)".into(),
        ));
    }
    match b[0] {
        0 => Ok(()),
        code @ (1 | 2) => {
            let msg = read_line(s).await?;
            let msg = msg.trim().to_string();
            if code == 1 {
                Err(Error::Remote(format!("scp: {msg}")))
            } else {
                Err(Error::Remote(format!("scp fatal: {msg}")))
            }
        }
        other => Err(Error::Remote(format!(
            "scp: unexpected response byte {other:#x}"
        ))),
    }
}

async fn read_line<S: AsyncRead + Unpin>(s: &mut S) -> Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).await?;
        if n == 0 || b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 4096 {
            return Err(Error::Remote("scp: header line too long".into()));
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

#[async_trait]
impl Receiver for ScpEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        let (handle, mut stream) = self
            .exec(&format!("scp -f {}", shell_quote(&self.remote_path())))
            .await?;
        // We are the sink: kick off with an ACK, then parse the header.
        stream.write_all(b"\0").await?;
        let size = loop {
            let mut kind = [0u8; 1];
            if stream.read(&mut kind).await? == 0 {
                return Err(Error::Remote(
                    "scp: no response from remote (file not found or scp missing?)".into(),
                ));
            }
            match kind[0] {
                b'C' => {
                    let hdr = read_line(&mut stream).await?;
                    // "<mode> <size> <name>"
                    let mut it = hdr.split_whitespace();
                    let _mode = it.next();
                    let size: u64 = it
                        .next()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| Error::Remote(format!("scp: bad header 'C{hdr}'")))?;
                    break size;
                }
                b'T' => {
                    // timestamps (only with -p); acknowledge and continue
                    let _ = read_line(&mut stream).await?;
                    stream.write_all(b"\0").await?;
                }
                b'D' => return Err(Error::Remote("scp: remote path is a directory".into())),
                1 | 2 => {
                    let msg = read_line(&mut stream).await?;
                    return Err(Error::Remote(format!("scp: {}", msg.trim())));
                }
                other => {
                    return Err(Error::Remote(format!(
                        "scp: unexpected header byte {other:#x}"
                    )));
                }
            }
        };
        stream.write_all(b"\0").await?;
        debug!(size, "scp download");
        Ok(stream::boxed(ScpReader {
            stream,
            remaining: size,
            acked: false,
            _handle: handle,
        }))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        Err(Error::UnsupportedOperation {
            scheme: "scp".into(),
            op: "list (use sftp:// instead)",
        })
    }
}

/// Reads exactly the announced number of bytes, then sends the final ACK.
struct ScpReader {
    stream: ChannelStream<Msg>,
    remaining: u64,
    acked: bool,
    _handle: Handle<ClientHandler>,
}

impl AsyncRead for ScpReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.remaining == 0 {
            if !self.acked {
                // Best effort: confirm receipt so the remote scp exits cleanly.
                self.acked = true;
                let _ = Pin::new(&mut self.stream).poll_write(cx, b"\0");
            }
            return Poll::Ready(Ok(()));
        }
        let want = (buf.remaining() as u64).min(self.remaining) as usize;
        let mut limited = buf.take(want);
        match Pin::new(&mut self.stream).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let n = limited.filled().len();
                // SAFETY: `limited` only exposes bytes it has initialised; `n` of them are filled.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("scp: stream ended with {} bytes missing", self.remaining),
                    )));
                }
                self.remaining -= n as u64;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[async_trait]
impl Sender for ScpEndpoint {
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let name = meta.filename_or("payload").to_string();
        // SCP needs the size up front.
        let (mut reader, size): (ByteStream, u64) = match meta.size {
            Some(n) => (body, n),
            None => {
                let (file, n) = stream::spool_to_tempfile(body).await?;
                (stream::boxed(file), n)
            }
        };

        let target = self.remote_path();
        let cmd = if self.loc.is_dir_target() {
            format!("scp -t -d {}", shell_quote(target.trim_end_matches('/')))
        } else {
            format!("scp -t {}", shell_quote(&target))
        };
        let (handle, mut stream) = self.exec(&cmd).await?;

        read_ack(&mut stream).await?;
        let header = format!("C0644 {size} {}\n", name.replace(['\n', '/'], "_"));
        stream.write_all(header.as_bytes()).await?;
        read_ack(&mut stream).await?;
        debug!(size, %target, "scp upload");
        let copied = tokio::io::copy(&mut reader, &mut stream).await?;
        if copied != size {
            return Err(Error::Io(std::io::Error::other(format!(
                "scp: announced {size} bytes but source yielded {copied}"
            ))));
        }
        stream.write_all(b"\0").await?;
        stream.flush().await?;
        read_ack(&mut stream).await?;
        stream.shutdown().await?;
        super::disconnect(&handle).await;
        Ok(())
    }
}
