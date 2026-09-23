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
use std::task::{Context, Poll, ready};

use async_trait::async_trait;
use russh::ChannelStream;
use russh::client::{Handle, Msg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

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

    /// Open an exec channel. The stream carries an inactivity deadline, so a
    /// server that stops talking mid-transfer fails instead of hanging.
    async fn exec(&self, command: &str) -> Result<(Handle<ClientHandler>, ScpStream)> {
        let handle = self.cfg.connect().await?;
        let channel = handle.channel_open_session().await.map_err(ssh_err)?;
        debug!(%command, "scp exec");
        channel.exec(false, command).await.map_err(ssh_err)?;
        Ok((
            handle,
            stream::Idle::maybe(channel.into_stream(), self.cfg.idle),
        ))
    }

    fn remote_path(&self) -> String {
        let p = self.loc.path();
        p.strip_prefix("/~/")
            .map(String::from)
            .unwrap_or_else(|| p.to_string())
    }

    /// Remote path of a file called `name` next to this location.
    fn sibling_path(&self, name: &str) -> Result<String> {
        let p = self.loc.sibling(name)?;
        Ok(p.path()
            .strip_prefix("/~/")
            .map(String::from)
            .unwrap_or_else(|| p.path().to_string()))
    }

    /// Run a command on the server and turn a non-zero exit status into an
    /// error, with whatever the command wrote as the message.
    async fn run(&self, command: &str) -> Result<()> {
        let handle = self.cfg.connect().await?;
        let mut channel = handle.channel_open_session().await.map_err(ssh_err)?;
        debug!(%command, "ssh exec");
        channel.exec(true, command).await.map_err(ssh_err)?;
        let mut ended = Ended::Unknown;
        let mut output = Vec::new();
        let collect = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data }
                    | russh::ChannelMsg::ExtendedData { data, .. } => {
                        output.extend_from_slice(&data)
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        ended = Ended::Status(exit_status)
                    }
                    russh::ChannelMsg::ExitSignal { signal_name, .. } => {
                        ended = Ended::Signal(format!("{signal_name:?}"))
                    }
                    _ => {}
                }
            }
        };
        let timed_out = tokio::time::timeout(self.cfg.timeout, collect)
            .await
            .is_err();
        super::disconnect(&handle).await;
        if timed_out {
            return Err(Error::Remote(format!(
                "ssh: `{command}` did not finish within {:?}",
                self.cfg.timeout
            )));
        }
        judge(command, ended, &output)
    }
}

/// How a remote command ended, as far as the server said.
enum Ended {
    Status(u32),
    Signal(String),
    Unknown,
}

/// Only an exit status of 0 is success. A command killed by a signal, or
/// one whose end the server did not report, may have done nothing.
fn judge(command: &str, ended: Ended, output: &[u8]) -> Result<()> {
    let output = String::from_utf8_lossy(output);
    let output = output.trim();
    match ended {
        Ended::Status(0) => Ok(()),
        Ended::Status(code) => Err(Error::Remote(format!(
            "ssh: `{command}` failed (exit {code}) {output}"
        ))),
        Ended::Signal(sig) => Err(Error::Remote(format!(
            "ssh: `{command}` was killed by signal {sig} {output}"
        ))),
        Ended::Unknown => Err(Error::Remote(format!(
            "ssh: `{command}` ended without an exit status {output}"
        ))),
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

/// Parse the body of an SCP `C` header, i.e. everything after the leading
/// `C`: `<mode> <size> <name>`. Returns the announced size and the file name.
///
/// The name is what the *remote* proposes; callers that write a file must run
/// it through [`crate::location::safe_name`] first.
pub fn parse_c_header(line: &str) -> Result<(u64, String)> {
    let bad = || Error::Remote(format!("scp: bad header 'C{}'", line.trim_end()));
    let rest = line.trim_start();
    // The mode is octal and always four digits in practice, but only its
    // presence matters here.
    let (mode, rest) = rest.split_once(' ').ok_or_else(bad)?;
    if mode.is_empty() || !mode.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let rest = rest.trim_start();
    let (size, name) = rest.split_once(' ').ok_or_else(bad)?;
    let size: u64 = size.parse().map_err(|_| bad())?;
    let name = name.trim_end_matches(['\r', '\n']).to_string();
    if name.is_empty() {
        return Err(bad());
    }
    Ok((size, name))
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
                    break parse_c_header(&hdr)?.0;
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
        Ok(stream::boxed(stream::Guarded::new(
            ScpReader::new(stream, size),
            handle,
        )))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        Err(Error::UnsupportedOperation {
            scheme: "scp".into(),
            op: "list (use sftp:// instead)",
        })
    }
}

/// An SCP exec channel with an inactivity deadline.
type ScpStream = stream::Idle<ChannelStream<Msg>>;

/// Reads exactly the announced number of bytes, then the status byte the
/// remote sends after them, then sends the final ACK. Only then does it
/// report the end of the stream: a remote that fails after the data (a read
/// error on its side) fails the download.
struct ScpReader<S> {
    stream: S,
    remaining: u64,
    tail: Tail,
}

/// Where [`ScpReader`] is after the data.
enum Tail {
    Data,
    Status,
    /// A warning (1) or fatal error (2), and its message so far.
    Message(Vec<u8>),
    Ack,
    Flush,
    Done,
}

impl<S> ScpReader<S> {
    fn new(stream: S, size: u64) -> Self {
        ScpReader {
            stream,
            remaining: size,
            tail: Tail::Data,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ScpReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.tail {
                Tail::Data if this.remaining > 0 => {
                    let want = (buf.remaining() as u64).min(this.remaining) as usize;
                    let mut limited = buf.take(want);
                    ready!(Pin::new(&mut this.stream).poll_read(cx, &mut limited))?;
                    let n = limited.filled().len();
                    // SAFETY: `limited` only exposes bytes it has initialised; `n` of them are filled.
                    unsafe { buf.assume_init(n) };
                    buf.advance(n);
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            format!("scp: stream ended with {} bytes missing", this.remaining),
                        )));
                    }
                    this.remaining -= n as u64;
                    return Poll::Ready(Ok(()));
                }
                Tail::Data => this.tail = Tail::Status,
                Tail::Status => {
                    let mut b = [0u8; 1];
                    let mut one = ReadBuf::new(&mut b);
                    ready!(Pin::new(&mut this.stream).poll_read(cx, &mut one))?;
                    this.tail = match one.filled() {
                        [] => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "scp: stream ended before the remote confirmed the file",
                            )));
                        }
                        [0] => Tail::Ack,
                        [1 | 2] => Tail::Message(Vec::new()),
                        [other] => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("scp: unexpected status byte {other:#x} after the data"),
                            )));
                        }
                        _ => unreachable!("a one-byte buffer"),
                    };
                }
                Tail::Message(msg) => {
                    let mut b = [0u8; 1];
                    let mut one = ReadBuf::new(&mut b);
                    ready!(Pin::new(&mut this.stream).poll_read(cx, &mut one))?;
                    match one.filled() {
                        [b'\n'] | [] => {}
                        [c] if msg.len() < 4096 => {
                            msg.push(*c);
                            continue;
                        }
                        _ => {}
                    }
                    let msg = String::from_utf8_lossy(msg).trim().to_string();
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "scp: the remote failed after sending the data: {msg}"
                    ))));
                }
                Tail::Ack => {
                    // Confirm receipt so that the remote scp exits cleanly.
                    // The file is complete either way, so a failure to say so
                    // is not the download's.
                    match ready!(Pin::new(&mut this.stream).poll_write(cx, b"\0")) {
                        Ok(_) => this.tail = Tail::Flush,
                        Err(e) => {
                            debug!("scp: final ACK not sent: {e}");
                            this.tail = Tail::Done;
                        }
                    }
                }
                Tail::Flush => {
                    if let Err(e) = ready!(Pin::new(&mut this.stream).poll_flush(cx)) {
                        debug!("scp: final ACK not sent: {e}");
                    }
                    this.tail = Tail::Done;
                }
                Tail::Done => return Poll::Ready(Ok(())),
            }
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
                warn!(
                    "scp: source size unknown, spooling to a temporary file (use the memory cache to avoid disk I/O)"
                );
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
        let header = format!("C0644 {size} {}\n", crate::location::safe_name(&name)?);
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

    /// SCP itself cannot rename, but the SSH session it runs on can.
    fn supports_rename(&self) -> bool {
        true
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = self.sibling_path(from)?;
        let to = self.sibling_path(to)?;
        self.run(&format!(
            "mv -f {} {}",
            shell_quote(&from),
            shell_quote(&to)
        ))
        .await
    }

    fn supports_remove(&self) -> bool {
        true
    }

    async fn remove(&self, name: &str) -> Result<()> {
        let path = self.sibling_path(name)?;
        self.run(&format!("rm -f {}", shell_quote(&path))).await
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    async fn mkdir_all(&self) -> Result<()> {
        let dir = self.loc.parent()?;
        let path = dir
            .path()
            .strip_prefix("/~/")
            .unwrap_or(dir.path())
            .to_string();
        if path.is_empty() {
            return Ok(());
        }
        self.run(&format!("mkdir -p {}", shell_quote(&path))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What an `scp -f` sends after its header: `data`, then `tail`.
    async fn download(data: &[u8], tail: &[u8]) -> (std::io::Result<Vec<u8>>, Vec<u8>) {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut sent = data.to_vec();
        sent.extend_from_slice(tail);
        let remote = tokio::spawn(async move {
            theirs.write_all(&sent).await.unwrap();
            theirs.shutdown().await.unwrap();
            let mut acks = Vec::new();
            let _ = theirs.read_to_end(&mut acks).await;
            acks
        });
        let mut reader = ScpReader::new(ours, data.len() as u64);
        let mut got = Vec::new();
        let res = reader.read_to_end(&mut got).await.map(|_| got);
        drop(reader);
        (res, remote.await.unwrap())
    }

    #[test]
    fn only_exit_status_zero_is_success() {
        assert!(judge("mv a b", Ended::Status(0), b"").is_ok());
        let err = judge("mv a b", Ended::Status(1), b"no such file\n").unwrap_err();
        assert!(err.to_string().contains("exit 1) no such file"), "{err}");
        let err = judge("mv a b", Ended::Signal("KILL".into()), b"").unwrap_err();
        assert!(err.to_string().contains("signal KILL"), "{err}");
        assert!(judge("mv a b", Ended::Unknown, b"").is_err());
    }

    #[tokio::test]
    async fn a_download_ends_with_the_remote_status() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let (got, acks) = download(&data, b"\0").await;
        assert_eq!(got.unwrap(), data);
        assert_eq!(acks, b"\0", "the final ACK is sent");

        // The remote fails after the data: the download fails with it.
        let (got, acks) = download(&data, b"\x01scp: read error\n").await;
        let err = got.unwrap_err().to_string();
        assert!(err.contains("read error"), "{err}");
        assert!(acks.is_empty(), "nothing to acknowledge");

        // The stream ends without a status.
        assert!(download(&data, b"").await.0.is_err());
    }

    #[test]
    fn c_headers() {
        assert_eq!(
            parse_c_header("0644 1234 report.pdf").unwrap(),
            (1234, "report.pdf".to_string())
        );
        // Leading and repeated spaces are tolerated; names may contain spaces,
        // since only the first two fields are fixed.
        assert_eq!(parse_c_header("  0644  7 a.bin").unwrap().0, 7);
        assert_eq!(
            parse_c_header("0755 0 two words.txt\n").unwrap(),
            (0, "two words.txt".to_string())
        );
        for bad in [
            "",
            "0644",
            "0644 ",
            "0644 x name",
            "0644 12",
            "-644 12 name",
            "0644 99999999999999999999999 name",
            "0644 12 ",
        ] {
            assert!(parse_c_header(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
