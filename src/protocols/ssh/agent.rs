//! Connecting to the ssh-agent, which is a different thing on every platform.
//!
//! * Unix: the socket in `$SSH_AUTH_SOCK`.
//! * Windows: the named pipe of the Windows OpenSSH agent
//!   (`\\.\pipe\openssh-ssh-agent`, or whatever `$SSH_AUTH_SOCK` names, since
//!   Git for Windows sets it to a pipe path), then PuTTY's Pageant.
//!
//! Everything else in the crate goes through [`connect`] and [`Stream`], so no
//! call site needs a `cfg`.

use russh::keys::agent::client::AgentClient;

use crate::{Error, Result};

#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;

/// Whether an agent is worth trying at all, so the authentication chain can
/// skip it without opening anything.
#[cfg(unix)]
pub fn available() -> bool {
    std::env::var_os("SSH_AUTH_SOCK").is_some()
}

#[cfg(unix)]
pub async fn connect() -> Result<AgentClient<Stream>> {
    AgentClient::connect_env()
        .await
        .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))
}

#[cfg(windows)]
pub use windows::{Stream, available, connect};

#[cfg(windows)]
mod windows {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use russh::keys::agent::client::AgentClient;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::windows::named_pipe::NamedPipeClient;
    use tracing::debug;

    use crate::{Error, Result};

    /// The default pipe of the Windows OpenSSH agent service.
    const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

    /// Either kind of agent connection, so callers keep one type.
    pub enum Stream {
        Pipe(NamedPipeClient),
        Pageant(pageant::PageantStream),
    }

    impl AsyncRead for Stream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.get_mut() {
                Stream::Pipe(s) => Pin::new(s).poll_read(cx, buf),
                Stream::Pageant(s) => Pin::new(s).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match self.get_mut() {
                Stream::Pipe(s) => Pin::new(s).poll_write(cx, buf),
                Stream::Pageant(s) => Pin::new(s).poll_write(cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            match self.get_mut() {
                Stream::Pipe(s) => Pin::new(s).poll_flush(cx),
                Stream::Pageant(s) => Pin::new(s).poll_flush(cx),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            match self.get_mut() {
                Stream::Pipe(s) => Pin::new(s).poll_shutdown(cx),
                Stream::Pageant(s) => Pin::new(s).poll_shutdown(cx),
            }
        }
    }

    /// An agent may always be there: the service pipe needs no environment
    /// variable, and Pageant none either.
    pub fn available() -> bool {
        true
    }

    pub async fn connect() -> Result<AgentClient<Stream>> {
        // $SSH_AUTH_SOCK first: Git for Windows and some tools point it at
        // their own pipe.
        let named = std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| OPENSSH_PIPE.to_string());
        let mut why = Vec::new();
        match open_pipe(&named).await {
            Ok(pipe) => {
                debug!(pipe = %named, "ssh-agent: named pipe");
                return Ok(AgentClient::connect(Stream::Pipe(pipe)));
            }
            Err(e) => why.push(format!("{named}: {e}")),
        }
        match pageant::PageantStream::new().await {
            Ok(stream) => {
                debug!("ssh-agent: pageant");
                Ok(AgentClient::connect(Stream::Pageant(stream)))
            }
            Err(e) => {
                why.push(format!("pageant: {e}"));
                Err(Error::Auth(format!("ssh-agent: {}", why.join("; "))))
            }
        }
    }

    /// Open the pipe, waiting out the moment when the agent is serving
    /// someone else (ERROR_PIPE_BUSY), as every named-pipe client must.
    async fn open_pipe(path: &str) -> std::io::Result<NamedPipeClient> {
        const ERROR_PIPE_BUSY: i32 = 231;
        for _ in 0..20 {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                Ok(client) => return Ok(client),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("{path} stayed busy"),
        ))
    }
}
