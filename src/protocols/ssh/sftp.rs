//! `sftp://` via the SSH SFTP subsystem (russh-sftp).

use async_trait::async_trait;
use russh::client::Handle;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{OpenFlags, Packet, StatusCode};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tracing::debug;

use super::{ClientHandler, SshConfig, ssh_err};
use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, SendMeta, Sender, stream,
};

pub struct SftpEndpoint {
    loc: Location,
    cfg: SshConfig,
}

impl SftpEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        let cfg = SshConfig::from_location(&loc)?;
        Ok(SftpEndpoint { loc, cfg })
    }

    async fn session(&self) -> Result<(Handle<ClientHandler>, SftpSession)> {
        let handle = self.cfg.connect().await?;
        let channel = handle.channel_open_session().await.map_err(ssh_err)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(ssh_err)?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(sftp_err)?;
        Ok((handle, sftp))
    }

    /// Remote path; a leading `/~/` means "relative to the login directory".
    fn remote_path(&self) -> String {
        strip_home(self.loc.path())
    }
}

fn strip_home(p: &str) -> String {
    p.strip_prefix("/~/")
        .map(|rest| rest.to_string())
        .unwrap_or_else(|| p.to_string())
}

/// The server's status the way every protocol reports it: a missing file
/// as [`Error::not_found`], a refusal as a permission error, any other
/// answer as the server's word; only a session that broke off is transport
/// trouble worth another attempt.
fn sftp_err(e: russh_sftp::client::error::Error) -> Error {
    use russh_sftp::client::error::Error as E;
    match e {
        E::Status(s) => {
            // OpenSSH's message is the code's name again; others say more.
            let msg = match s.error_message.trim() {
                "" => format!("sftp: {}", s.status_code),
                m => format!("sftp: {m}"),
            };
            match s.status_code {
                StatusCode::NoSuchFile => Error::not_found(msg),
                StatusCode::PermissionDenied => Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    msg,
                )),
                StatusCode::NoConnection | StatusCode::ConnectionLost => {
                    Error::transport("sftp", E::Status(s))
                }
                _ => Error::Remote(msg),
            }
        }
        other => Error::transport("sftp", other),
    }
}

/// The OpenSSH extension that renames the way rename(2) does.
const POSIX_RENAME: &str = "posix-rename@openssh.com";

async fn posix_rename(raw: &RawSftpSession, from: &str, to: &str) -> Result<()> {
    // Two SSH strings: a 32-bit big-endian length, then the bytes.
    let mut data = Vec::with_capacity(8 + from.len() + to.len());
    for s in [from, to] {
        data.extend_from_slice(&(s.len() as u32).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
    }
    match raw.extended(POSIX_RENAME, data).await.map_err(sftp_err)? {
        Packet::Status(s) if s.status_code == StatusCode::Ok => Ok(()),
        Packet::Status(s) => Err(sftp_err(s.into())),
        _ => Err(Error::Remote(format!(
            "sftp: unexpected reply to {POSIX_RENAME}"
        ))),
    }
}

/// Plain SFTP rename and remove on one session.
struct SftpRenamer<'a>(&'a RawSftpSession);

#[async_trait]
impl crate::protocols::Renamer for SftpRenamer<'_> {
    async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        self.0.rename(from, to).await.map(|_| ()).map_err(sftp_err)
    }

    async fn remove(&mut self, path: &str) -> Result<()> {
        self.0.remove(path).await.map(|_| ()).map_err(sftp_err)
    }
}

impl Endpoint for SftpEndpoint {
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

#[async_trait]
impl Receiver for SftpEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        let (handle, sftp) = self.session().await?;
        let file = sftp.open(self.remote_path()).await.map_err(sftp_err)?;
        let file = stream::Idle::maybe(file, self.cfg.idle);
        Ok(stream::boxed(stream::Guarded::new(file, (sftp, handle))))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        let (handle, sftp) = self.session().await?;
        let path = self.remote_path();
        let path = if path.is_empty() {
            ".".to_string()
        } else {
            path
        };
        let rd = sftp.read_dir(path).await.map_err(sftp_err)?;
        let mut out: Vec<Entry> = rd
            .filter(|e| e.file_name() != "." && e.file_name() != "..")
            .map(|e| {
                let md = e.metadata();
                Entry {
                    name: e.file_name(),
                    size: if md.is_dir() { None } else { md.size },
                    is_dir: md.is_dir(),
                    modified: md.modified().ok(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        Ok(out)
    }

    async fn size(&self) -> Result<Option<u64>> {
        let (handle, sftp) = self.session().await?;
        let md = sftp.metadata(self.remote_path()).await.map_err(sftp_err);
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        match md {
            Ok(md) => Ok(if md.is_dir() { None } else { md.size }),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl Sender for SftpEndpoint {
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let (handle, sftp) = self.session().await?;
        let mut target = strip_home(&self.loc.target_path(meta.filename.as_deref())?);
        // If the path exists and is a directory, append the file name.
        if !self.loc.is_dir_target()
            && let Some(name) = &meta.filename
            && let Ok(md) = sftp.metadata(target.clone()).await
            && md.is_dir()
        {
            let name = crate::location::safe_name(name)?;
            target = format!("{}/{}", target.trim_end_matches('/'), name);
        }
        debug!(%target, "sftp upload");
        let file = sftp
            .open_with_flags(
                target.clone(),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(sftp_err)?;
        let mut file = stream::Idle::maybe(file, self.cfg.idle);
        let result = stream::pipe(body, &mut file).await;
        file.shutdown().await?;
        result?;
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        Ok(())
    }

    async fn is_dir(&self) -> Result<bool> {
        let (handle, sftp) = self.session().await?;
        let md = sftp.metadata(self.remote_path()).await.map_err(sftp_err);
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        match md {
            Ok(md) => Ok(md.is_dir()),
            Err(e) if e.is_not_found() => Ok(false),
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
        let (handle, sftp) = self.session().await?;
        let path = strip_home(self.loc.sibling(name)?.path());
        let size = match sftp.metadata(path).await {
            Ok(md) if !md.is_dir() => md.size,
            _ => None,
        };
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        Ok(size)
    }

    async fn append(&self, body: ByteStream, meta: &SendMeta, offset: u64) -> Result<()> {
        let (handle, sftp) = self.session().await?;
        let target = strip_home(&self.loc.target_path(meta.filename.as_deref())?);
        debug!(%target, offset, "resuming an sftp upload");
        // Write at `offset` rather than with the APPEND flag: a retry after a
        // failed attempt finds that attempt's bytes behind `offset` and must
        // replace them, not add to them.
        let there = sftp
            .metadata(target.clone())
            .await
            .map_err(sftp_err)?
            .size
            .unwrap_or(0);
        if there < offset {
            return Err(Error::Remote(format!(
                "sftp: {target} holds {there} bytes, cannot resume at {offset}"
            )));
        }
        let mut file = sftp
            .open_with_flags(target.clone(), OpenFlags::WRITE)
            .await
            .map_err(sftp_err)?;
        let cut = russh_sftp::protocol::FileAttributes {
            size: Some(offset),
            ..Default::default()
        };
        file.set_metadata(cut).await.map_err(sftp_err)?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut file = stream::Idle::maybe(file, self.cfg.idle);
        let result = stream::pipe(body, &mut file).await;
        file.shutdown().await?;
        let written = result?;
        // As with FTP's APPE: only the size the server reports proves that
        // the rest arrived.
        let remote = sftp.metadata(target.clone()).await.map_err(sftp_err)?.size;
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        if remote != Some(offset + written) {
            return Err(Error::Remote(format!(
                "sftp: resume incomplete: server holds {} of {} bytes for {target}",
                remote.map_or_else(|| "an unknown number".into(), |n| n.to_string()),
                offset + written
            )));
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = strip_home(self.loc.sibling(from)?.path());
        let to = strip_home(self.loc.sibling(to)?.path());
        // The session's own type does not say which extensions the server
        // has; the raw one does.
        let handle = self.cfg.connect().await?;
        let channel = handle.channel_open_session().await.map_err(ssh_err)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(ssh_err)?;
        let raw = RawSftpSession::new(channel.into_stream());
        let res = match raw.init().await {
            // OpenSSH's rename(2): replaces an existing target in one step.
            Ok(v) if v.extensions.get(POSIX_RENAME).is_some_and(|v| v == "1") => {
                posix_rename(&raw, &from, &to).await
            }
            // Plain SFTP rename refuses an existing target: move it aside
            // rather than delete it, so a failed rename loses nothing.
            Ok(_) => crate::protocols::replace_aside(&mut SftpRenamer(&raw), &from, &to).await,
            Err(e) => Err(sftp_err(e)),
        };
        let _ = raw.close_session();
        super::disconnect(&handle).await;
        res
    }

    fn supports_remove(&self) -> bool {
        true
    }

    async fn remove(&self, name: &str) -> Result<()> {
        let (handle, sftp) = self.session().await?;
        let path = strip_home(self.loc.sibling(name)?.path());
        let res = sftp.remove_file(path).await.map_err(sftp_err);
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        res
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    async fn mkdir_all(&self) -> Result<()> {
        let dir = strip_home(self.loc.parent()?.path());
        let (handle, sftp) = self.session().await?;
        let absolute = dir.starts_with('/');
        let mut path = String::new();
        let mut res = Ok(());
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            if absolute || !path.is_empty() {
                path.push('/');
            }
            path.push_str(part);
            if sftp.metadata(path.clone()).await.is_ok() {
                continue;
            }
            debug!(%path, "sftp mkdir");
            if let Err(e) = sftp.create_dir(path.clone()).await {
                res = Err(sftp_err(e));
                break;
            }
        }
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::Status;

    fn status(code: StatusCode, msg: &str) -> Error {
        sftp_err(
            Status {
                id: 1,
                status_code: code,
                error_message: msg.into(),
                language_tag: "en".into(),
            }
            .into(),
        )
    }

    #[test]
    fn statuses_map_to_the_same_kinds_everywhere() {
        let e = status(StatusCode::NoSuchFile, "No such file");
        assert!(e.is_not_found() && !e.is_transient(), "{e}");
        assert_eq!(e.to_string(), "I/O error: sftp: No such file");
        let e = status(StatusCode::PermissionDenied, "Permission denied");
        assert!(!e.is_transient() && e.exit_code() == 1, "{e}");
        let e = status(StatusCode::Failure, "");
        assert!(
            matches!(&e, Error::Remote(m) if m == "sftp: Failure"),
            "{e}"
        );
        assert!(!e.is_transient());
        assert!(status(StatusCode::ConnectionLost, "").is_transient());
    }
}
