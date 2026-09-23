//! `sftp://` via the SSH SFTP subsystem (russh-sftp).

use async_trait::async_trait;
use russh::client::Handle;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
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

fn sftp_err(e: russh_sftp::client::error::Error) -> Error {
    Error::transport("sftp", e)
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
        let md = sftp.metadata(self.remote_path()).await.map_err(sftp_err)?;
        let _ = sftp.close().await;
        super::disconnect(&handle).await;
        Ok(if md.is_dir() { None } else { md.size })
    }
}

#[async_trait]
impl Sender for SftpEndpoint {
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let (handle, sftp) = self.session().await?;
        let mut target = strip_home(&self.loc.target_path(meta.filename.as_deref())?);
        // If the path exists and is a directory, append the file name.
        if !self.loc.is_dir_target()
            && let Some(name) = &meta.filename
            && let Ok(md) = sftp.metadata(target.clone()).await
            && md.is_dir()
        {
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
        let (handle, sftp) = self.session().await?;
        let from = strip_home(self.loc.sibling(from)?.path());
        let to = strip_home(self.loc.sibling(to)?.path());
        // Plain SFTP rename refuses an existing target; replace it first.
        let _ = sftp.remove_file(to.clone()).await;
        let res = sftp.rename(from, to).await.map_err(sftp_err);
        let _ = sftp.close().await;
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
