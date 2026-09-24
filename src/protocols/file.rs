//! Local file system.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs;
use tokio::io::AsyncSeekExt;

use crate::{ByteStream, Endpoint, Entry, Location, Receiver, Result, SendMeta, Sender, stream};

pub struct FileEndpoint {
    loc: Location,
}

impl FileEndpoint {
    pub fn new(loc: Location) -> Self {
        FileEndpoint { loc }
    }

    fn path(&self) -> &Path {
        Path::new(self.loc.path())
    }

    /// Effective target for a send: append the file name when the path is a
    /// directory (either trailing `/` or an existing directory).
    async fn target(&self, meta: &SendMeta) -> Result<PathBuf> {
        let p = self.path();
        let is_dir =
            self.loc.is_dir_target() || fs::metadata(p).await.map(|m| m.is_dir()).unwrap_or(false);
        Ok(match (is_dir, &meta.filename) {
            (true, Some(name)) => p.join(crate::location::safe_name(name)?),
            _ => p.to_path_buf(),
        })
    }
}

impl Endpoint for FileEndpoint {
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
impl Receiver for FileEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        let f = fs::File::open(self.path()).await?;
        Ok(stream::boxed(f))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        let mut rd = fs::read_dir(self.path()).await?;
        let mut out = Vec::new();
        while let Some(e) = rd.next_entry().await? {
            let md = e.metadata().await?;
            out.push(Entry {
                name: e.file_name().to_string_lossy().into_owned(),
                size: if md.is_file() { Some(md.len()) } else { None },
                is_dir: md.is_dir(),
                modified: md.modified().ok(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn size(&self) -> Result<Option<u64>> {
        match fs::metadata(self.path()).await {
            Ok(md) => Ok(md.is_file().then_some(md.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl FileEndpoint {
    /// Absolute path of a file called `name` next to this location.
    fn sibling_path(&self, name: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(self.loc.sibling(name)?.path().to_string()))
    }
}

#[async_trait]
impl Sender for FileEndpoint {
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let target = self.target(meta).await?;
        if let Some(parent) = target.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).await?;
        }
        let mut f = fs::File::create(&target).await?;
        stream::pipe(body, &mut f).await?;
        f.sync_all().await?;
        Ok(())
    }

    fn supports_rename(&self) -> bool {
        true
    }

    fn supports_append(&self) -> bool {
        true
    }

    async fn existing_size(&self, name: &str) -> Result<Option<u64>> {
        match fs::metadata(self.sibling_path(name)?).await {
            Ok(md) if md.is_file() => Ok(Some(md.len())),
            _ => Ok(None),
        }
    }

    async fn append(&self, body: ByteStream, meta: &SendMeta, offset: u64) -> Result<()> {
        let target = self.target(meta).await?;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .await
            .map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("{}: {e}", target.display()),
                ))
            })?;
        // Write at `offset`, not at the end: a retry after a failed attempt
        // finds that attempt's bytes behind `offset` and must replace them.
        let len = f.metadata().await?.len();
        if len < offset {
            return Err(crate::Error::Remote(format!(
                "{}: holds {len} bytes, cannot resume at {offset}",
                target.display()
            )));
        }
        f.set_len(offset).await?;
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        tracing::debug!(?target, offset, "resuming a local file");
        stream::pipe(body, &mut f).await?;
        f.sync_all().await?;
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(fs::rename(self.sibling_path(from)?, self.sibling_path(to)?).await?)
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    async fn mkdir_all(&self) -> Result<()> {
        let dir = self.loc.parent()?;
        let path = std::path::Path::new(dir.path());
        if path.as_os_str().is_empty() {
            return Ok(());
        }
        Ok(fs::create_dir_all(path).await?)
    }

    fn supports_remove(&self) -> bool {
        true
    }

    async fn remove(&self, name: &str) -> Result<()> {
        Ok(fs::remove_file(self.sibling_path(name)?).await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::Sender;

    /// Yields `left` bytes of `byte`, then fails, like a dropped connection.
    struct Broken {
        left: usize,
        byte: u8,
    }

    impl tokio::io::AsyncRead for Broken {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.left == 0 {
                return std::task::Poll::Ready(Err(std::io::Error::other("connection lost")));
            }
            let n = self.left.min(buf.remaining());
            buf.put_slice(&vec![self.byte; n]);
            self.left -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_retried_append_writes_at_the_offset() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("f.mpt-part");
        std::fs::write(&part, b"0123456789").unwrap();
        let ep = super::FileEndpoint::new(crate::Location::parse(part.to_str().unwrap()).unwrap());
        let meta = crate::SendMeta::default();

        // The first attempt dies after a few bytes of the rest ...
        let first = ep
            .append(
                Box::pin(Broken {
                    left: 3,
                    byte: b'x',
                }),
                &meta,
                10,
            )
            .await;
        assert!(first.is_err());
        // ... and the retry sends the whole rest again from the same offset.
        ep.append(
            Box::pin(std::io::Cursor::new(b"abcdef".to_vec())),
            &meta,
            10,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&part).unwrap(), b"0123456789abcdef");

        // A file shorter than the offset cannot be continued.
        let err = ep
            .append(Box::pin(std::io::Cursor::new(b"z".to_vec())), &meta, 100)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot resume"), "{err}");
    }

    #[tokio::test]
    async fn the_size_of_nothing_is_unknown() {
        use crate::Receiver;
        let dir = tempfile::tempdir().unwrap();
        let ep = |p: &std::path::Path| {
            super::FileEndpoint::new(crate::Location::parse(p.to_str().unwrap()).unwrap())
        };
        assert_eq!(ep(&dir.path().join("missing")).size().await.unwrap(), None);
        assert_eq!(ep(dir.path()).size().await.unwrap(), None, "a directory");
        std::fs::write(dir.path().join("f"), b"abc").unwrap();
        assert_eq!(ep(&dir.path().join("f")).size().await.unwrap(), Some(3));
        // Something other than "not there" is still an error.
        std::fs::write(dir.path().join("file"), b"").unwrap();
        assert!(ep(&dir.path().join("file/below")).size().await.is_err());
    }

    #[tokio::test]
    async fn roundtrip_and_dir_target() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.txt");
        std::fs::write(&src, b"hello").unwrap();

        let s = crate::open(src.to_str().unwrap()).unwrap();
        let d = crate::open(&format!("{}/", dir.path().join("out").display())).unwrap();
        crate::copy(s.as_ref(), d.as_ref()).await.unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("out/in.txt")).unwrap(),
            b"hello"
        );

        let entries = d.receiver().unwrap().list().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "in.txt");
        assert_eq!(entries[0].size, Some(5));
    }
}
