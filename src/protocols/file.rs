//! Local file system.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs;

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
        let md = fs::metadata(self.path()).await?;
        Ok(md.is_file().then_some(md.len()))
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

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        Ok(fs::rename(self.sibling_path(from)?, self.sibling_path(to)?).await?)
    }

    async fn remove(&self, name: &str) -> Result<()> {
        Ok(fs::remove_file(self.sibling_path(name)?).await?)
    }
}

#[cfg(test)]
mod tests {
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
