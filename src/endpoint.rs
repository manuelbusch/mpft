use std::time::SystemTime;

use async_trait::async_trait;

use crate::{ByteStream, Location, Result};

/// A directory entry returned by [`Receiver::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub size: Option<u64>,
    pub is_dir: bool,
    pub modified: Option<SystemTime>,
}

/// Metadata that accompanies a payload on [`Sender::send`].
#[derive(Clone, Default)]
pub struct SendMeta {
    /// File name of the payload (used when the target is a directory, for
    /// mail attachments and for Content-Disposition).
    pub filename: Option<String>,
    /// Total length if known. Lets protocols set Content-Length / SCP headers
    /// without spooling.
    pub size: Option<u64>,
    /// MIME type if known; otherwise guessed from `filename`.
    pub content_type: Option<String>,
    /// Checksum of the payload, available once the stream has been read to
    /// EOF. Senders that cannot place a sidecar file (mail) use it directly.
    pub digest: Option<crate::DigestHandle>,
    /// Signer for the checksum file; senders that cannot place a sibling
    /// file (mail) attach the signature themselves.
    pub signer: Option<std::sync::Arc<dyn crate::sign::Signer>>,
}

impl std::fmt::Debug for SendMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendMeta")
            .field("filename", &self.filename)
            .field("size", &self.size)
            .field("content_type", &self.content_type)
            .field("digest", &self.digest)
            .field("signer", &self.signer.as_ref().map(|s| s.identity()))
            .finish()
    }
}

impl SendMeta {
    /// Metadata for a payload called `name`. The name is normalized to a
    /// single safe path component (see [`crate::location::safe_name`]), so a
    /// name taken from a remote listing cannot escape the target directory.
    pub fn from_filename(name: impl AsRef<str>) -> Result<Self> {
        let mut meta = SendMeta::default();
        meta.set_filename(name)?;
        Ok(meta)
    }

    /// Set the file name, normalizing it the same way as [`Self::from_filename`].
    pub fn set_filename(&mut self, name: impl AsRef<str>) -> Result<()> {
        self.filename = Some(crate::location::safe_name(name.as_ref())?);
        Ok(())
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// The effective MIME type: explicit, else guessed from the file name,
    /// else `application/octet-stream`.
    pub fn mime(&self) -> String {
        if let Some(ct) = &self.content_type {
            return ct.clone();
        }
        self.filename
            .as_deref()
            .map(|f| mime_guess::from_path(f).first_or_octet_stream().to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string())
    }

    /// File name to use, falling back to `fallback` when none is known.
    pub fn filename_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        self.filename.as_deref().unwrap_or(fallback)
    }
}

/// Something that can produce data (download) and enumerate entries.
#[async_trait]
pub trait Receiver: Send + Sync {
    /// Open the resource at the endpoint's path for reading.
    async fn receive(&self) -> Result<ByteStream>;

    /// List the directory at the endpoint's path.
    async fn list(&self) -> Result<Vec<Entry>>;

    /// Size of the resource if cheaply available (used for progress and for
    /// senders that need the length up front). Default: unknown.
    async fn size(&self) -> Result<Option<u64>> {
        Ok(None)
    }
}

/// Something that can consume data (upload / deliver).
#[async_trait]
pub trait Sender: Send + Sync {
    /// Write the payload to the endpoint's path (or deliver it, for mail).
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()>;

    /// Whether the target can rename a file, which is what makes an atomic
    /// finish possible: upload to `<name>.mpt-part`, then rename into place.
    fn supports_rename(&self) -> bool {
        false
    }

    /// Rename `from` to `to`. Both are plain file names in the directory of
    /// this endpoint's location (see [`Location::sibling`]).
    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let _ = (from, to);
        Err(crate::Error::UnsupportedOperation {
            scheme: String::new(),
            op: "rename",
        })
    }

    /// Delete the file `name` in the directory of this endpoint's location.
    async fn remove(&self, name: &str) -> Result<()> {
        let _ = name;
        Err(crate::Error::UnsupportedOperation {
            scheme: String::new(),
            op: "remove",
        })
    }

    /// Whether the target can be written to from a given offset, which is
    /// what makes resuming an interrupted upload possible.
    fn supports_append(&self) -> bool {
        false
    }

    /// Size of the file `name` in the directory of this endpoint's location,
    /// or `None` when it is not there. Used to find out how much of an
    /// interrupted upload has arrived.
    async fn existing_size(&self, name: &str) -> Result<Option<u64>> {
        let _ = name;
        Ok(None)
    }

    /// Write `body` to the end of the endpoint's file, which already holds
    /// `offset` bytes. The caller has skipped that many bytes of the payload.
    async fn append(&self, body: ByteStream, meta: &SendMeta, offset: u64) -> Result<()> {
        let _ = (body, meta, offset);
        Err(crate::Error::UnsupportedOperation {
            scheme: String::new(),
            op: "append",
        })
    }
}

/// A parsed, ready-to-use endpoint. Direction support is optional per protocol.
pub trait Endpoint: Send + Sync {
    fn location(&self) -> &Location;

    /// `None` when the protocol cannot receive (e.g. `mailto:`).
    fn as_receiver(&self) -> Option<&dyn Receiver>;

    /// `None` when the protocol cannot send.
    fn as_sender(&self) -> Option<&dyn Sender>;

    /// Receiver or a descriptive error.
    fn receiver(&self) -> Result<&dyn Receiver> {
        self.as_receiver()
            .ok_or_else(|| crate::Error::UnsupportedOperation {
                scheme: self.location().scheme().to_string(),
                op: "receive",
            })
    }

    /// Sender or a descriptive error.
    fn sender(&self) -> Result<&dyn Sender> {
        self.as_sender()
            .ok_or_else(|| crate::Error::UnsupportedOperation {
                scheme: self.location().scheme().to_string(),
                op: "send",
            })
    }
}
