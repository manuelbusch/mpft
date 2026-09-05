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
#[derive(Debug, Clone, Default)]
pub struct SendMeta {
    /// File name of the payload (used when the target is a directory, for
    /// mail attachments and for Content-Disposition).
    pub filename: Option<String>,
    /// Total length if known. Lets protocols set Content-Length / SCP headers
    /// without spooling.
    pub size: Option<u64>,
    /// MIME type if known; otherwise guessed from `filename`.
    pub content_type: Option<String>,
}

impl SendMeta {
    pub fn from_filename(name: impl Into<String>) -> Self {
        SendMeta {
            filename: Some(name.into()),
            ..Default::default()
        }
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
