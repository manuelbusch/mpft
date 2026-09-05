//! Multi-protocol file transceiver.
//!
//! Every endpoint is a URL with a protocol prefix (`sftp://`, `ftps://`, `s3://`,
//! `mailto:` ...). [`open`] turns a URL into an [`Endpoint`], which optionally
//! exposes a [`Receiver`] (download / list) and a [`Sender`] (upload).
//! Protocols that can only send (e-mail) simply return `None` for the receiver.

pub mod config;
pub mod credentials;
pub mod endpoint;
pub mod error;
pub mod hash;
pub mod location;
pub mod policy;
pub mod protocols;
pub mod sign;
pub mod stream;
#[cfg(feature = "ftp")]
pub mod tls;
pub mod transfer;

pub use config::Config;
pub use endpoint::{Endpoint, Entry, Receiver, SendMeta, Sender};
pub use error::{Error, Result};
pub use hash::{DigestHandle, HashAlgo};
pub use location::{Location, Scheme};
pub use sign::{SignFormat, SignSpec, Signer, Verifier, VerifySpec};
pub use stream::{ByteStream, MemoryCache, TeeOptions, tee};
pub use transfer::{
    CacheMode, CopyOptions, CopyReport, FanoutReport, TargetReport, copy, copy_many,
};

/// Parse a URL (or bare local path) and open the matching protocol endpoint.
///
/// `mpt://<profile>/<path>` is resolved against the configuration file that
/// [`config::install`] published. No network connection is made here;
/// connections are established lazily by the individual operations.
pub fn open(url: &str) -> Result<Box<dyn Endpoint>> {
    protocols::open(config::locate(url)?)
}

/// Close what is still open: pooled SSH sessions are kept for the life of the
/// process so a transfer's several steps share one handshake, and this says
/// goodbye to them properly. Nothing else needs it.
pub async fn shutdown() {
    #[cfg(feature = "ssh")]
    protocols::ssh::close_sessions().await;
}

/// Install the process-wide rustls crypto provider (aws-lc-rs).
///
/// Several dependencies (reqwest, lettre, suppaftp, object_store) build rustls
/// configs and panic if no default provider is installed. Idempotent.
pub fn init_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
