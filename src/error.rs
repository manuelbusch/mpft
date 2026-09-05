use std::fmt;

/// Library-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL could not be parsed or is missing required parts.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// The scheme is unknown or was compiled out via cargo features.
    #[error("unsupported scheme '{0}'")]
    UnsupportedScheme(String),

    /// The scheme exists but cannot perform the requested direction.
    #[error("scheme '{scheme}' cannot {op}")]
    UnsupportedOperation { scheme: String, op: &'static str },

    /// A query option had an invalid value.
    #[error("invalid option '{name}': {reason}")]
    InvalidOption { name: String, reason: String },

    /// Authentication failed or no usable credentials were found.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Remote side reported an error (file not found, permission denied, ...).
    #[error("remote error: {0}")]
    Remote(String),

    /// The transferred content does not match the expected checksum.
    #[error("{algo} checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch {
        algo: &'static str,
        expected: String,
        actual: String,
    },

    /// Local I/O error.
    #[error("I/O error: {0}")]
    Io(std::io::Error),

    /// Wrapped protocol-library error.
    ///
    /// The source is part of the message (not exposed via `source()`), so
    /// error chains printed by callers do not repeat it.
    #[error("{protocol}: {source}")]
    Transport {
        protocol: &'static str,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    pub fn transport<E>(protocol: &'static str, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Transport {
            protocol,
            source: Box::new(source),
        }
    }

    pub fn invalid_option(name: impl Into<String>, reason: impl fmt::Display) -> Self {
        Error::InvalidOption {
            name: name.into(),
            reason: reason.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
