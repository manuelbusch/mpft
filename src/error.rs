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

    /// The configuration file is missing, unreadable or invalid.
    #[error("configuration: {0}")]
    Config(String),

    /// A query option had an invalid value.
    #[error("invalid option '{name}': {reason}")]
    InvalidOption { name: String, reason: String },

    /// Authentication failed or no usable credentials were found.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Remote side reported an error (file not found, permission denied, ...).
    #[error("remote error: {0}")]
    Remote(String),

    /// A signature could not be verified, or its signer is not trusted.
    #[error("signature: {0}")]
    Signature(String),

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

    /// The operation was stopped on request (Ctrl-C, cancellation token).
    #[error("cancelled")]
    Cancelled,

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
    /// Whether retrying makes sense: connection problems and temporary
    /// refusals, not bad credentials, a missing file or a rejection by the
    /// server that another attempt would meet again.
    pub fn is_transient(&self) -> bool {
        use std::io::ErrorKind as K;
        match self {
            Error::Transport { .. } => true,
            // What the file system or the peer says for good; everything else
            // (a reset, a timeout, a stream that broke off) may heal.
            Error::Io(e) => !matches!(
                e.kind(),
                K::NotFound
                    | K::PermissionDenied
                    | K::AlreadyExists
                    | K::InvalidInput
                    | K::InvalidData
                    | K::Unsupported
                    | K::OutOfMemory
                    | K::StorageFull
                    | K::QuotaExceeded
                    | K::FileTooLarge
                    | K::ReadOnlyFilesystem
                    | K::NotADirectory
                    | K::IsADirectory
                    | K::DirectoryNotEmpty
                    | K::InvalidFilename
            ),
            // The server's own word: FTP's 4xx replies are temporary by
            // definition, and so are HTTP's 5xx, 408 and 429. A reply that
            // did not come at all is a connection problem.
            Error::Remote(msg) => {
                let code = |prefix: &str| msg.strip_prefix(prefix).and_then(|r| r.get(..3));
                matches!(code("ftp: "), Some(c) if c.starts_with('4'))
                    || msg.starts_with("ftp: no reply")
                    || matches!(code("http "), Some(c) if c.starts_with('5') || c == "408" || c == "429")
            }
            _ => false,
        }
    }

    /// Whether retrying the connect and login phase makes sense. Everything
    /// that is not a configuration or credential problem qualifies: at that
    /// point no payload has been read, so a second attempt costs nothing and
    /// heals a server that answered out of turn.
    pub fn is_retryable_connect(&self) -> bool {
        !matches!(
            self,
            Error::Auth(_)
                | Error::Config(_)
                | Error::InvalidUrl(_)
                | Error::InvalidOption { .. }
                | Error::UnsupportedScheme(_)
                | Error::UnsupportedOperation { .. }
                | Error::ChecksumMismatch { .. }
                | Error::Signature(_)
                | Error::Cancelled
        )
    }

    /// The exit code the command line gives for this error, so a relay
    /// ends the way `cp` would have: 1 a failed transfer, 2 a bad URL,
    /// option or configuration, 3 a checksum or signature that did not
    /// hold, 4 refused credentials, 130 cancelled.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::ChecksumMismatch { .. } | Error::Signature(_) => 3,
            Error::Auth(_) => 4,
            Error::Cancelled => 130,
            Error::Config(_)
            | Error::InvalidUrl(_)
            | Error::InvalidOption { .. }
            | Error::UnsupportedScheme(_)
            | Error::UnsupportedOperation { .. } => 2,
            _ => 1,
        }
    }

    /// A short, stable name of the variant, for machine-readable output:
    /// `io`, `auth`, `cancelled`, …
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidUrl(_) => "invalid_url",
            Error::UnsupportedScheme(_) => "unsupported_scheme",
            Error::UnsupportedOperation { .. } => "unsupported_operation",
            Error::Config(_) => "config",
            Error::InvalidOption { .. } => "invalid_option",
            Error::Auth(_) => "auth",
            Error::Remote(_) => "remote",
            Error::Signature(_) => "signature",
            Error::ChecksumMismatch { .. } => "checksum_mismatch",
            Error::Io(_) => "io",
            Error::Cancelled => "cancelled",
            Error::Transport { .. } => "transport",
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_another_attempt_can_cure_is_transient() {
        let io = |k| Error::Io(std::io::Error::from(k));
        let remote = |m: &str| Error::Remote(m.into());
        for e in [
            io(std::io::ErrorKind::ConnectionReset),
            io(std::io::ErrorKind::TimedOut),
            io(std::io::ErrorKind::UnexpectedEof),
            io(std::io::ErrorKind::Other),
            remote("ftp: 421 Service not available"),
            remote("ftp: 426 Connection closed; transfer aborted"),
            remote("ftp: no reply to STOR within 30s"),
            remote("http 503 Service Unavailable"),
            remote("http 429 Too Many Requests"),
            Error::transport("sftp", std::io::Error::other("channel closed")),
        ] {
            assert!(e.is_transient(), "{e}");
        }
        for e in [
            Error::Auth("denied".into()),
            Error::invalid_option("x", "bad"),
            Error::Cancelled,
            Error::ChecksumMismatch {
                algo: "SHA-256",
                expected: "a".into(),
                actual: "b".into(),
            },
            io(std::io::ErrorKind::NotFound),
            io(std::io::ErrorKind::PermissionDenied),
            io(std::io::ErrorKind::NotADirectory),
            remote("ftp: 550 No such file"),
            remote("http 404 Not Found"),
            remote("scp: permission denied"),
        ] {
            assert!(!e.is_transient(), "{e}");
        }
    }
}
