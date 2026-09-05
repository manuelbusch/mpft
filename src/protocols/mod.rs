//! Protocol implementations and the scheme → endpoint dispatcher.

pub mod file;

#[cfg(feature = "ftp")]
pub mod ftp;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "mail")]
pub mod mail;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "webdav")]
pub mod webdav;

use crate::{Endpoint, Error, Location, Result, Scheme};

/// Retry `connect` up to `allowed` times while it fails with a transient
/// error, with a linear backoff.
///
/// Only safe around the connect and login phase: nothing of the payload has
/// been read at that point, so repeating it cannot lose data.
#[allow(dead_code)]
pub(crate) async fn with_connect_retries<T, F, Fut>(
    allowed: u32,
    what: &str,
    connect: F,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut attempt = 0;
    loop {
        match connect().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < allowed && e.is_retryable_connect() => {
                attempt += 1;
                tracing::warn!("{what} failed ({e}); retry {attempt} of {allowed}");
                tokio::time::sleep(std::time::Duration::from_secs(attempt as u64)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Build the endpoint for a parsed location. Credentials from the environment
/// are applied here (see [`Location::apply_env`]).
pub fn open(mut loc: Location) -> Result<Box<dyn Endpoint>> {
    loc.apply_env();
    crate::policy::check_credentials(&loc)?;
    let scheme = loc.scheme();
    match scheme {
        Scheme::File => Ok(Box::new(file::FileEndpoint::new(loc))),

        #[cfg(feature = "ssh")]
        Scheme::Sftp => Ok(Box::new(ssh::sftp::SftpEndpoint::new(loc)?)),
        #[cfg(feature = "ssh")]
        Scheme::Scp => Ok(Box::new(ssh::scp::ScpEndpoint::new(loc)?)),

        #[cfg(feature = "ftp")]
        Scheme::Ftp | Scheme::Ftps => Ok(Box::new(ftp::FtpEndpoint::new(loc)?)),

        #[cfg(feature = "http")]
        Scheme::Http | Scheme::Https => Ok(Box::new(http::HttpEndpoint::new(loc)?)),

        #[cfg(feature = "webdav")]
        Scheme::WebDav | Scheme::WebDavs => Ok(Box::new(webdav::WebDavEndpoint::new(loc)?)),

        #[cfg(feature = "s3")]
        Scheme::S3 => Ok(Box::new(s3::S3Endpoint::new(loc)?)),

        #[cfg(feature = "mail")]
        Scheme::Mailto | Scheme::Smtp => Ok(Box::new(mail::MailEndpoint::new(loc)?)),

        #[allow(unreachable_patterns)]
        other => Err(Error::UnsupportedScheme(format!(
            "{other} (compiled without the '{}' feature)",
            other.info().feature
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test(start_paused = true)]
    async fn connect_retries_only_help_transient_failures() {
        let calls = AtomicU32::new(0);
        let flaky = || async {
            if calls.fetch_add(1, Ordering::Relaxed) < 2 {
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "nope",
                )))
            } else {
                Ok(7u32)
            }
        };
        assert_eq!(
            with_connect_retries(3, "test", flaky).await.unwrap(),
            7,
            "a refused connection is worth another try"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        // Too few attempts: the error is passed on.
        let calls = AtomicU32::new(0);
        let flaky = || async {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>(Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "nope",
            )))
        };
        assert!(with_connect_retries(1, "test", flaky).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 2);

        // Bad credentials are never retried.
        let calls = AtomicU32::new(0);
        let denied = || async {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>(Error::Auth("wrong password".into()))
        };
        assert!(with_connect_retries(5, "test", denied).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
