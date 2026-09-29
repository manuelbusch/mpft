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

/// A server path as the protocol takes it: a leading `/~/` means "relative
/// to the login directory" and is dropped, every other path is taken as
/// it is. (A URL path always starts with `/`, so without this there would
/// be no way to name a path relative to where the login lands.)
#[allow(dead_code)]
pub(crate) fn strip_home(p: &str) -> String {
    p.strip_prefix("/~/")
        .map(String::from)
        .unwrap_or_else(|| p.to_string())
}

/// Rename and delete on one open connection, for [`replace_aside`].
#[allow(dead_code)]
#[async_trait::async_trait]
pub(crate) trait Renamer: Send {
    async fn rename(&mut self, from: &str, to: &str) -> Result<()>;
    async fn remove(&mut self, path: &str) -> Result<()>;
}

/// Suffix under which [`replace_aside`] keeps the file it replaces until the
/// new one is in place.
pub const OLD_SUFFIX: &str = ".mpft-old";

/// Rename `from` to `to` on a server whose rename may refuse an existing
/// target, without a moment in which neither file is there for good: the
/// old target is moved aside, the new one renamed into place, and only then
/// is the old one deleted. If the second rename fails, the old one is put
/// back.
#[allow(dead_code)]
pub(crate) async fn replace_aside(r: &mut dyn Renamer, from: &str, to: &str) -> Result<()> {
    let first = match r.rename(from, to).await {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    let old = format!("{to}{OLD_SUFFIX}");
    if r.rename(to, &old).await.is_err() {
        // A file left under the temporary name by a run that stopped half
        // way is in the way. The name is mpft's own, so it goes, once.
        if r.remove(&old).await.is_err() {
            // Nothing there to move aside, or it cannot be moved: the
            // first error is the one that says what is wrong.
            return Err(first);
        }
        tracing::debug!(%old, "removed a stale file left under the temporary name");
        if r.rename(to, &old).await.is_err() {
            return Err(first);
        }
    }
    if let Err(e) = r.rename(from, to).await {
        if let Err(back) = r.rename(&old, to).await {
            tracing::warn!("could not put the previous file back: {back}");
            tracing::debug!(%old, %to, "the previous file is still aside");
        }
        return Err(e);
    }
    if let Err(e) = r.remove(&old).await {
        tracing::warn!("could not remove the previous file: {e}");
        tracing::debug!(%old, "the previous file is still aside");
    }
    Ok(())
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
        Scheme::Ssh => Err(Error::UnsupportedOperation {
            scheme: "ssh".into(),
            op: "hold files (it names a relay for `cp --via`; sftp:// or scp:// reach its files)",
        }),

        #[cfg(feature = "ftp")]
        Scheme::Ftp | Scheme::Ftps => Ok(Box::new(ftp::FtpEndpoint::new(loc)?)),

        #[cfg(feature = "http")]
        Scheme::Http | Scheme::Https => Ok(Box::new(http::HttpEndpoint::new(loc)?)),

        #[cfg(feature = "webdav")]
        Scheme::WebDav | Scheme::WebDavs => Ok(Box::new(webdav::WebDavEndpoint::new(loc)?)),

        #[cfg(feature = "s3")]
        Scheme::S3 => Ok(Box::new(s3::S3Endpoint::new(loc)?)),

        #[cfg(feature = "mail")]
        Scheme::Mailto | Scheme::Smtp | Scheme::Smtps => {
            Ok(Box::new(mail::MailEndpoint::new(loc)?))
        }

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

    /// A server whose rename refuses an existing target, and which can be
    /// told to refuse one rename more.
    #[derive(Default)]
    struct Server {
        files: std::collections::HashMap<String, &'static str>,
        refuse: Option<(String, String)>,
    }

    #[async_trait::async_trait]
    impl Renamer for Server {
        async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
            let refused = self.refuse.as_ref() == Some(&(from.to_string(), to.to_string()));
            if refused || self.files.contains_key(to) || !self.files.contains_key(from) {
                return Err(Error::Remote(format!("ftp: 550 cannot rename {from}")));
            }
            let v = self.files.remove(from).unwrap();
            self.files.insert(to.into(), v);
            Ok(())
        }
        async fn remove(&mut self, path: &str) -> Result<()> {
            self.files
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| Error::Remote("gone".into()))
        }
    }

    #[tokio::test]
    async fn replacing_a_file_never_loses_both() {
        let mut s = Server::default();
        s.files.insert("f.mpft-part".into(), "new");
        replace_aside(&mut s, "f.mpft-part", "f").await.unwrap();
        assert_eq!(s.files.len(), 1);
        assert_eq!(s.files["f"], "new");

        // An existing target is replaced, and its old version is gone after.
        s.files.insert("f.mpft-part".into(), "newer");
        replace_aside(&mut s, "f.mpft-part", "f").await.unwrap();
        assert_eq!(s.files.len(), 1);
        assert_eq!(s.files["f"], "newer");

        // The rename into place fails: the old file is back where it was.
        s.files.insert("f.mpft-part".into(), "newest");
        s.refuse = Some(("f.mpft-part".into(), "f".into()));
        assert!(replace_aside(&mut s, "f.mpft-part", "f").await.is_err());
        assert_eq!(s.files["f"], "newer");
        assert_eq!(s.files["f.mpft-part"], "newest");
        assert!(!s.files.contains_key("f.mpft-old"));
    }

    #[tokio::test]
    async fn a_stale_file_under_the_temporary_name_is_not_in_the_way() {
        let mut s = Server::default();
        s.files.insert("f".into(), "old");
        s.files.insert("f.mpft-old".into(), "left by a crash");
        s.files.insert("f.mpft-part".into(), "new");
        replace_aside(&mut s, "f.mpft-part", "f").await.unwrap();
        assert_eq!(s.files.len(), 1, "{:?}", s.files);
        assert_eq!(s.files["f"], "new");
    }

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
