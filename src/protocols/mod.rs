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

/// Build the endpoint for a parsed location. Credentials from the environment
/// are applied here (see [`Location::apply_env`]).
pub fn open(mut loc: Location) -> Result<Box<dyn Endpoint>> {
    loc.apply_env();
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
