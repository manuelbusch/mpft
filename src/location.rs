//! URL parsing: turns `scheme://user:pass@host:port/path?opt=val` (or a bare
//! local path, or `mailto:a@b.c?subject=x`) into a [`Location`].

use std::fmt;

use percent_encoding::percent_decode_str;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::broker::{Brokers, PasswordRequest};
use crate::{Error, Result};

/// Supported protocol prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    File,
    Sftp,
    Scp,
    /// An SSH host as such: where `cp --via` runs the relay. Nothing is
    /// read from or written to it.
    Ssh,
    Ftp,
    Ftps,
    Http,
    Https,
    WebDav,
    WebDavs,
    S3,
    Mailto,
    Smtp,
}

/// Static description of a scheme, used by `mpt schemes`.
#[derive(Debug, Clone, Copy)]
pub struct SchemeInfo {
    pub scheme: Scheme,
    pub prefix: &'static str,
    pub description: &'static str,
    pub can_receive: bool,
    pub can_send: bool,
    pub default_port: Option<u16>,
    pub options: &'static str,
    pub feature: &'static str,
}

impl Scheme {
    pub const ALL: &'static [SchemeInfo] = &[
        SchemeInfo {
            scheme: Scheme::File,
            prefix: "file://",
            description: "local file system (bare paths work too)",
            can_receive: true,
            can_send: true,
            default_port: None,
            options: "-",
            feature: "-",
        },
        SchemeInfo {
            scheme: Scheme::Sftp,
            prefix: "sftp://",
            description: "SFTP over SSH",
            can_receive: true,
            can_send: true,
            default_port: Some(22),
            options: "key=<file>, known_hosts=strict|accept-new|off, hostkey=SHA256:…",
            feature: "ssh",
        },
        SchemeInfo {
            scheme: Scheme::Scp,
            prefix: "scp://",
            description: "SCP over SSH",
            can_receive: true,
            can_send: true,
            default_port: Some(22),
            options: "key=<file>, known_hosts=strict|accept-new|off, hostkey=SHA256:…",
            feature: "ssh",
        },
        SchemeInfo {
            scheme: Scheme::Ssh,
            prefix: "ssh://",
            description: "an SSH host running `mpt relay` (cp --via)",
            can_receive: false,
            can_send: false,
            default_port: Some(22),
            options: "key=<file>, known_hosts=strict|accept-new|off, hostkey=SHA256:…",
            feature: "relay",
        },
        SchemeInfo {
            scheme: Scheme::Ftp,
            prefix: "ftp://",
            description: "FTP without TLS",
            can_receive: true,
            can_send: true,
            default_port: Some(21),
            options: "passive=true|false",
            feature: "ftp",
        },
        SchemeInfo {
            scheme: Scheme::Ftps,
            prefix: "ftps://",
            description: "FTP with TLS (explicit by default)",
            can_receive: true,
            can_send: true,
            default_port: Some(21),
            options: "tls=explicit|implicit, insecure=true, passive=true|false",
            feature: "ftp",
        },
        SchemeInfo {
            scheme: Scheme::Http,
            prefix: "http://",
            description: "HTTP GET / PUT",
            can_receive: true,
            can_send: true,
            default_port: Some(80),
            options: "method=put|post, header=Name:Value, insecure=true",
            feature: "http",
        },
        SchemeInfo {
            scheme: Scheme::Https,
            prefix: "https://",
            description: "HTTPS GET / PUT",
            can_receive: true,
            can_send: true,
            default_port: Some(443),
            options: "method=put|post, header=Name:Value, insecure=true",
            feature: "http",
        },
        SchemeInfo {
            scheme: Scheme::WebDav,
            prefix: "webdav://",
            description: "WebDAV over HTTP",
            can_receive: true,
            can_send: true,
            default_port: Some(80),
            options: "insecure=true",
            feature: "webdav",
        },
        SchemeInfo {
            scheme: Scheme::WebDavs,
            prefix: "webdavs://",
            description: "WebDAV over HTTPS",
            can_receive: true,
            can_send: true,
            default_port: Some(443),
            options: "insecure=true",
            feature: "webdav",
        },
        SchemeInfo {
            scheme: Scheme::S3,
            prefix: "s3://",
            description: "S3-compatible object storage (bucket/key)",
            can_receive: true,
            can_send: true,
            default_port: None,
            options: "endpoint=<url>, region=<r>, path_style=true, insecure=true",
            feature: "s3",
        },
        SchemeInfo {
            scheme: Scheme::Mailto,
            prefix: "mailto:",
            description: "e-mail attachment, SMTP server from MPT_SMTP_URL",
            can_receive: false,
            can_send: true,
            default_port: None,
            options: "subject=, cc=, bcc=, body=, from=, filename=",
            feature: "mail",
        },
        SchemeInfo {
            scheme: Scheme::Smtp,
            prefix: "smtp://",
            description: "e-mail attachment, SMTP server in URL (path = recipients)",
            can_receive: false,
            can_send: true,
            default_port: Some(587),
            options: "tls=starttls|implicit|none, subject=, cc=, bcc=, body=, from=, filename=",
            feature: "mail",
        },
    ];

    pub fn parse(s: &str) -> Option<Scheme> {
        Some(match s.to_ascii_lowercase().as_str() {
            "file" => Scheme::File,
            "sftp" => Scheme::Sftp,
            "scp" => Scheme::Scp,
            "ssh" => Scheme::Ssh,
            "ftp" => Scheme::Ftp,
            "ftps" => Scheme::Ftps,
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            "webdav" | "webdav+http" | "dav" => Scheme::WebDav,
            "webdavs" | "webdav+https" | "davs" => Scheme::WebDavs,
            "s3" => Scheme::S3,
            "mailto" => Scheme::Mailto,
            "smtp" | "smtps" => Scheme::Smtp,
            _ => return None,
        })
    }

    pub fn info(self) -> &'static SchemeInfo {
        Scheme::ALL
            .iter()
            .find(|i| i.scheme == self)
            .expect("every scheme has info")
    }

    pub fn as_str(self) -> &'static str {
        self.info()
            .prefix
            .trim_end_matches("://")
            .trim_end_matches(':')
    }

    pub fn can_receive(self) -> bool {
        self.info().can_receive
    }

    pub fn can_send(self) -> bool {
        self.info().can_send
    }

    pub fn default_port(self) -> Option<u16> {
        self.info().default_port
    }

    /// True for `mailto:` / `smtp://`, whose "path" is a recipient list.
    pub fn is_mail(self) -> bool {
        matches!(self, Scheme::Mailto | Scheme::Smtp)
    }

    /// Whether the path is sent in a URL, and so has to keep track of its
    /// encoding (see [`Location::encoded_path`]).
    fn has_wire_path(self) -> bool {
        matches!(
            self,
            Scheme::Http | Scheme::Https | Scheme::WebDav | Scheme::WebDavs
        )
    }

    /// Whether the scheme needs a host component.
    fn needs_host(self) -> bool {
        !matches!(self, Scheme::File | Scheme::Mailto)
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed endpoint address.
#[derive(Debug, Clone)]
pub struct Location {
    scheme: Scheme,
    username: Option<String>,
    /// Wrapped so that it is redacted in `Debug` output and wiped on drop.
    password: Option<SecretString>,
    host: Option<String>,
    port: Option<u16>,
    /// Percent-decoded path. For `file` this is the local path; for `s3` it is
    /// `bucket/key`; for mail schemes it is the comma-separated recipient list.
    path: String,
    /// For `http(s)` and `webdav(s)`: the path as it goes on the wire,
    /// every segment percent-encoded, kept in step with `path`. It is what
    /// remembers that `%2F` was a character of a segment rather than a
    /// separator, which the decoded `path` cannot tell.
    wire_path: Option<String>,
    options: Vec<(String, String)>,
    /// True when the original path ended in `/` (target is a directory).
    dir_hint: bool,
    /// True when the password came from the URL itself, which means it is
    /// visible in the process list and the shell history.
    password_from_url: bool,
    /// Ways to get a secret at login time instead of carrying it here. Not
    /// part of the URL in any form.
    brokers: Brokers,
    /// The profile this location was resolved from, if any: what decides
    /// which relay it goes through.
    profile: Option<String>,
}

impl Location {
    /// Parse a URL or bare path. Pure: no environment lookups (see [`Location::apply_env`]).
    pub fn parse(input: &str) -> Result<Location> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Error::InvalidUrl("empty".into()));
        }

        // Bare local path (no scheme, or a Windows drive letter).
        if !looks_like_url(input) {
            return Ok(Location::local(input));
        }

        let url = Url::parse(input).map_err(|e| Error::InvalidUrl(format!("{input}: {e}")))?;
        let scheme = Scheme::parse(url.scheme())
            .ok_or_else(|| Error::UnsupportedScheme(url.scheme().to_string()))?;

        if scheme == Scheme::File {
            let path = url
                .to_file_path()
                .map_err(|_| Error::InvalidUrl(format!("{input}: not a valid file URL")))?;
            let mut loc = Location::local(&path.to_string_lossy());
            loc.dir_hint = url.path().ends_with('/');
            return Ok(loc);
        }

        let username = non_empty(percent_decode(url.username()));
        let password = url
            .password()
            .map(|p| SecretString::from(percent_decode(p)));
        let host = url
            .host_str()
            .map(|h| h.trim_matches(['[', ']']).to_string());
        let port = url.port();

        if scheme.needs_host() && host.is_none() {
            return Err(Error::InvalidUrl(format!(
                "{}: missing host",
                masked(input)
            )));
        }

        let wire_path = scheme.has_wire_path().then(|| {
            let raw = if url.path().is_empty() {
                "/"
            } else {
                url.path()
            };
            normalize_wire_path(raw)
        });
        let (path, dir_hint) = match scheme {
            Scheme::Mailto => {
                // RFC 6068: mailto:addr1,addr2?subject=...; opaque path.
                let recipients = percent_decode(url.path());
                if recipients.trim().is_empty() {
                    return Err(Error::InvalidUrl("mailto: missing recipient".into()));
                }
                (recipients, false)
            }
            Scheme::Smtp => {
                // smtp://user@host/ziel@x?…  -> path is recipient list
                let p = percent_decode(url.path());
                (p.trim_matches('/').to_string(), false)
            }
            Scheme::S3 => {
                // s3://bucket/key -> "bucket/key"
                let key = percent_decode(url.path());
                let bucket = host.clone().unwrap_or_default();
                let full = if key.trim_matches('/').is_empty() {
                    bucket
                } else {
                    format!("{bucket}/{}", key.trim_start_matches('/'))
                };
                (full, url.path().ends_with('/'))
            }
            _ => {
                let p = percent_decode(url.path());
                let p = if p.is_empty() { "/".to_string() } else { p };
                let dir = p.ends_with('/');
                (p, dir)
            }
        };

        let options = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        Ok(Location {
            scheme,
            password_from_url: password.is_some(),
            username,
            password,
            host,
            port,
            path,
            wire_path,
            options,
            dir_hint,
            brokers: Brokers::default(),
            profile: None,
        })
    }

    /// Parse and then fill credentials from the environment (`MPT_PASSWORD`,
    /// `MPT_SMTP_PASSWORD`).
    pub fn parse_with_env(input: &str) -> Result<Location> {
        let mut loc = Location::parse(input)?;
        loc.apply_env();
        Ok(loc)
    }

    /// A bare local path: no scheme, no host, and a trailing separator marks
    /// a directory (on Windows `\` counts as one).
    fn local(path: &str) -> Location {
        Location {
            scheme: Scheme::File,
            username: None,
            password: None,
            host: None,
            port: None,
            path: path.to_string(),
            wire_path: None,
            options: Vec::new(),
            dir_hint: path.ends_with('/') || (cfg!(windows) && path.ends_with('\\')),
            password_from_url: false,
            brokers: Brokers::default(),
            profile: None,
        }
    }

    /// Fill in a password from the environment if the URL had none.
    pub fn apply_env(&mut self) {
        if self.password.is_some() {
            return;
        }
        let var = match self.scheme {
            Scheme::File => return,
            Scheme::Mailto | Scheme::Smtp => "MPT_SMTP_PASSWORD",
            _ => "MPT_PASSWORD",
        };
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            self.password = Some(SecretString::from(v));
            self.password_from_url = false;
        }
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    /// The password in the clear. Callers must not log or store what they
    /// get back; it is a secret everywhere else in this crate.
    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|p| p.expose_secret())
    }
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
    /// Host or error for schemes that require one.
    pub fn host_required(&self) -> Result<&str> {
        self.host()
            .ok_or_else(|| Error::InvalidUrl("missing host".into()))
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
    /// Explicit port or the scheme default.
    pub fn port_or_default(&self) -> u16 {
        self.port.or(self.scheme.default_port()).unwrap_or(0)
    }
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The path as it goes into an HTTP or WebDAV request: every segment
    /// percent-encoded (`%`, `#`, `?`, space, non-ASCII, …), so the server
    /// sees the name that [`Location::path`] holds. A `%2F` of the original
    /// URL is still `%2F` here, one segment and not two.
    pub fn encoded_path(&self) -> String {
        match &self.wire_path {
            Some(w) => w.clone(),
            None => encode_path(&self.path),
        }
    }

    /// [`Location::target_path`], encoded like [`Location::encoded_path`].
    pub fn encoded_target_path(&self, filename: Option<&str>) -> Result<String> {
        match (self.is_dir_target(), filename) {
            (true, Some(name)) => {
                let name = safe_name(name)?;
                let dir = self.encoded_path();
                let sep = if dir.ends_with('/') { "" } else { "/" };
                Ok(format!("{dir}{sep}{}", encode_segment(&name)))
            }
            _ => Ok(self.encoded_path()),
        }
    }
    pub fn options(&self) -> &[(String, String)] {
        &self.options
    }
    pub fn set_password(&mut self, pw: impl Into<String>) {
        self.password = Some(SecretString::from(pw.into()));
        self.password_from_url = false;
    }

    /// Whether the password was written into the URL, where the process list
    /// and the shell history can see it.
    pub fn password_in_url(&self) -> bool {
        self.password_from_url
    }

    /// The same location without its password: for handing it to a relay
    /// that is to ask for the password instead.
    pub fn without_password(&self) -> Location {
        let mut loc = self.clone();
        loc.password = None;
        loc.password_from_url = false;
        loc
    }

    /// The profile this location came from.
    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }
    pub fn set_profile(&mut self, name: impl Into<String>) {
        self.profile = Some(name.into());
    }

    /// The brokers this location asks at login time.
    pub fn brokers(&self) -> &Brokers {
        &self.brokers
    }
    pub fn set_brokers(&mut self, brokers: Brokers) {
        self.brokers = brokers;
    }

    /// The password for a login: the one this location carries, otherwise
    /// what its password broker hands out for this attempt, otherwise
    /// nothing. Fetched at every login and meant to be dropped right after
    /// it, so a relay never holds a password longer than one authentication.
    pub async fn login_password(&self, attempt: u32) -> Result<Option<SecretString>> {
        if let Some(pw) = &self.password {
            return Ok(Some(pw.clone()));
        }
        match &self.brokers.password {
            Some(source) => {
                source
                    .password(&PasswordRequest {
                        target: self,
                        attempt,
                    })
                    .await
            }
            None => Ok(None),
        }
    }

    /// Whether a login could get a password at all, from either source.
    pub fn has_password(&self) -> bool {
        self.password.is_some() || self.brokers.password.is_some()
    }
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.push((key.into(), value.into()));
    }

    /// Drop every value of `key`. Used when a more specific source of options
    /// (a profile, a URL reference) replaces what the location came with.
    pub fn remove_option(&mut self, key: &str) {
        self.options.retain(|(k, _)| k != key);
    }

    /// True when the path denotes a directory target (`.../`), meaning the
    /// source file name should be appended when sending.
    pub fn is_dir_target(&self) -> bool {
        self.dir_hint
    }

    /// Last path segment, if any (used as default file name).
    pub fn filename(&self) -> Option<&str> {
        if self.scheme.is_mail() {
            return None;
        }
        let p = trim_end_separators(&self.path);
        let name = match last_separator(p) {
            Some(i) => &p[i + 1..],
            None => p,
        };
        if name.is_empty() { None } else { Some(name) }
    }

    /// Path with `name` appended (for directory targets). `name` must be a
    /// single, safe path component; see [`safe_name`].
    pub fn path_joined(&self, name: &str) -> Result<String> {
        let name = safe_name(name)?;
        Ok(if self.path.ends_with('/') {
            format!("{}{}", self.path, name)
        } else {
            format!("{}/{}", self.path, name)
        })
    }

    /// Resolve the effective target path for a send: the path itself, or path +
    /// file name when the location is a directory target.
    pub fn target_path(&self, filename: Option<&str>) -> Result<String> {
        match (self.is_dir_target(), filename) {
            (true, Some(name)) => self.path_joined(name),
            _ => Ok(self.path.clone()),
        }
    }

    /// Append a relative path to a directory location: `a/b/c.pdf`, one safe
    /// component at a time, so nothing can climb out of the directory. A
    /// trailing `/` marks the result as a directory target again.
    pub fn join(&self, rel: &str) -> Result<Location> {
        if self.scheme.is_mail() {
            return Err(Error::UnsupportedOperation {
                scheme: self.scheme.to_string(),
                op: "have a path appended",
            });
        }
        let mut loc = self.clone();
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            loc.push_segment(&safe_name(part)?);
        }
        loc.finish_join(rel.ends_with('/'), rel.is_empty() && self.dir_hint);
        Ok(loc)
    }

    /// Like [`Location::join`], for a relative path written the way a URL
    /// path is: percent-encoded. Each segment is decoded before it is
    /// checked, so `%2e%2e` is refused like `..`. On HTTP and WebDAV a
    /// segment that decodes to something with a `/` in it stays one
    /// segment (`group%2Fproject`); elsewhere the `/` separates.
    pub fn join_url_path(&self, rel: &str) -> Result<Location> {
        if self.scheme.is_mail() {
            return self.join(rel);
        }
        let mut loc = self.clone();
        for raw in rel.split('/').filter(|p| !p.is_empty()) {
            let seg = percent_decode_str(raw)
                .decode_utf8()
                .map_err(|e| Error::InvalidUrl(format!("'{raw}': {e}")))?;
            // Every piece has to be a plain name, whether or not the
            // protocol treats the `/` as a separator: a server that decodes
            // `%2F` must not find a `..` either.
            for piece in seg.split('/') {
                check_segment(piece)?;
            }
            if self.wire_path.is_some() {
                loc.push_segment(&seg);
            } else {
                for piece in seg.split('/') {
                    loc.push_segment(piece);
                }
            }
        }
        loc.finish_join(rel.ends_with('/'), rel.is_empty() && self.dir_hint);
        Ok(loc)
    }

    /// Append one segment, checked by the caller, to both forms of the path.
    fn push_segment(&mut self, name: &str) {
        if !self.path.ends_with('/') {
            self.path.push('/');
        }
        self.path.push_str(name);
        if let Some(w) = &mut self.wire_path {
            if !w.ends_with('/') {
                w.push('/');
            }
            w.push_str(&encode_segment(name));
        }
    }

    /// Mark the result of a join as a directory or not. Nothing appended
    /// leaves a directory a directory.
    fn finish_join(&mut self, trailing_slash: bool, was_dir: bool) {
        self.dir_hint = trailing_slash || was_dir;
        if self.dir_hint {
            if !self.path.ends_with('/') {
                self.path.push('/');
            }
            if let Some(w) = &mut self.wire_path
                && !w.ends_with('/')
            {
                w.push('/');
            }
        }
    }

    /// The directory this location is in: the location itself for a
    /// directory target, otherwise the path without its last component.
    /// Credentials and options are kept. Not available for mail schemes.
    pub fn parent(&self) -> Result<Location> {
        if self.scheme.is_mail() {
            return Err(Error::UnsupportedOperation {
                scheme: self.scheme.to_string(),
                op: "have a parent directory",
            });
        }
        let mut loc = self.clone();
        if !self.is_dir_target()
            && let Some(w) = &self.wire_path
        {
            // The encoded form knows where the segments end.
            let w = w.trim_end_matches('/');
            let dir = &w[..w.rfind('/').map_or(0, |i| i + 1)];
            let dir = if dir.is_empty() { "/" } else { dir };
            loc.path = percent_decode(dir);
            loc.wire_path = Some(dir.to_string());
        } else if !self.is_dir_target() {
            let p = trim_end_separators(&self.path);
            loc.path = match last_separator(p) {
                Some(idx) => p[..=idx].to_string(),
                // Nothing in front of the name. Only a bare local path
                // (`report.pdf`) and an s3 path that is just a bucket can get
                // here — every URL scheme carries a leading `/`. An empty
                // path is one no protocol can list, so name the directory:
                // the working directory locally, the bucket root on s3.
                None if self.scheme == Scheme::S3 => format!("{p}/"),
                None => ".".to_string(),
            };
        }
        loc.dir_hint = true;
        Ok(loc)
    }

    /// Location of a file called `name` next to this one: inside the
    /// directory for directory targets, otherwise in the parent directory.
    /// Credentials and options are kept. Not available for mail schemes.
    pub fn sibling(&self, name: &str) -> Result<Location> {
        if self.scheme.is_mail() {
            return Err(Error::UnsupportedOperation {
                scheme: self.scheme.to_string(),
                op: "address a sibling file",
            });
        }
        let name = safe_name(name)?;
        let mut loc = self.clone();
        if self.wire_path.is_some() {
            let mut dir = self.parent()?;
            dir.push_segment(&name);
            dir.dir_hint = false;
            return Ok(dir);
        }
        loc.path = if self.is_dir_target() {
            self.path_joined(&name)?
        } else {
            // Keep the separator that is already in use, so a Windows path
            // stays a Windows path.
            match last_separator(&self.path) {
                Some(idx) => format!("{}{}{}", &self.path[..idx + 1], name, ""),
                None => name.to_string(),
            }
        };
        loc.dir_hint = false;
        Ok(loc)
    }

    /// Inactivity timeout for network operations: `?timeout=<seconds>`,
    /// 30 seconds by default. `0` disables it.
    pub fn timeout(&self) -> Result<Option<std::time::Duration>> {
        let secs = match self.opt("timeout") {
            Some(v) => v
                .parse::<u64>()
                .map_err(|e| Error::invalid_option("timeout", e))?,
            None => 30,
        };
        Ok((secs > 0).then(|| std::time::Duration::from_secs(secs)))
    }

    /// Like [`Self::timeout`], but with a value for "no timeout" too, for
    /// places that need a deadline no matter what (connecting, for instance).
    pub fn timeout_or(&self, fallback: std::time::Duration) -> Result<std::time::Duration> {
        Ok(self.timeout()?.unwrap_or(fallback))
    }

    /// How often to retry connecting and logging in: `?connect_retries=<n>`,
    /// none by default. Only the connect phase is repeated, before any payload
    /// byte has been read, and only for transient errors.
    pub fn connect_retries(&self) -> Result<u32> {
        match self.opt("connect_retries") {
            Some(v) => v
                .parse::<u32>()
                .map_err(|e| Error::invalid_option("connect_retries", e)),
            None => Ok(0),
        }
    }

    /// First value of a query option.
    pub fn opt(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// All values of a repeated query option.
    pub fn opts(&self, name: &str) -> impl Iterator<Item = &str> {
        self.options
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Boolean option: `true|1|yes|on` ⇒ true, `false|0|no|off` ⇒ false.
    pub fn opt_bool(&self, name: &str) -> Result<Option<bool>> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "" | "true" | "1" | "yes" | "on" => Ok(Some(true)),
                "false" | "0" | "no" | "off" => Ok(Some(false)),
                other => Err(Error::invalid_option(
                    name,
                    format!("expected boolean, got '{other}'"),
                )),
            },
        }
    }

    /// Recipients for mail schemes (comma-separated path).
    pub fn recipients(&self) -> Vec<String> {
        self.path
            .split([',', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }

    /// The URL with the password replaced by `***`, safe for logs.
    pub fn masked(&self) -> String {
        self.to_string()
    }

    /// The URL with the password in it and every part encoded, so that
    /// [`Location::parse`] reads it back as it is: for handing an endpoint
    /// to another process (a relay), never for a log.
    pub fn unmasked(&self) -> String {
        use percent_encoding::utf8_percent_encode as enc;
        let mut out = String::new();
        match self.scheme {
            Scheme::File => return self.path.clone(),
            Scheme::Mailto => {
                out.push_str("mailto:");
                out.push_str(&enc(&self.path, PATH_SET).to_string());
            }
            Scheme::S3 => {
                out.push_str("s3://");
                out.push_str(&enc(&self.path, PATH_SET).to_string());
            }
            _ => {
                out.push_str(&format!("{}://", self.scheme));
                if let Some(u) = &self.username {
                    out.push_str(&enc(u, USERINFO_SET).to_string());
                    if let Some(p) = &self.password {
                        out.push(':');
                        out.push_str(&enc(p.expose_secret(), USERINFO_SET).to_string());
                    }
                    out.push('@');
                }
                if let Some(h) = &self.host {
                    if h.contains(':') {
                        out.push_str(&format!("[{h}]"));
                    } else {
                        out.push_str(h);
                    }
                }
                if let Some(p) = self.port {
                    out.push_str(&format!(":{p}"));
                }
                if self.scheme == Scheme::Smtp {
                    out.push('/');
                }
                match &self.wire_path {
                    Some(w) => out.push_str(w),
                    None => out.push_str(&enc(&self.path, PATH_SET).to_string()),
                }
            }
        }
        if !self.options.is_empty() {
            let q: Vec<String> = self
                .options
                .iter()
                .map(|(k, v)| format!("{}={}", enc(k, QUERY_SET), enc(v, QUERY_SET)))
                .collect();
            out.push('?');
            out.push_str(&q.join("&"));
        }
        out
    }
}

/// What [`Location::unmasked`] encodes in the user name and password.
const USERINFO_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// What [`Location::unmasked`] encodes in the path: what would end it or
/// be decoded on the way back.
const PATH_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// What [`Location::encoded_path`] encodes in a segment: everything a URL
/// path would read as syntax or decode on the way in. Non-ASCII is always
/// encoded.
const SEGMENT_SET: &percent_encoding::AsciiSet = &PATH_SET
    .add(b'/')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|');

fn encode_segment(seg: &str) -> String {
    percent_encoding::utf8_percent_encode(seg, SEGMENT_SET).to_string()
}

/// A decoded path, encoded segment by segment.
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// A path as a URL had it, with every segment decoded and encoded again:
/// the same name, in one spelling, with `%2F` kept inside its segment.
fn normalize_wire_path(raw: &str) -> String {
    raw.split('/')
        .map(|seg| encode_segment(&percent_decode(seg)))
        .collect::<Vec<_>>()
        .join("/")
}

/// A segment of a path that came from outside, taken as it is: no `.`,
/// `..`, empty name or control characters. Unlike [`safe_name`] it rewrites
/// nothing.
fn check_segment(seg: &str) -> Result<()> {
    let bad = |why: &str| Error::InvalidUrl(format!("unsafe file name '{seg}': {why}"));
    if seg.is_empty() {
        return Err(bad("empty"));
    }
    if seg == "." || seg == ".." {
        return Err(bad("refers to a directory"));
    }
    if seg.chars().any(|c| c.is_control()) {
        return Err(bad("contains control characters"));
    }
    Ok(())
}

/// What [`Location::unmasked`] encodes in an option's key and value.
const QUERY_SET: &percent_encoding::AsciiSet = &PATH_SET.add(b'&').add(b'=').add(b'+');

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scheme {
            Scheme::File => return f.write_str(&self.path),
            Scheme::Mailto => {
                write!(f, "mailto:{}", self.path)?;
            }
            Scheme::S3 => {
                write!(f, "s3://{}", self.path)?;
            }
            _ => {
                write!(f, "{}://", self.scheme)?;
                if let Some(u) = &self.username {
                    f.write_str(u)?;
                    if self.password.is_some() {
                        f.write_str(":***")?;
                    }
                    f.write_str("@")?;
                }
                if let Some(h) = &self.host {
                    f.write_str(h)?;
                }
                if let Some(p) = self.port {
                    write!(f, ":{p}")?;
                }
                if self.scheme == Scheme::Smtp {
                    write!(f, "/{}", self.path)?;
                } else {
                    f.write_str(&self.path)?;
                }
            }
        }
        if !self.options.is_empty() {
            let q: Vec<String> = self
                .options
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            write!(f, "?{}", q.join("&"))?;
        }
        Ok(())
    }
}

/// Index of the last path separator: `/` everywhere, and `\` on Windows,
/// where both are separators and a bare path may use either.
fn last_separator(path: &str) -> Option<usize> {
    let slash = path.rfind('/');
    if cfg!(windows) {
        let backslash = path.rfind('\\');
        return match (slash, backslash) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
    slash
}

/// Drop trailing separators, `\` included on Windows.
fn trim_end_separators(path: &str) -> &str {
    if cfg!(windows) {
        path.trim_end_matches(['/', '\\'])
    } else {
        path.trim_end_matches('/')
    }
}

fn looks_like_url(s: &str) -> bool {
    // A scheme is case-insensitive, `MAILTO:` included.
    if s.get(..7)
        .is_some_and(|h| h.eq_ignore_ascii_case("mailto:"))
    {
        return true;
    }
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        // A Windows drive letter ("C:\") is never followed by "//", but guard anyway.
        return !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
    }
    false
}

/// Reduce a file name that came from somewhere else (a remote listing, an SCP
/// header, a `Content-Disposition`, a URL) to a single safe path component.
///
/// Keeps only the last segment, so `../../etc/passwd` becomes `passwd`, and
/// rejects names that cannot denote a file: empty, `.`, `..`, or containing
/// control characters.
pub fn safe_name(name: &str) -> Result<String> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let trimmed = last.trim();
    let bad = |why: &str| Error::InvalidUrl(format!("unsafe file name '{name}': {why}"));
    if trimmed.is_empty() {
        return Err(bad("empty"));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(bad("refers to a directory"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(bad("contains control characters"));
    }
    Ok(trimmed.to_string())
}

fn percent_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Mask `user:password@` in a raw URL string (for error messages before parsing succeeded).
fn masked(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("***"));
            u.to_string()
        }
        _ => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joining_nothing_keeps_a_directory_a_directory() {
        let dir = Location::parse("sftp://h/in/").unwrap();
        let same = dir.join("").unwrap();
        assert!(same.is_dir_target());
        assert_eq!(same.path(), "/in/");
        assert!(!dir.join("x.bin").unwrap().is_dir_target());
        assert!(dir.join("sub/").unwrap().is_dir_target());
        let file = Location::parse("sftp://h/in/x.bin").unwrap();
        assert!(!file.join("").unwrap().is_dir_target());
    }

    #[test]
    fn parent_is_the_directory_of_a_file_or_the_directory_itself() {
        let file = Location::parse("sftp://u@h:2222/in/x.bin?timeout=5").unwrap();
        let dir = file.parent().unwrap();
        assert_eq!(dir.path(), "/in/");
        assert!(dir.is_dir_target());
        assert_eq!(dir.opt("timeout"), Some("5"));
        assert_eq!(dir.parent().unwrap().path(), "/in/");
        assert_eq!(
            Location::parse("/tmp/a").unwrap().parent().unwrap().path(),
            "/tmp/"
        );
        assert_eq!(
            Location::parse("s3://b/k/x")
                .unwrap()
                .parent()
                .unwrap()
                .path(),
            "b/k/"
        );
        assert!(
            Location::parse("mailto:a@example.com")
                .unwrap()
                .parent()
                .is_err()
        );
    }

    /// A name with nothing in front of it still has a directory, and it has
    /// to be one the protocol can list: an empty path is not. This is what a
    /// bare pattern (`mpt cp '*.csv' out/`) rests on.
    #[test]
    fn the_parent_of_a_bare_name_is_the_working_directory() {
        for name in ["a.bin", "*.csv", "report.pdf"] {
            let parent = Location::parse(name).unwrap().parent().unwrap();
            assert_eq!(parent.path(), ".", "parent of {name}");
            assert!(parent.is_dir_target(), "parent of {name} is a directory");
        }
        // Appending to it stays in the working directory.
        let dir = Location::parse("*.csv").unwrap().parent().unwrap();
        assert_eq!(dir.join("one.csv").unwrap().path(), "./one.csv");

        // On s3 a path without a separator is a bucket, already at its root.
        assert_eq!(
            Location::parse("s3://b").unwrap().parent().unwrap().path(),
            "b/"
        );
        assert_eq!(
            Location::parse("s3://b/k")
                .unwrap()
                .parent()
                .unwrap()
                .path(),
            "b/"
        );
    }

    #[test]
    fn bare_path_is_file() {
        let l = Location::parse("/tmp/a.txt").unwrap();
        assert_eq!(l.scheme(), Scheme::File);
        assert_eq!(l.path(), "/tmp/a.txt");
        assert_eq!(l.filename(), Some("a.txt"));
        assert!(!l.is_dir_target());

        let l = Location::parse("relative/dir/").unwrap();
        assert_eq!(l.scheme(), Scheme::File);
        assert!(l.is_dir_target());
    }

    #[test]
    fn windows_paths_are_local_files() {
        // A drive letter is not a scheme: nothing follows the colon but a
        // separator, never "//".
        let l = Location::parse("C:\\data\\report.pdf").unwrap();
        assert_eq!(l.scheme(), Scheme::File);
        assert_eq!(l.path(), "C:\\data\\report.pdf");
        // A UNC path likewise.
        let l = Location::parse("\\\\server\\share\\x.bin").unwrap();
        assert_eq!(l.scheme(), Scheme::File);
        assert!(!l.is_dir_target());
        // Forward slashes work on Windows too, and are unambiguous here.
        let l = Location::parse("D:/data/").unwrap();
        assert_eq!(l.scheme(), Scheme::File);
        assert!(l.is_dir_target());
        assert_eq!(l.path_joined("x.bin").unwrap(), "D:/data/x.bin");
    }

    #[cfg(windows)]
    #[test]
    fn windows_separators_are_separators() {
        let l = Location::parse("C:\\data\\report.pdf").unwrap();
        assert_eq!(l.filename(), Some("report.pdf"));
        assert_eq!(
            l.sibling("report.pdf.sha256").unwrap().path(),
            "C:\\data\\report.pdf.sha256"
        );
        let dir = Location::parse("C:\\data\\").unwrap();
        assert!(dir.is_dir_target());
    }

    #[test]
    fn file_url() {
        let l = Location::parse("file:///tmp/x%20y.bin").unwrap();
        assert_eq!(l.scheme(), Scheme::File);
        assert_eq!(l.path(), "/tmp/x y.bin");
        assert_eq!(l.to_string(), "/tmp/x y.bin");
    }

    #[test]
    fn sftp_full() {
        let l = Location::parse(
            "sftp://deploy:s%40cret@srv.example.com:2222/var/log/app.log?key=/k/id&known_hosts=off",
        )
        .unwrap();
        assert_eq!(l.scheme(), Scheme::Sftp);
        assert_eq!(l.username(), Some("deploy"));
        assert_eq!(l.password(), Some("s@cret"));
        assert_eq!(l.host(), Some("srv.example.com"));
        assert_eq!(l.port(), Some(2222));
        assert_eq!(l.port_or_default(), 2222);
        assert_eq!(l.path(), "/var/log/app.log");
        assert_eq!(l.opt("key"), Some("/k/id"));
        assert_eq!(l.opt("known_hosts"), Some("off"));
        assert_eq!(l.filename(), Some("app.log"));
        assert_eq!(
            l.to_string(),
            "sftp://deploy:***@srv.example.com:2222/var/log/app.log?key=/k/id&known_hosts=off"
        );
    }

    #[test]
    fn default_ports() {
        assert_eq!(
            Location::parse("scp://u@h/p").unwrap().port_or_default(),
            22
        );
        assert_eq!(
            Location::parse("ftps://u@h/p").unwrap().port_or_default(),
            21
        );
        assert_eq!(
            Location::parse("https://h/p").unwrap().port_or_default(),
            443
        );
        assert_eq!(
            Location::parse("smtp://u@h/a@b.c")
                .unwrap()
                .port_or_default(),
            587
        );
    }

    #[test]
    fn dir_target_appends_filename() {
        let l = Location::parse("sftp://u@h/incoming/").unwrap();
        assert!(l.is_dir_target());
        assert_eq!(l.target_path(Some("r.pdf")).unwrap(), "/incoming/r.pdf");
        let l = Location::parse("sftp://u@h/incoming/x.pdf").unwrap();
        assert_eq!(l.target_path(Some("r.pdf")).unwrap(), "/incoming/x.pdf");
    }

    #[test]
    fn missing_host_is_error() {
        assert!(matches!(
            Location::parse("sftp:///x").unwrap_err(),
            Error::InvalidUrl(_)
        ));
    }

    #[test]
    fn unknown_scheme() {
        assert!(
            matches!(Location::parse("gopher://h/x").unwrap_err(), Error::UnsupportedScheme(s) if s == "gopher")
        );
    }

    #[test]
    fn s3_bucket_key() {
        let l = Location::parse(
            "s3://my-bucket/dir/obj.csv?endpoint=http://minio:9000&path_style=true",
        )
        .unwrap();
        assert_eq!(l.scheme(), Scheme::S3);
        assert_eq!(l.host(), Some("my-bucket"));
        assert_eq!(l.path(), "my-bucket/dir/obj.csv");
        assert_eq!(l.opt("endpoint"), Some("http://minio:9000"));
        assert_eq!(l.opt_bool("path_style").unwrap(), Some(true));
        assert_eq!(l.filename(), Some("obj.csv"));
        let d = Location::parse("s3://b/prefix/").unwrap();
        assert!(d.is_dir_target());
        assert_eq!(d.target_path(Some("f")).unwrap(), "b/prefix/f");
    }

    #[test]
    fn mailto() {
        let l = Location::parse("mailto:a@x.de,b@y.de?subject=Report%20KW36&cc=c@z.de").unwrap();
        assert_eq!(l.scheme(), Scheme::Mailto);
        assert!(!l.scheme().can_receive());
        assert!(l.scheme().can_send());
        assert_eq!(l.recipients(), vec!["a@x.de", "b@y.de"]);
        assert_eq!(l.opt("subject"), Some("Report KW36"));
        assert_eq!(l.opt("cc"), Some("c@z.de"));
        assert_eq!(l.filename(), None);
        assert!(
            l.to_string()
                .starts_with("mailto:a@x.de,b@y.de?subject=Report KW36")
        );
        assert!(Location::parse("mailto:?subject=x").is_err());
        // The scheme's case does not matter, here as anywhere else.
        let l = Location::parse("MAILTO:a@x.de").unwrap();
        assert_eq!(l.scheme(), Scheme::Mailto);
        assert_eq!(l.recipients(), vec!["a@x.de"]);
    }

    #[test]
    fn smtp_url() {
        let l = Location::parse("smtp://me%40mail.example.com:pw@mail.example.com:465/team@example.com?tls=implicit&subject=Daten").unwrap();
        assert_eq!(l.scheme(), Scheme::Smtp);
        assert_eq!(l.username(), Some("me@mail.example.com"));
        assert_eq!(l.password(), Some("pw"));
        assert_eq!(l.host(), Some("mail.example.com"));
        assert_eq!(l.port(), Some(465));
        assert_eq!(l.recipients(), vec!["team@example.com"]);
        assert_eq!(l.opt("tls"), Some("implicit"));
        assert_eq!(
            l.to_string(),
            "smtp://me@mail.example.com:***@mail.example.com:465/team@example.com?tls=implicit&subject=Daten"
        );
    }

    #[test]
    fn bool_options() {
        let l = Location::parse("ftps://u@h/p?insecure&passive=no").unwrap();
        assert_eq!(l.opt_bool("insecure").unwrap(), Some(true));
        assert_eq!(l.opt_bool("passive").unwrap(), Some(false));
        assert_eq!(l.opt_bool("missing").unwrap(), None);
        let bad = Location::parse("ftps://u@h/p?insecure=maybe").unwrap();
        assert!(bad.opt_bool("insecure").is_err());
    }

    #[test]
    fn repeated_options() {
        let l = Location::parse("https://h/p?header=A:1&header=B:2").unwrap();
        assert_eq!(l.opts("header").collect::<Vec<_>>(), vec!["A:1", "B:2"]);
    }

    #[test]
    fn webdav_aliases() {
        assert_eq!(
            Location::parse("webdav://h/x").unwrap().scheme(),
            Scheme::WebDav
        );
        assert_eq!(
            Location::parse("webdav+https://h/x").unwrap().scheme(),
            Scheme::WebDavs
        );
        assert_eq!(
            Location::parse("davs://h/x").unwrap().scheme(),
            Scheme::WebDavs
        );
    }

    #[test]
    fn ipv6_host() {
        let l = Location::parse("sftp://u@[::1]:22/x").unwrap();
        assert_eq!(l.host(), Some("::1"));
    }

    #[test]
    fn sibling_locations() {
        let l =
            Location::parse("sftp://u:p@h:2222/data/in/file.bin?key=/k&known_hosts=off").unwrap();
        let s = l.sibling("file.bin.sha256").unwrap();
        assert_eq!(s.path(), "/data/in/file.bin.sha256");
        assert_eq!(s.password(), Some("p"));
        assert_eq!(s.opt("key"), Some("/k"));
        assert!(!s.is_dir_target());

        let d = Location::parse("sftp://u@h/data/in/").unwrap();
        assert_eq!(d.sibling("x.b3").unwrap().path(), "/data/in/x.b3");

        let s3 = Location::parse("s3://bucket/dir/obj.csv?endpoint=http://m:9000").unwrap();
        assert_eq!(
            s3.sibling("obj.csv.b3").unwrap().path(),
            "bucket/dir/obj.csv.b3"
        );
        assert_eq!(
            Location::parse("s3://bucket/obj")
                .unwrap()
                .sibling("obj.b3")
                .unwrap()
                .path(),
            "bucket/obj.b3"
        );

        assert_eq!(
            Location::parse("relative.txt")
                .unwrap()
                .sibling("relative.txt.b3")
                .unwrap()
                .path(),
            "relative.txt.b3"
        );
        assert_eq!(
            Location::parse("/tmp/a.txt")
                .unwrap()
                .sibling("a.txt.b3")
                .unwrap()
                .to_string(),
            "/tmp/a.txt.b3"
        );
        assert!(
            Location::parse("mailto:a@b.c")
                .unwrap()
                .sibling("x")
                .is_err()
        );
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let l = Location::parse("ftps://u:hunter2@h/x?passphrase=y").unwrap();
        let debug = format!("{l:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("REDACTED"), "{debug}");
        // Display masks it as before, and the value is still usable.
        assert!(!l.to_string().contains("hunter2"), "{l}");
        assert_eq!(l.password(), Some("hunter2"));
    }

    #[test]
    fn timeouts() {
        let d = |u: &str| Location::parse(u).unwrap().timeout().unwrap();
        assert_eq!(d("sftp://h/x"), Some(std::time::Duration::from_secs(30)));
        assert_eq!(
            d("sftp://h/x?timeout=5"),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(d("sftp://h/x?timeout=0"), None);
        assert!(
            Location::parse("sftp://h/x?timeout=soon")
                .unwrap()
                .timeout()
                .is_err()
        );
        assert_eq!(
            Location::parse("sftp://h/x?timeout=0")
                .unwrap()
                .timeout_or(std::time::Duration::from_secs(9))
                .unwrap(),
            std::time::Duration::from_secs(9)
        );
    }

    #[test]
    fn safe_names() {
        assert_eq!(safe_name("report.pdf").unwrap(), "report.pdf");
        assert_eq!(safe_name("../x").unwrap(), "x");
        assert_eq!(safe_name("a/../../b").unwrap(), "b");
        assert_eq!(safe_name("/etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_name("C:\\tmp\\x.bin").unwrap(), "x.bin");
        assert_eq!(safe_name("  spaced.txt  ").unwrap(), "spaced.txt");
        for bad in [
            "",
            "   ",
            ".",
            "..",
            "../",
            "a/..",
            "with\nnewline",
            "nul\0byte",
            "/",
        ] {
            assert!(safe_name(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn joins_reject_traversal() {
        let dir = Location::parse("sftp://h/data/").unwrap();
        assert_eq!(dir.path_joined("a.txt").unwrap(), "/data/a.txt");
        assert_eq!(dir.path_joined("../a.txt").unwrap(), "/data/a.txt");
        assert!(dir.path_joined("..").is_err());
        assert!(dir.sibling("../../etc/shadow").unwrap().path() == "/data/shadow");
        assert!(dir.sibling("").is_err());
    }

    #[test]
    fn env_password_fallback() {
        let mut l = Location::parse("ftp://u@h/p").unwrap();
        assert_eq!(l.password(), None);
        l.set_password("from-env");
        assert_eq!(l.password(), Some("from-env"));
        assert!(l.to_string().contains("u:***@"));
    }

    #[test]
    fn unmasked_round_trips_through_parse() {
        for raw in [
            "sftp://u%40x:p%25%3Ass@h:2222/a%20b/c%3Fd?key=/x/y&hostkey=SHA256:ab%2Bc%3D",
            "ftps://u@[::1]:21/in/",
            "s3://bucket/some%20key?endpoint=https://minio:9000",
            "smtp://u:pw@mail/a@x.y,b@x.y?tls=starttls",
            "mailto:a@x.y?subject=hi%20there",
            "/tmp/plain path",
        ] {
            let loc = Location::parse(raw).unwrap();
            let again = Location::parse(&loc.unmasked()).unwrap();
            assert_eq!(again.scheme(), loc.scheme(), "{raw}");
            assert_eq!(again.username(), loc.username(), "{raw}");
            assert_eq!(again.password(), loc.password(), "{raw}");
            assert_eq!(again.host(), loc.host(), "{raw}");
            assert_eq!(again.port(), loc.port(), "{raw}");
            assert_eq!(again.path(), loc.path(), "{raw}");
            assert_eq!(again.options(), loc.options(), "{raw}");
            assert_eq!(again.is_dir_target(), loc.is_dir_target(), "{raw}");
        }
        let loc = Location::parse("sftp://u:secret@h/x").unwrap();
        assert!(loc.unmasked().contains("secret"));
        assert!(!loc.to_string().contains("secret"));
    }

    /// HTTP and WebDAV get their path encoded segment by segment, and a
    /// `%2F` stays inside its segment through every path operation.
    #[test]
    fn the_encoded_path_keeps_segments_apart() {
        let l = Location::parse("https://h/a%2520b").unwrap();
        assert_eq!(l.path(), "/a%20b");
        assert_eq!(l.encoded_path(), "/a%2520b");

        let l = Location::parse("https://h/api/group%2Fproject/raw").unwrap();
        assert_eq!(l.path(), "/api/group/project/raw");
        assert_eq!(l.encoded_path(), "/api/group%2Fproject/raw");
        assert_eq!(l.parent().unwrap().encoded_path(), "/api/group%2Fproject/");
        assert_eq!(
            l.sibling("raw.sha256").unwrap().encoded_path(),
            "/api/group%2Fproject/raw.sha256"
        );
        let last = Location::parse("webdav://h/d/a%2Fb").unwrap();
        assert_eq!(last.parent().unwrap().encoded_path(), "/d/");
        assert_eq!(last.parent().unwrap().path(), "/d/");
        assert_eq!(
            Location::parse(&l.unmasked()).unwrap().encoded_path(),
            l.encoded_path()
        );

        let dir = Location::parse("webdavs://h/in/").unwrap();
        let f = dir.join("M\u{e4}rz #1?100%.pdf").unwrap();
        assert_eq!(f.path(), "/in/M\u{e4}rz #1?100%.pdf");
        assert_eq!(f.encoded_path(), "/in/M%C3%A4rz%20%231%3F100%25.pdf");
        assert_eq!(
            dir.encoded_target_path(Some("a b.txt")).unwrap(),
            "/in/a%20b.txt"
        );
        assert_eq!(
            dir.join("sub/").unwrap().encoded_path(),
            "/in/sub/",
            "a directory stays one"
        );

        // A URL-encoded relative path: one segment on HTTP, two elsewhere,
        // and no `..` in any form.
        let joined = dir.join_url_path("group%2Fproject/x%20y").unwrap();
        assert_eq!(joined.encoded_path(), "/in/group%2Fproject/x%20y");
        let sftp = Location::parse("sftp://h/in/").unwrap();
        assert_eq!(sftp.join_url_path("a%2Fb/c").unwrap().path(), "/in/a/b/c");
        for bad in ["%2e%2e/x", "a/%2E%2E", "..%2Fx", "a%2F..%2Fb"] {
            assert!(dir.join_url_path(bad).is_err(), "{bad}");
            assert!(sftp.join_url_path(bad).is_err(), "{bad}");
        }

        // Schemes without a request path encode what they have.
        assert_eq!(
            Location::parse("sftp://h/a%20b").unwrap().encoded_path(),
            "/a%20b"
        );
    }

    /// A broker is asked at every login, told which attempt it is, and
    /// leaves no trace in the URL or the debug output.
    #[tokio::test]
    async fn a_password_broker_is_asked_per_login() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        use crate::broker::{Brokers, PasswordRequest, PasswordSource};

        struct Counting(AtomicU32);
        #[async_trait::async_trait]
        impl PasswordSource for Counting {
            async fn password(&self, req: &PasswordRequest<'_>) -> Result<Option<SecretString>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                assert_eq!(req.target.username(), Some("u"));
                Ok(Some(SecretString::from(format!("pw{}", req.attempt))))
            }
        }
        let source = Arc::new(Counting(AtomicU32::new(0)));
        let mut loc = Location::parse("sftp://u@h/x").unwrap();
        assert!(!loc.has_password());
        assert!(loc.login_password(1).await.unwrap().is_none());
        loc.set_brokers(Brokers {
            password: Some(source.clone()),
            agent: None,
        });
        assert!(loc.has_password());
        assert_eq!(
            loc.login_password(1)
                .await
                .unwrap()
                .unwrap()
                .expose_secret(),
            "pw1"
        );
        assert_eq!(
            loc.login_password(2)
                .await
                .unwrap()
                .unwrap()
                .expose_secret(),
            "pw2"
        );
        assert_eq!(source.0.load(Ordering::Relaxed), 2);
        assert!(loc.password().is_none(), "the broker's answer is not kept");
        assert!(!loc.unmasked().contains("pw"));
        assert!(format!("{loc:?}").contains("password: true"));

        // The location's own password wins and the broker is left alone.
        loc.set_password("own");
        assert_eq!(
            loc.login_password(3)
                .await
                .unwrap()
                .unwrap()
                .expose_secret(),
            "own"
        );
        assert_eq!(source.0.load(Ordering::Relaxed), 2);

        // Brokers survive the path arithmetic.
        let child = Location::parse("sftp://u@h/dir/").unwrap();
        let mut child = child;
        child.set_brokers(Brokers {
            password: Some(source.clone()),
            agent: None,
        });
        assert!(child.join("x").unwrap().has_password());
        assert!(child.sibling("y").unwrap().has_password());
    }
}
