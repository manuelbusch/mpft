//! URL parsing: turns `scheme://user:pass@host:port/path?opt=val` (or a bare
//! local path, or `mailto:a@b.c?subject=x`) into a [`Location`].

use std::fmt;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::{Error, Result};

/// Supported protocol prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    File,
    Sftp,
    Scp,
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
            options: "key=<file>, known_hosts=strict|accept-new|off",
            feature: "ssh",
        },
        SchemeInfo {
            scheme: Scheme::Scp,
            prefix: "scp://",
            description: "SCP over SSH",
            can_receive: true,
            can_send: true,
            default_port: Some(22),
            options: "key=<file>, known_hosts=strict|accept-new|off",
            feature: "ssh",
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
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    /// Percent-decoded path. For `file` this is the local path; for `s3` it is
    /// `bucket/key`; for mail schemes it is the comma-separated recipient list.
    path: String,
    options: Vec<(String, String)>,
    /// True when the original path ended in `/` (target is a directory).
    dir_hint: bool,
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
        let password = url.password().map(percent_decode);
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
            username,
            password,
            host,
            port,
            path,
            options,
            dir_hint,
        })
    }

    /// Parse and then fill credentials from the environment (`MPT_PASSWORD`,
    /// `MPT_SMTP_PASSWORD`).
    pub fn parse_with_env(input: &str) -> Result<Location> {
        let mut loc = Location::parse(input)?;
        loc.apply_env();
        Ok(loc)
    }

    fn local(path: &str) -> Location {
        Location {
            scheme: Scheme::File,
            username: None,
            password: None,
            host: None,
            port: None,
            path: path.to_string(),
            options: Vec::new(),
            dir_hint: path.ends_with('/'),
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
            self.password = Some(v);
        }
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
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
    pub fn options(&self) -> &[(String, String)] {
        &self.options
    }
    pub fn set_password(&mut self, pw: impl Into<String>) {
        self.password = Some(pw.into());
    }
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.push((key.into(), value.into()));
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
        let p = self.path.trim_end_matches('/');
        let name = p.rsplit('/').next().unwrap_or("");
        if name.is_empty() { None } else { Some(name) }
    }

    /// Path with `name` appended (for directory targets).
    pub fn path_joined(&self, name: &str) -> String {
        if self.path.ends_with('/') {
            format!("{}{}", self.path, name)
        } else {
            format!("{}/{}", self.path, name)
        }
    }

    /// Resolve the effective target path for a send: the path itself, or path +
    /// file name when the location is a directory target.
    pub fn target_path(&self, filename: Option<&str>) -> String {
        match (self.is_dir_target(), filename) {
            (true, Some(name)) => self.path_joined(name),
            _ => self.path.clone(),
        }
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
        let mut loc = self.clone();
        loc.path = if self.is_dir_target() {
            self.path_joined(name)
        } else {
            match self.path.rfind('/') {
                Some(idx) => format!("{}/{}", &self.path[..idx], name),
                None => name.to_string(),
            }
        };
        loc.dir_hint = false;
        Ok(loc)
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
}

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

fn looks_like_url(s: &str) -> bool {
    if s.starts_with("mailto:") {
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
        assert_eq!(l.target_path(Some("r.pdf")), "/incoming/r.pdf");
        let l = Location::parse("sftp://u@h/incoming/x.pdf").unwrap();
        assert_eq!(l.target_path(Some("r.pdf")), "/incoming/x.pdf");
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
        assert_eq!(d.target_path(Some("f")), "b/prefix/f");
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
    fn env_password_fallback() {
        let mut l = Location::parse("ftp://u@h/p").unwrap();
        assert_eq!(l.password(), None);
        l.set_password("from-env");
        assert_eq!(l.password(), Some("from-env"));
        assert!(l.to_string().contains("u:***@"));
    }
}
