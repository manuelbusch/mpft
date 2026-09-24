//! `mailto:` and `smtp://`: deliver the payload as an e-mail attachment.
//!
//! * `mailto:a@x.de,b@y.de?subject=…&cc=…` — recipients in the URL, SMTP
//!   server from `MPT_SMTP_URL` (an `smtp://` URL) and `MPT_SMTP_PASSWORD`.
//! * `smtp://user@mail.host:587/a@x.de?tls=starttls&subject=…` — everything
//!   in one URL.
//!
//! Receiving is not supported; the endpoint has no [`Receiver`].

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info};

use crate::{
    ByteStream, Endpoint, Error, Location, Receiver, Result, Scheme, SendMeta, Sender, stream,
};

const DEFAULT_MAX_ATTACHMENT: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpTls {
    StartTls,
    /// STARTTLS where the server offers it, the clear otherwise: port 25
    /// without `?tls=`, where servers talk to each other and not every
    /// one has a certificate.
    Opportunistic,
    Implicit,
    None,
}

impl SmtpTls {
    fn default_port(self) -> u16 {
        match self {
            SmtpTls::Implicit => 465,
            SmtpTls::None | SmtpTls::Opportunistic => 25,
            SmtpTls::StartTls => 587,
        }
    }
}

/// How to talk to a server: `?tls=` if given, else what its scheme and
/// port suggest.
fn tls_mode(server: &Location) -> Result<SmtpTls> {
    Ok(
        match server.opt("tls").map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("starttls") | Some("required") => SmtpTls::StartTls,
            Some("implicit") | Some("wrapper") | Some("tls") => SmtpTls::Implicit,
            Some("none") | Some("off") | Some("false") => SmtpTls::None,
            None if server.scheme() == Scheme::Smtps => SmtpTls::Implicit,
            None => match server.port() {
                Some(465) => SmtpTls::Implicit,
                Some(25) => SmtpTls::Opportunistic,
                _ => SmtpTls::StartTls,
            },
            Some(other) => {
                return Err(Error::invalid_option(
                    "tls",
                    format!("expected starttls|implicit|none, got '{other}'"),
                ));
            }
        },
    )
}

/// `[mail] password` belongs to the server `[mail] smtp` names, and to no
/// other: a URL that names another server (`smtp://me@elsewhere/…`) must
/// not be handed it.
fn configured_password(server: &Location, cfg: &crate::Config) -> Option<SecretString> {
    let pw = cfg.resolved.mail_password.as_ref()?;
    let configured = Location::parse(cfg.mail.smtp.as_deref()?).ok()?;
    let same_host = match (server.host(), configured.host()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    };
    let port = |l: &Location| {
        l.port()
            .or_else(|| tls_mode(l).ok().map(SmtpTls::default_port))
    };
    (same_host && port(server) == port(&configured)).then(|| pw.clone())
}

pub struct MailEndpoint {
    loc: Location,
}

/// Resolved SMTP connection parameters.
struct SmtpConfig {
    server: Location,
    tls: SmtpTls,
    insecure: bool,
    /// `?timeout=`, of the target URL or else of the server's.
    timeout: Option<std::time::Duration>,
    /// Which SASL mechanisms to offer; `None` leaves lettre's choice alone.
    auth: Option<Vec<Mechanism>>,
}

/// `?auth=` — which SASL mechanism to log in with. `xoauth2` is what
/// Microsoft 365 and Google want now that they have switched basic
/// authentication off: the "password" is then an access token.
fn auth_mechanisms(value: Option<&str>) -> Result<Option<Vec<Mechanism>>> {
    let Some(v) = value else {
        return Ok(None);
    };
    Ok(Some(match v.trim().to_ascii_lowercase().as_str() {
        "" | "auto" | "default" => return Ok(None),
        "xoauth2" | "oauth2" | "oauth" => vec![Mechanism::Xoauth2],
        "plain" => vec![Mechanism::Plain],
        "login" => vec![Mechanism::Login],
        other => {
            return Err(Error::invalid_option(
                "auth",
                format!("expected xoauth2|plain|login|auto, got '{other}'"),
            ));
        }
    }))
}

impl MailEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        crate::init_crypto();
        if loc.recipients().is_empty() {
            return Err(Error::InvalidUrl("mail: no recipient".into()));
        }
        Ok(MailEndpoint { loc })
    }

    /// Resolve the SMTP server: the URL itself for `smtp://`, `MPT_SMTP_URL` for `mailto:`.
    fn smtp_config(&self) -> Result<SmtpConfig> {
        let mut server = match self.loc.scheme() {
            Scheme::Smtp | Scheme::Smtps => self.loc.clone(),
            _ => {
                let url = std::env::var("MPT_SMTP_URL")
                    .ok()
                    .or_else(|| crate::config::global().mail.smtp.clone())
                    .ok_or_else(|| {
                        Error::Config(
                            "mailto: requires MPT_SMTP_URL or [mail] smtp in the configuration \
                             (e.g. smtp://user@mail.example.com:587?tls=starttls)"
                                .into(),
                        )
                    })?;
                let mut s = Location::parse(&url)?;
                if !s.scheme().is_smtp() {
                    return Err(Error::InvalidUrl(format!(
                        "MPT_SMTP_URL must be an smtp:// or smtps:// URL, got '{}'",
                        s.scheme()
                    )));
                }
                s.apply_env();
                s
            }
        };
        let cfg = crate::config::global();
        if server.password().is_none()
            && let Some(pw) = configured_password(&server, &cfg)
        {
            server.set_password(pw.expose_secret());
        }
        // A recipient behind a relay asks its client for the server's
        // password; the server it resolves to must ask the same way.
        if server.brokers().is_empty() {
            server.set_brokers(self.loc.brokers().clone());
        }
        server.host_required()?;
        // The recipient URL was checked in `open`; the server it resolves to
        // carries the credentials, so it needs the same look.
        crate::policy::check_credentials(&server)?;
        let tls = tls_mode(&server)?;
        let timeout = match self.loc.opt("timeout") {
            Some(_) => self.loc.timeout()?,
            None => server.timeout()?,
        };
        let insecure = self
            .loc
            .opt_bool("insecure")?
            .or(server.opt_bool("insecure")?)
            .unwrap_or(false);
        let auth = auth_mechanisms(
            self.loc
                .opt("auth")
                .or_else(|| server.opt("auth"))
                .or_else(|| cfg.mail.auth.as_deref()),
        )?;
        Ok(SmtpConfig {
            server,
            tls,
            insecure,
            timeout,
            auth,
        })
    }

    fn max_attachment(&self) -> u64 {
        std::env::var("MPT_MAIL_MAX_ATTACHMENT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| {
                let cfg = crate::config::global();
                let v = cfg.mail.max_attachment.as_deref()?;
                crate::config::parse_size(v)
                    .map_err(|e| tracing::warn!("[mail] max_attachment: {e}"))
                    .ok()
            })
            .unwrap_or(DEFAULT_MAX_ATTACHMENT)
    }

    /// The password is fetched here, for this transport only.
    async fn transport(&self, cfg: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let host = cfg.server.host_required()?;
        let port = cfg.server.port().unwrap_or(cfg.tls.default_port());
        let tls = match cfg.tls {
            SmtpTls::None => Tls::None,
            mode => {
                let params = TlsParameters::builder(host.to_string())
                    .dangerous_accept_invalid_certs(cfg.insecure)
                    .build()
                    .map_err(|e| Error::transport("smtp", e))?;
                match mode {
                    SmtpTls::Implicit => Tls::Wrapper(params),
                    SmtpTls::Opportunistic => Tls::Opportunistic(params),
                    _ => Tls::Required(params),
                }
            }
        };
        let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .tls(tls)
            .timeout(cfg.timeout);
        if let Some(user) = cfg.server.username() {
            // For XOAUTH2 the "password" is the access token; lettre wraps it
            // in the user=…\x01auth=Bearer …\x01\x01 string itself.
            let secret = cfg.server.login_password(1).await?;
            let secret = secret.as_ref().map(|p| p.expose_secret()).unwrap_or("");
            b = b.credentials(Credentials::new(user.to_string(), secret.to_string()));
        }
        if let Some(mechanisms) = &cfg.auth {
            debug!(?mechanisms, "smtp authentication");
            b = b.authentication(mechanisms.clone());
        }
        Ok(b.build())
    }

    /// The first option value from the target URL, falling back to the server URL.
    fn opt<'a>(&'a self, server: &'a Location, name: &str) -> Option<&'a str> {
        self.loc.opt(name).or_else(|| server.opt(name))
    }

    fn sender_address(&self, server: &Location) -> Result<Mailbox> {
        let from = self
            .opt(server, "from")
            .map(String::from)
            .or_else(|| std::env::var("MPT_MAIL_FROM").ok())
            .or_else(|| crate::config::global().mail.from.clone())
            .or_else(|| {
                server
                    .username()
                    .filter(|u| u.contains('@'))
                    .map(String::from)
            })
            .ok_or_else(|| {
                Error::InvalidUrl(
                    "mail: no sender (use ?from=, MPT_MAIL_FROM or an e-mail address as SMTP user)"
                        .into(),
                )
            })?;
        parse_mailbox(&from)
    }
}

fn parse_mailbox(s: &str) -> Result<Mailbox> {
    s.trim()
        .parse::<Mailbox>()
        .map_err(|e| Error::InvalidUrl(format!("mail: bad address '{s}': {e}")))
}

fn split_addresses(s: &str) -> impl Iterator<Item = &str> {
    s.split([',', ';']).map(str::trim).filter(|a| !a.is_empty())
}

impl Endpoint for MailEndpoint {
    fn location(&self) -> &Location {
        &self.loc
    }
    fn as_receiver(&self) -> Option<&dyn Receiver> {
        None
    }
    fn as_sender(&self) -> Option<&dyn Sender> {
        Some(self)
    }
}

#[async_trait]
impl Sender for MailEndpoint {
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    fn places_sidecar(&self) -> bool {
        false
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let cfg = self.smtp_config()?;
        let server = &cfg.server;
        let filename = self
            .opt(server, "filename")
            .map(String::from)
            .unwrap_or_else(|| meta.filename_or("attachment.bin").to_string());
        let subject = self
            .opt(server, "subject")
            .map(String::from)
            .unwrap_or_else(|| filename.clone());
        let text = self
            .opt(server, "body")
            .map(String::from)
            .unwrap_or_else(|| format!("Attached: {filename}\n"));

        let data = stream::read_to_vec(body, self.max_attachment()).await?;
        let content_type = ContentType::parse(&meta.mime())
            .unwrap_or(ContentType::parse("application/octet-stream").unwrap());
        // The stream is fully read now, so a digest computed upstream is final.
        let checksum = meta
            .digest
            .as_ref()
            .and_then(|d| d.get().map(|hex| (d.algo(), hex)));
        let text = match &checksum {
            Some((algo, hex)) => format!("{text}\n{}: {hex}\n", algo.label()),
            None => text,
        };

        let mut msg = Message::builder()
            .from(self.sender_address(server)?)
            .subject(subject);
        for to in self.loc.recipients() {
            msg = msg.to(parse_mailbox(&to)?);
        }
        for cc in self.opt(server, "cc").into_iter().flat_map(split_addresses) {
            msg = msg.cc(parse_mailbox(cc)?);
        }
        for bcc in self
            .opt(server, "bcc")
            .into_iter()
            .flat_map(split_addresses)
        {
            msg = msg.bcc(parse_mailbox(bcc)?);
        }
        let mut parts = MultiPart::mixed()
            .singlepart(SinglePart::plain(text))
            .singlepart(Attachment::new(filename.clone()).body(data, content_type));
        if let Some((algo, hex)) = &checksum {
            let sidecar = algo.sidecar_name(&filename);
            let content = crate::hash::sidecar_content_at(
                hex,
                &filename,
                meta.signer.as_ref().map(|_| std::time::SystemTime::now()),
            );
            parts = parts.singlepart(
                Attachment::new(sidecar.clone()).body(content.clone(), ContentType::TEXT_PLAIN),
            );
            // Detached signature over the checksum file as a third attachment.
            if let Some(signer) = &meta.signer {
                let sig = signer.sign(content.as_bytes()).await?;
                let sig_name = signer.format().signature_name(&sidecar);
                parts =
                    parts.singlepart(Attachment::new(sig_name).body(sig, ContentType::TEXT_PLAIN));
            }
        }
        let email = msg
            .multipart(parts)
            .map_err(|e| Error::transport("mail", e))?;

        let transport = self.transport(&cfg).await?;
        debug!(%server, to = ?self.loc.recipients(), %filename, "smtp send");
        let resp = transport.send(email).await.map_err(|e| {
            let s = e.to_string();
            if s.contains("authentication") || s.contains("535") {
                Error::Auth(format!("smtp: {s}"))
            } else {
                Error::transport("smtp", e)
            }
        })?;
        info!(code = %resp.code(), "mail accepted by server");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_login_mechanism_can_be_chosen() {
        assert_eq!(auth_mechanisms(None).unwrap(), None);
        assert_eq!(auth_mechanisms(Some("auto")).unwrap(), None);
        assert_eq!(
            auth_mechanisms(Some("XOAUTH2")).unwrap(),
            Some(vec![Mechanism::Xoauth2])
        );
        assert_eq!(
            auth_mechanisms(Some("login")).unwrap(),
            Some(vec![Mechanism::Login])
        );
        let err = auth_mechanisms(Some("ntlm")).unwrap_err().to_string();
        assert!(err.contains("xoauth2"), "{err}");
    }

    #[test]
    fn the_url_chooses_before_the_server_and_the_configuration() {
        let ep = MailEndpoint::new(
            Location::parse("smtp://user@mail.example.com:587/a@b.c?auth=xoauth2").unwrap(),
        )
        .unwrap();
        let cfg = ep.smtp_config().unwrap();
        assert_eq!(cfg.auth, Some(vec![Mechanism::Xoauth2]));

        // Nothing said: lettre picks what the server offers.
        let ep =
            MailEndpoint::new(Location::parse("smtp://user@mail.example.com:587/a@b.c").unwrap())
                .unwrap();
        assert_eq!(ep.smtp_config().unwrap().auth, None);
    }

    fn tls_of(url: &str) -> SmtpTls {
        MailEndpoint::new(Location::parse(url).unwrap())
            .unwrap()
            .smtp_config()
            .unwrap()
            .tls
    }

    /// Port 25 without `?tls=` upgrades where the server offers it, and
    /// `?timeout=` of the target wins over the server's.
    #[test]
    fn port_25_tries_starttls_and_the_timeout_is_honoured() {
        assert_eq!(
            tls_of("smtp://relay.example.com:25/a@b.c"),
            SmtpTls::Opportunistic
        );
        assert_eq!(
            tls_of("smtp://relay.example.com:25/a@b.c?tls=none"),
            SmtpTls::None
        );
        let timeout = |url: &str| {
            MailEndpoint::new(Location::parse(url).unwrap())
                .unwrap()
                .smtp_config()
                .unwrap()
                .timeout
        };
        let secs = |n| Some(std::time::Duration::from_secs(n));
        assert_eq!(timeout("smtp://h/a@b.c"), secs(30));
        assert_eq!(timeout("smtp://h/a@b.c?timeout=5"), secs(5));
        assert_eq!(timeout("smtp://h/a@b.c?timeout=0"), None);
    }

    /// `[mail] password` goes to the server `[mail] smtp` names only.
    #[test]
    fn the_configured_password_stays_with_its_server() {
        let mut cfg =
            crate::Config::parse("[mail]\nsmtp = \"smtp://me@Mail.Example.com/?tls=starttls\"\n")
                .unwrap();
        cfg.resolved.mail_password = Some(SecretString::from("pw"));
        let pw = |url: &str, cfg: &crate::Config| {
            configured_password(&Location::parse(url).unwrap(), cfg).is_some()
        };
        assert!(pw("smtp://me@mail.example.com/a@b.c", &cfg));
        assert!(pw("smtp://other@mail.example.com:587/a@b.c", &cfg));
        assert!(!pw("smtp://me@attacker.example:25/a@b.c", &cfg));
        assert!(
            !pw("smtp://me@mail.example.com:25/a@b.c", &cfg),
            "another port"
        );
        assert!(
            !pw("smtps://me@mail.example.com/a@b.c", &cfg),
            "465 is another port"
        );
        cfg.mail.smtp = None;
        assert!(!pw("smtp://me@mail.example.com/a@b.c", &cfg));
    }

    /// `smtps://` is implicit TLS, on 465 unless the URL names a port.
    #[test]
    fn smtps_means_implicit_tls() {
        assert_eq!(tls_of("smtps://mail.example.com/a@b.c"), SmtpTls::Implicit);
        assert_eq!(
            tls_of("SMTPS://mail.example.com:2465/a@b.c"),
            SmtpTls::Implicit
        );
        assert_eq!(tls_of("smtp://mail.example.com/a@b.c"), SmtpTls::StartTls);
        assert_eq!(
            tls_of("smtp://mail.example.com:465/a@b.c"),
            SmtpTls::Implicit
        );
        assert_eq!(
            Location::parse("smtps://mail.example.com/a@b.c")
                .unwrap()
                .port_or_default(),
            465
        );
    }
}
