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
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{debug, info};

use crate::{
    ByteStream, Endpoint, Error, Location, Receiver, Result, Scheme, SendMeta, Sender, stream,
};

const DEFAULT_MAX_ATTACHMENT: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpTls {
    StartTls,
    Implicit,
    None,
}

pub struct MailEndpoint {
    loc: Location,
}

/// Resolved SMTP connection parameters.
struct SmtpConfig {
    server: Location,
    tls: SmtpTls,
    insecure: bool,
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
        let server = match self.loc.scheme() {
            Scheme::Smtp => self.loc.clone(),
            _ => {
                let url = std::env::var("MPT_SMTP_URL").map_err(|_| {
                    Error::Auth("mailto: requires MPT_SMTP_URL (e.g. smtp://user@mail.example.com:587?tls=starttls)".into())
                })?;
                let mut s = Location::parse(&url)?;
                if s.scheme() != Scheme::Smtp {
                    return Err(Error::InvalidUrl(format!(
                        "MPT_SMTP_URL must be an smtp:// URL, got '{}'",
                        s.scheme()
                    )));
                }
                s.apply_env();
                s
            }
        };
        server.host_required()?;
        let tls = match server.opt("tls").map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("starttls") | Some("required") => SmtpTls::StartTls,
            Some("implicit") | Some("wrapper") | Some("tls") => SmtpTls::Implicit,
            Some("none") | Some("off") | Some("false") => SmtpTls::None,
            None => match server.port() {
                Some(465) => SmtpTls::Implicit,
                Some(25) => SmtpTls::None,
                _ => SmtpTls::StartTls,
            },
            Some(other) => {
                return Err(Error::invalid_option(
                    "tls",
                    format!("expected starttls|implicit|none, got '{other}'"),
                ));
            }
        };
        let insecure = self
            .loc
            .opt_bool("insecure")?
            .or(server.opt_bool("insecure")?)
            .unwrap_or(false);
        Ok(SmtpConfig {
            server,
            tls,
            insecure,
        })
    }

    fn max_attachment(&self) -> u64 {
        std::env::var("MPT_MAIL_MAX_ATTACHMENT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_ATTACHMENT)
    }

    fn transport(&self, cfg: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let host = cfg.server.host_required()?;
        let port = cfg.server.port().unwrap_or(match cfg.tls {
            SmtpTls::Implicit => 465,
            SmtpTls::None => 25,
            SmtpTls::StartTls => 587,
        });
        let tls = match cfg.tls {
            SmtpTls::None => Tls::None,
            mode => {
                let params = TlsParameters::builder(host.to_string())
                    .dangerous_accept_invalid_certs(cfg.insecure)
                    .build()
                    .map_err(|e| Error::transport("smtp", e))?;
                if mode == SmtpTls::Implicit {
                    Tls::Wrapper(params)
                } else {
                    Tls::Required(params)
                }
            }
        };
        let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .tls(tls);
        if let Some(user) = cfg.server.username() {
            let pw = cfg.server.password().unwrap_or("").to_string();
            b = b.credentials(Credentials::new(user.to_string(), pw));
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
            let content = crate::hash::sidecar_content(hex, &filename);
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

        let transport = self.transport(&cfg)?;
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
