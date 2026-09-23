//! Configuration file: defaults for the flags, security policies and
//! per-protocol settings.
//!
//! The file is TOML and is looked up in this order, the first hit wins:
//!
//! 1. `--config <path>` (an error if it does not exist)
//! 2. `$MPT_CONFIG` (likewise)
//! 3. `$XDG_CONFIG_HOME/mpt/config.toml`, else `~/.config/mpt/config.toml`
//!
//! In addition, `./mpt.toml` in the working directory contributes
//! `[defaults]` and `[policy]` and wins over the user file; every other
//! section in it is ignored with a warning, because a directory one happens
//! to stand in must not silently redirect a transfer.
//!
//! It never overrides what a caller says explicitly. The order is
//!
//! ```text
//! CLI flag  >  URL option  >  environment variable  >  configuration  >  built-in
//! ```
//!
//! String values may contain `${VAR}`, which is replaced by the environment
//! variable of that name (an error if it is unset), and paths may start with
//! `~/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use secrecy::SecretString;
use serde::Deserialize;
use tracing::debug;

use crate::credentials::Secret;
use crate::{Error, Location, Result};

/// The whole configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub policy: PolicySection,
    #[serde(default)]
    pub signing: SigningSection,
    #[serde(default)]
    pub verify: VerifySection,
    #[serde(default)]
    pub ssh: SshSection,
    #[serde(default)]
    pub mail: MailSection,
    #[serde(default)]
    pub s3: S3Section,
    #[serde(default)]
    pub http: HttpSection,
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub relay: RelaySection,
    /// Named targets, addressed as `mpt://<name>/<path>`.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    /// The secrets the sections above refer to, once they have been fetched
    /// (see [`Config::resolve_secrets`]).
    #[serde(skip)]
    pub resolved: Resolved,
    /// Which files it was read from; empty for the built-in defaults.
    #[serde(skip)]
    pub sources: Vec<PathBuf>,
    /// Complaints collected while loading. They are kept rather than logged
    /// because the configuration decides the log level in the first place.
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// `[defaults]` — values for flags that are not given on the command line.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// `auto`, `always` or `never`.
    pub color: Option<String>,
    /// Checksum algorithm for `--hash`.
    pub hash: Option<String>,
    pub cache: Option<bool>,
    /// Size with a unit, e.g. `256M`.
    pub cache_limit: Option<String>,
    pub retries: Option<u32>,
    pub chunk: Option<String>,
    pub queue: Option<usize>,
    /// Inactivity timeout in seconds; `0` disables it.
    pub timeout: Option<u64>,
    /// Finish transfers through a `.mpt-part` file.
    pub atomic: Option<bool>,
    /// Continue an interrupted transfer from what is in the `.mpt-part` file.
    pub resume: Option<bool>,
    /// Leave targets alone that already hold a file of the same name and size.
    pub skip_existing: Option<bool>,
    /// Delete the source once every target has it.
    pub delete_source: Option<bool>,
    /// Log level, either a bare level or `RUST_LOG` syntax.
    pub log: Option<String>,
    /// Print the report as JSON on standard output.
    pub json: Option<bool>,
    /// Jobs in flight at once for `cp -t` and `batch`.
    pub parallel: Option<usize>,
    /// The relay `cp` and `batch` send through unless `--no-via` says
    /// otherwise: an `ssh://` URL or a profile with one. Not taken from a
    /// working directory's file, which would otherwise choose where every
    /// target's credentials go.
    pub via: Option<String>,
    /// How the relay gets the targets' passwords: `header` (in the URLs
    /// it is sent, the default) or `on-demand` (asked of this side at
    /// every login, never held). The relay has to allow it as well.
    pub via_credentials: Option<String>,
    /// Forward an ssh-agent to the relay, so it authenticates against the
    /// SSH targets with this side's keys and certificates (default true).
    pub via_agent: Option<bool>,
}

/// `[policy]` — rules that hold for every endpoint of the process.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    /// Default host-key policy for SSH: `strict`, `accept-new` or `off`.
    pub known_hosts: Option<String>,
    pub refuse_plaintext_auth: Option<bool>,
    /// Refuse `?insecure=true` instead of honouring it.
    pub refuse_insecure_tls: Option<bool>,
    /// `--check` must also verify a signature.
    pub require_signature: Option<bool>,
    /// A configuration file with credentials that others can read is an
    /// error, not a warning.
    pub strict_permissions: Option<bool>,
    /// How old a signature may be, judged against the signing time in the
    /// checksum file: `7d`, `24h`, `30m`, `0` for no limit.
    pub max_signature_age: Option<String>,
}

/// `[signing]` — defaults for `--sign`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSection {
    /// Signing key in the `--sign` syntax: `ssh`, `ssh:<file>`, `pgp:<file>`.
    pub key: Option<String>,
    /// Which ssh-agent identity to sign with (`SHA256:…`).
    pub agent_fingerprint: Option<String>,
    /// Passphrase of the signing key.
    pub passphrase: Option<Secret>,
}

/// `[verify]` — defaults for `--verify-signers` / `--verify-keyring`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifySection {
    pub allowed_signers: Option<String>,
    pub keyring: Option<String>,
}

/// `[ssh]` — defaults for `sftp://` and `scp://`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshSection {
    pub user: Option<String>,
    pub key: Option<String>,
    /// OpenSSH certificate for the key (`<key>-cert.pub` is found on its own).
    pub cert: Option<String>,
    /// Passphrase of the private key.
    pub passphrase: Option<Secret>,
    pub known_hosts_file: Option<String>,
    /// Pinned host-key fingerprints, one string or a list.
    #[serde(default, deserialize_with = "string_or_list")]
    pub hostkey: Vec<String>,
}

/// `[mail]` — defaults for `mailto:` and `smtp://`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailSection {
    /// SMTP server for `mailto:` targets, e.g. `smtp://user@host:587?tls=starttls`.
    pub smtp: Option<String>,
    /// Password for the SMTP server, or the access token with `auth = "xoauth2"`.
    pub password: Option<Secret>,
    /// SASL mechanism: `xoauth2`, `plain`, `login` or `auto`.
    pub auth: Option<String>,
    pub from: Option<String>,
    /// Attachment size limit with a unit, e.g. `25M`.
    pub max_attachment: Option<String>,
}

/// `[http]` — defaults for `http://`, `https://` and WebDAV.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSection {
    /// OAuth2 bearer token, sent as `Authorization: Bearer …`.
    pub token: Option<Secret>,
}

/// `[server]` — settings for `mpt serve`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Address to listen on, `127.0.0.1:7788` by default.
    pub bind: Option<String>,
    /// The bearer token every request must carry. Without one, only a
    /// loopback address may be bound.
    pub token: Option<Secret>,
    /// JSONL file that records submitted jobs, so those still open when
    /// the server stops are run again after a restart.
    pub journal: Option<String>,
    /// How long finished jobs stay available: `24h`, `7d`, `0` for until
    /// the server stops.
    pub retention: Option<String>,
    /// Transfers in flight at once, over all jobs.
    pub parallel: Option<usize>,
    /// Largest request body, with a unit: `8M`.
    pub max_body: Option<String>,
    /// How long a shutdown waits for running jobs before cancelling them.
    pub grace: Option<String>,
    /// Which URLs a job may name: `profiles` (only `mpt://<profile>/…`,
    /// the default) or `any`.
    pub urls: Option<UrlRule>,
    /// With `urls = "profiles"`: only these profiles; empty means all.
    #[serde(default, deserialize_with = "string_or_list")]
    pub profiles: Vec<String>,
    /// Let jobs delete their source (`delete_source`). Off by default:
    /// with a token alone one could empty every directory a profile reaches.
    pub allow_delete: Option<bool>,
    /// Transfers one job may hold after patterns and trees are expanded.
    pub max_transfers: Option<usize>,
    /// Jobs not yet finished before new ones are refused.
    pub max_queued: Option<usize>,
}

/// `[relay]` — settings for `mpt relay --listen`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySection {
    /// The server's host key; generated when the file is missing.
    pub host_key: Option<String>,
    /// OpenSSH `authorized_keys`: who may relay.
    pub authorized_keys: Option<String>,
    /// Relays running at once; further sessions wait.
    pub parallel: Option<usize>,
    /// How long a shutdown waits for running relays before cancelling them.
    pub grace: Option<String>,
    /// Refuse uploads larger than this, with a unit: `10G`; 0 for no limit.
    pub max_size: Option<String>,
    /// Which way a client may send the targets' passwords: `header` (the
    /// default), `on-demand` or `any`.
    pub credentials: Option<String>,
    /// Take the agent a client forwards (default true).
    pub agent_forwarding: Option<bool>,
}

/// Which URLs the server accepts in a job.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlRule {
    /// Only `mpt://<profile>/…`: the configuration decides what the API
    /// can reach, and no credential travels in a URL.
    #[default]
    Profiles,
    /// Any URL the command line would take.
    Any,
}

impl std::fmt::Display for UrlRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UrlRule::Profiles => "profiles",
            UrlRule::Any => "any",
        })
    }
}

/// `[s3]` — defaults for `s3://`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Section {
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub path_style: Option<bool>,
    pub access_key_id: Option<Secret>,
    pub secret_access_key: Option<Secret>,
    /// AWS profile to take credentials from (feature `s3-aws-auth`).
    pub profile: Option<String>,
}

/// The secrets of the sections above, fetched from their providers.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub ssh_passphrase: Option<SecretString>,
    pub signing_passphrase: Option<SecretString>,
    pub mail_password: Option<SecretString>,
    pub http_token: Option<SecretString>,
    pub s3_access_key_id: Option<SecretString>,
    pub s3_secret_access_key: Option<SecretString>,
    /// Passwords of the profiles that were asked for, by profile name.
    pub profile_passwords: BTreeMap<String, SecretString>,
}

/// `[profiles.<name>]` — a named target.
///
/// Besides the reserved keys below, every entry becomes a URL option of the
/// resolved location, so a profile can carry anything the scheme understands
/// (`key`, `known_hosts`, `hostkey`, `timeout`, `tls`, `subject`, …).
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// The endpoint this profile stands for.
    pub url: String,
    /// Password for this endpoint.
    pub password: Option<Secret>,
    /// Sign checksum files written to this target (`--sign` syntax).
    pub sign: Option<String>,
    /// Checksum algorithm for this target.
    pub hash: Option<String>,
    /// Finish through a `.mpt-part` file.
    pub atomic: Option<bool>,
    /// The relay this endpoint is reached through (an `ssh://` URL or a
    /// profile with one), instead of `[defaults] via`. A source with one
    /// is read by that relay, a target with one written by it.
    pub via: Option<String>,
    #[serde(flatten)]
    options: BTreeMap<String, toml::Value>,
}

impl Profile {
    /// The free-form entries as URL options, in the file's order. A value may
    /// be a list, which repeats the option (`hostkey`, `header`).
    pub fn options(&self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for (k, v) in &self.options {
            match v {
                toml::Value::Array(items) => {
                    for item in items {
                        out.push((k.clone(), scalar(k, item)?));
                    }
                }
                other => out.push((k.clone(), scalar(k, other)?)),
            }
        }
        Ok(out)
    }
}

/// Put `pairs` on the location, replacing every value the location already
/// had for those keys. Repeated keys (`hostkey`, `header`) keep all their new
/// values.
fn override_options(loc: &mut Location, pairs: Vec<(String, String)>) {
    for (k, _) in &pairs {
        loc.remove_option(k);
    }
    for (k, v) in pairs {
        loc.set_option(k, v);
    }
}

/// A profile option must be something that can stand in a URL.
fn scalar(key: &str, v: &toml::Value) -> Result<String> {
    Ok(match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        other => {
            return Err(Error::Config(format!(
                "profile option '{key}' must be a string, number or boolean, not {}",
                other.type_str()
            )));
        }
    })
}

/// The prefix that addresses a profile instead of a protocol.
pub const PROFILE_PREFIX: &str = "mpt://";

impl Config {
    /// Turn `mpt://<profile>/<path>?<options>` into the location the profile
    /// stands for. `Ok(None)` for every other URL.
    ///
    /// The path is appended to the profile's own path, and options of the
    /// reference replace those of the profile.
    pub fn resolve(&self, url: &str) -> Result<Option<Location>> {
        let Some(rest) = strip_profile_prefix(url) else {
            return Ok(None);
        };
        // A fragment is not part of the address, as in any other URL.
        let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
        let (head, query) = match rest.split_once('?') {
            Some((h, q)) => (h, Some(q)),
            None => (rest, None),
        };
        let (name, path) = match head.split_once('/') {
            Some((n, p)) => (n, p),
            None => (head, ""),
        };
        let profile = self.profiles.get(name).ok_or_else(|| {
            let known: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
            Error::Config(match known.is_empty() {
                true => format!("no profile '{name}' (the configuration defines none)"),
                false => format!("no profile '{name}' (known: {})", known.join(", ")),
            })
        })?;
        if is_profile_ref(&profile.url) {
            return Err(Error::Config(format!(
                "profile '{name}' points at another profile ({}); profiles do not chain",
                profile.url
            )));
        }
        let mut loc = Location::parse(&profile.url)
            .map_err(|e| Error::Config(format!("profile '{name}': {e}")))?;
        // The path is percent-decoded like the path of any URL, and before
        // it is checked: `%2e%2e` is `..` to every HTTP server.
        if !path.is_empty() {
            loc = loc
                .join_url_path(path)
                .map_err(|e| Error::Config(format!("mpt://{name}/{path}: {e}")))?;
        }
        if let Some(pw) = self.resolved.profile_passwords.get(name)
            && !loc.password_in_url()
        {
            use secrecy::ExposeSecret;
            loc.set_password(pw.expose_secret());
        }
        loc.set_profile(name);
        override_options(&mut loc, profile.options()?);
        if let Some(q) = query {
            override_options(&mut loc, crate::location::parse_query(q));
        }
        debug!(%name, %loc, "profile resolved");
        Ok(Some(loc))
    }

    /// Read the configuration, following the search order of the module docs.
    pub fn load(explicit: Option<&Path>) -> Result<Config> {
        let mut cfg = match Config::user_file(explicit)? {
            Some(path) => Config::read(&path)?,
            None => Config::default(),
        };
        if let Some(local) = Config::local_file()
            && let Some(mut over) = Config::read_local(&local)?
        {
            cfg.merge(&mut over);
        }
        Ok(cfg)
    }

    /// Which file to read, or `None` when there is no configuration at all.
    fn user_file(explicit: Option<&Path>) -> Result<Option<PathBuf>> {
        if let Some(p) = explicit {
            return if p.exists() {
                Ok(Some(p.to_path_buf()))
            } else {
                Err(Error::Config(format!("{} does not exist", p.display())))
            };
        }
        if let Some(p) = std::env::var_os("MPT_CONFIG").filter(|v| !v.is_empty()) {
            let p = PathBuf::from(expand_tilde(&p.to_string_lossy()));
            return if p.exists() {
                Ok(Some(p))
            } else {
                Err(Error::Config(format!(
                    "MPT_CONFIG points at {}, which does not exist",
                    p.display()
                )))
            };
        }
        Ok(Config::default_path().filter(|p| p.exists()))
    }

    /// `$XDG_CONFIG_HOME/mpt/config.toml`, else `~/.config/mpt/config.toml`.
    pub fn default_path() -> Option<PathBuf> {
        let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(v) => PathBuf::from(v),
            None => std::env::home_dir()?.join(".config"),
        };
        Some(base.join("mpt").join("config.toml"))
    }

    fn local_file() -> Option<PathBuf> {
        let p = PathBuf::from("mpt.toml");
        p.exists().then_some(p)
    }

    /// Read `./mpt.toml`, keeping only the sections that are safe to take
    /// from the working directory.
    fn read_local(path: &Path) -> Result<Option<Config>> {
        let cfg = Config::read(path)?;
        let ignored = cfg.non_local_sections();
        // An allow-list, not a strip-list: what a working directory may
        // contribute is named here and nothing else survives, so a section
        // added to `Config` later is dropped until someone decides otherwise.
        // The reverse — dropping the sections we happened to think of — let
        // [profiles] and [http] through, and a profile carries both a target
        // and a `cmd` credential provider.
        let mut local = Config {
            defaults: cfg.defaults,
            policy: cfg.policy,
            sources: cfg.sources,
            warnings: cfg.warnings,
            ..Config::default()
        };
        let via_keys = [
            ("via", local.defaults.via.take().is_some()),
            (
                "via_credentials",
                local.defaults.via_credentials.take().is_some(),
            ),
            ("via_agent", local.defaults.via_agent.take().is_some()),
        ];
        for (key, set) in via_keys {
            if set {
                local.warnings.push(format!(
                    "{}: ignoring [defaults] {key} — a configuration file in the working \
                     directory may not choose the relay that receives the targets' credentials",
                    path.display()
                ));
            }
        }
        if !ignored.is_empty() {
            local.warnings.push(format!(
                "{}: ignoring [{}] — a configuration file in the working directory \
                 only contributes [defaults] and [policy]",
                path.display(),
                ignored.join("], [")
            ));
        }
        Ok(Some(local))
    }

    /// Sections that `./mpt.toml` is not allowed to set.
    fn non_local_sections(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let SigningSection {
            key,
            agent_fingerprint,
            passphrase,
        } = &self.signing;
        if key.is_some() || agent_fingerprint.is_some() || passphrase.is_some() {
            out.push("signing");
        }
        let VerifySection {
            allowed_signers,
            keyring,
        } = &self.verify;
        if allowed_signers.is_some() || keyring.is_some() {
            out.push("verify");
        }
        let SshSection {
            user,
            key,
            cert,
            passphrase,
            known_hosts_file,
            hostkey,
        } = &self.ssh;
        if user.is_some()
            || key.is_some()
            || cert.is_some()
            || passphrase.is_some()
            || known_hosts_file.is_some()
            || !hostkey.is_empty()
        {
            out.push("ssh");
        }
        let MailSection {
            smtp,
            password,
            auth,
            from,
            max_attachment,
        } = &self.mail;
        if smtp.is_some()
            || password.is_some()
            || auth.is_some()
            || from.is_some()
            || max_attachment.is_some()
        {
            out.push("mail");
        }
        let S3Section {
            endpoint,
            region,
            path_style,
            access_key_id,
            secret_access_key,
            profile,
        } = &self.s3;
        if endpoint.is_some()
            || region.is_some()
            || path_style.is_some()
            || access_key_id.is_some()
            || secret_access_key.is_some()
            || profile.is_some()
        {
            out.push("s3");
        }
        let HttpSection { token } = &self.http;
        if token.is_some() {
            out.push("http");
        }
        let ServerSection {
            bind,
            token,
            journal,
            retention,
            parallel,
            max_body,
            grace,
            urls,
            profiles,
            allow_delete,
            max_transfers,
            max_queued,
        } = &self.server;
        if bind.is_some()
            || allow_delete.is_some()
            || max_transfers.is_some()
            || max_queued.is_some()
            || token.is_some()
            || journal.is_some()
            || retention.is_some()
            || parallel.is_some()
            || max_body.is_some()
            || grace.is_some()
            || urls.is_some()
            || !profiles.is_empty()
        {
            out.push("server");
        }
        let RelaySection {
            host_key,
            authorized_keys,
            parallel,
            grace,
            max_size,
            credentials,
            agent_forwarding,
        } = &self.relay;
        if host_key.is_some()
            || authorized_keys.is_some()
            || parallel.is_some()
            || grace.is_some()
            || max_size.is_some()
            || credentials.is_some()
            || agent_forwarding.is_some()
        {
            out.push("relay");
        }
        if !self.profiles.is_empty() {
            out.push("profiles");
        }
        out
    }

    /// Parse one file. Errors mention the path, so `mpt config check` can be
    /// pointed at any file.
    pub fn read(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
        let mut cfg =
            Config::parse(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        cfg.check_permissions(path)?;
        debug!(path = %path.display(), "configuration loaded");
        cfg.sources.push(path.to_path_buf());
        Ok(cfg)
    }

    /// Parse configuration text (no file, no environment lookup beyond the
    /// `${VAR}` interpolation).
    pub fn parse(text: &str) -> std::result::Result<Config, String> {
        let mut value: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        interpolate(&mut value)?;
        let cfg = Config::deserialize(value).map_err(|e| e.to_string())?;
        if let Some(v) = &cfg.policy.max_signature_age {
            parse_duration(v).map_err(|e| format!("[policy] max_signature_age: {e}"))?;
        }
        for (what, v) in [
            ("retention", &cfg.server.retention),
            ("grace", &cfg.server.grace),
        ] {
            if let Some(v) = v {
                parse_duration(v).map_err(|e| format!("[server] {what}: {e}"))?;
            }
        }
        if let Some(v) = &cfg.server.max_body {
            parse_size(v).map_err(|e| format!("[server] max_body: {e}"))?;
        }
        for (what, v) in [
            ("parallel", cfg.server.parallel),
            ("max_transfers", cfg.server.max_transfers),
            ("max_queued", cfg.server.max_queued),
        ] {
            if v == Some(0) {
                return Err(format!("[server] {what} must be at least 1"));
            }
        }
        Ok(cfg)
    }

    /// Take every value `other` sets; used to lay `./mpt.toml` over the user file.
    fn merge(&mut self, other: &mut Config) {
        macro_rules! take {
            ($($section:ident . $field:ident),* $(,)?) => {
                $(if other.$section.$field.is_some() {
                    self.$section.$field = other.$section.$field.take();
                })*
            };
        }
        take!(
            defaults.color,
            defaults.hash,
            defaults.cache,
            defaults.cache_limit,
            defaults.retries,
            defaults.chunk,
            defaults.queue,
            defaults.timeout,
            defaults.atomic,
            defaults.resume,
            defaults.log,
            defaults.json,
            policy.known_hosts,
            policy.refuse_plaintext_auth,
            policy.refuse_insecure_tls,
            policy.require_signature,
            policy.strict_permissions,
            policy.max_signature_age,
            signing.key,
            signing.agent_fingerprint,
            verify.allowed_signers,
            verify.keyring,
            ssh.user,
            ssh.key,
            ssh.cert,
            ssh.known_hosts_file,
            mail.smtp,
            mail.auth,
            mail.from,
            mail.max_attachment,
            s3.endpoint,
            s3.region,
            s3.path_style,
            s3.profile,
        );
        if !other.profiles.is_empty() {
            self.profiles.append(&mut other.profiles);
        }
        if !other.ssh.hostkey.is_empty() {
            self.ssh.hostkey = std::mem::take(&mut other.ssh.hostkey);
        }
        self.sources.append(&mut other.sources);
        self.warnings.append(&mut other.warnings);
    }

    /// Fetch the secrets the given URLs will need, and no others: a
    /// `cmd` provider starts a process, which should not happen for a
    /// profile or a protocol this run does not touch.
    ///
    /// Call it before [`install`]; the values then reach the protocols
    /// through [`Config::resolved`].
    pub async fn resolve_secrets(&mut self, urls: &[&str], signing: bool) -> Result<()> {
        let mut schemes = std::collections::HashSet::new();
        let mut names = Vec::new();
        // A profile's relay is one more endpoint to log in to.
        let mut urls: Vec<&str> = urls.to_vec();
        let vias: Vec<&str> = urls
            .iter()
            .filter_map(|u| self.profiles.get(profile_name(u)?)?.via.as_deref())
            .collect();
        urls.extend(vias);
        for url in urls {
            if let Some(name) = profile_name(url) {
                names.push(name.to_string());
            }
            let loc = match self.resolve(url) {
                Ok(Some(loc)) => Some(loc),
                Ok(None) => Location::parse(url).ok(),
                Err(_) => None, // an unusable URL is reported where it is opened
            };
            if let Some(loc) = loc {
                schemes.insert(loc.scheme());
            }
        }
        let uses = |wanted: &[crate::Scheme]| wanted.iter().any(|s| schemes.contains(s));
        // A profile can ask for signing on its own.
        let signing = signing
            || names
                .iter()
                .filter_map(|n| self.profiles.get(n))
                .any(|p| p.sign.is_some());

        for name in names {
            let Some(secret) = self.profiles.get(&name).and_then(|p| p.password.clone()) else {
                continue;
            };
            let pw = secret
                .resolve(&format!("password of profile '{name}'"))
                .await?;
            self.resolved.profile_passwords.insert(name, pw);
        }
        if uses(&[crate::Scheme::Sftp, crate::Scheme::Scp, crate::Scheme::Ssh])
            && let Some(s) = &self.ssh.passphrase
        {
            self.resolved.ssh_passphrase = Some(s.resolve("[ssh] passphrase").await?);
        }
        if uses(&[crate::Scheme::Mailto, crate::Scheme::Smtp])
            && let Some(s) = &self.mail.password
        {
            self.resolved.mail_password = Some(s.resolve("[mail] password").await?);
        }
        if uses(&[
            crate::Scheme::Http,
            crate::Scheme::Https,
            crate::Scheme::WebDav,
            crate::Scheme::WebDavs,
        ]) && let Some(s) = &self.http.token
        {
            self.resolved.http_token = Some(s.resolve("[http] token").await?);
        }
        if uses(&[crate::Scheme::S3]) {
            if let Some(s) = &self.s3.access_key_id {
                self.resolved.s3_access_key_id = Some(s.resolve("[s3] access_key_id").await?);
            }
            if let Some(s) = &self.s3.secret_access_key {
                self.resolved.s3_secret_access_key =
                    Some(s.resolve("[s3] secret_access_key").await?);
            }
        }
        if signing && let Some(s) = &self.signing.passphrase {
            self.resolved.signing_passphrase = Some(s.resolve("[signing] passphrase").await?);
        }
        Ok(())
    }

    /// Whether the file holds credentials, which decides how strictly its
    /// permissions are judged.
    fn holds_credentials(&self) -> bool {
        self.http.token.is_some()
            || self.server.token.is_some()
            || self.ssh.passphrase.is_some()
            || self.signing.passphrase.is_some()
            || self.mail.password.is_some()
            || self.s3.access_key_id.is_some()
            || self.s3.secret_access_key.is_some()
            || self.profiles.values().any(|p| p.password.is_some())
    }

    /// A file with credentials that others can read is a file that gives them
    /// away — even when it only points at a provider, because `cmd` runs what
    /// it says.
    fn check_permissions(&mut self, path: &Path) -> Result<()> {
        if !self.holds_credentials() {
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let Ok(md) = std::fs::metadata(path) else {
                return Ok(());
            };
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 == 0 {
                return Ok(());
            }
            let complaint = format!(
                "{} holds credentials and is readable by others (mode {mode:o}); chmod 600 it",
                path.display()
            );
            if self.policy.strict_permissions.unwrap_or(false) {
                return Err(Error::Config(complaint));
            }
            self.warnings.push(complaint);
        }
        // Windows: no mode bits, so the file's place has to do (see
        // crate::credentials::warn_if_world_readable).
        #[cfg(not(unix))]
        crate::credentials::warn_if_world_readable(path);
        Ok(())
    }

    /// The `[policy]` section as the process-wide policy, on top of what the
    /// environment already says.
    pub fn policy(&self) -> crate::policy::Policy {
        let mut p = crate::policy::Policy::from_env();
        if let Some(v) = self.policy.refuse_plaintext_auth {
            p.refuse_plaintext_auth = v;
        }
        if let Some(v) = self.policy.refuse_insecure_tls {
            p.refuse_insecure_tls = v;
        }
        if let Some(v) = self.policy.require_signature {
            p.require_signature = v;
        }
        if let Some(v) = self.policy.strict_permissions {
            p.strict_permissions = v;
        }
        if let Some(v) = &self.policy.max_signature_age {
            // Checked when the file is read; a bad value cannot reach here.
            p.max_signature_age = parse_duration(v).ok().filter(|d| !d.is_zero());
        }
        if let Some(v) = &self.policy.known_hosts {
            p.known_hosts = Some(v.clone());
        }
        p
    }
}

/// The installed configuration. Replaced as a whole by [`install`]; whoever
/// still holds the previous one keeps it until they drop it.
static GLOBAL: RwLock<Option<Arc<Config>>> = RwLock::new(None);

/// The configuration this process runs with. Empty unless [`install`] was
/// called, so the library keeps working without a configuration file.
pub fn global() -> Arc<Config> {
    if let Ok(g) = GLOBAL.read()
        && let Some(cfg) = &*g
    {
        return cfg.clone();
    }
    static EMPTY: OnceLock<Arc<Config>> = OnceLock::new();
    EMPTY.get_or_init(|| Arc::new(Config::default())).clone()
}

/// Parse a URL, resolving `mpt://<profile>/…` against the loaded
/// configuration first.
pub fn locate(url: &str) -> Result<Location> {
    match global().resolve(url)? {
        Some(loc) => Ok(loc),
        None => Location::parse(url),
    }
}

/// The profile a URL refers to, if it refers to one at all.
pub fn profile_of(url: &str) -> Option<Profile> {
    global().profiles.get(profile_name(url)?).cloned()
}

/// The profile name a `mpt://` URL names, without looking it up.
pub fn profile_name(url: &str) -> Option<&str> {
    strip_profile_prefix(url)?
        .split(['/', '?', '#'])
        .next()
        .filter(|n| !n.is_empty())
}

/// Whether `url` addresses a profile. The prefix is matched without regard
/// to case, as a URL scheme is.
pub fn is_profile_ref(url: &str) -> bool {
    strip_profile_prefix(url).is_some()
}

/// What follows `mpt://`, if `url` starts with it in any case.
fn strip_profile_prefix(url: &str) -> Option<&str> {
    let url = url.trim();
    let head = url.get(..PROFILE_PREFIX.len())?;
    head.eq_ignore_ascii_case(PROFILE_PREFIX)
        .then(|| &url[PROFILE_PREFIX.len()..])
}

impl Resolved {
    /// How many secrets are in hand; enough to tell whether a resolution
    /// pass found anything new.
    fn count(&self) -> usize {
        [
            &self.ssh_passphrase,
            &self.signing_passphrase,
            &self.mail_password,
            &self.http_token,
            &self.s3_access_key_id,
            &self.s3_secret_access_key,
        ]
        .iter()
        .filter(|s| s.is_some())
        .count()
            + self.profile_passwords.len()
    }
}

/// Fetch the secrets that `urls` need on top of what the installed
/// configuration already has, and publish the result. For endpoints that
/// turn up after the start (a job list read as it arrives); references
/// already fetched come from the process-wide cache, so this is cheap when
/// there is nothing new.
///
/// One resolution at a time: two that ran side by side (two submissions to
/// the server) would each start from the same configuration, and the one
/// published last would drop what the other fetched.
pub async fn resolve_more(urls: &[&str], signing: bool) -> Result<()> {
    static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _turn = ONE_AT_A_TIME.lock().await;
    let current = global();
    let mut cfg = Config::clone(&current);
    cfg.resolve_secrets(urls, signing).await?;
    if cfg.resolved.count() > current.resolved.count() {
        tracing::debug!("new credentials fetched, configuration republished");
        install(cfg);
    }
    Ok(())
}

/// Publish the loaded configuration for the rest of the process, and install
/// its `[policy]` section.
pub fn install(cfg: Config) {
    crate::policy::set_policy(cfg.policy());
    if let Ok(mut g) = GLOBAL.write() {
        *g = Some(Arc::new(cfg));
    }
}

/// Replace `${VAR}` in every string of the tree.
fn interpolate(value: &mut toml::Value) -> std::result::Result<(), String> {
    match value {
        toml::Value::String(s) => *s = expand_vars(s)?,
        toml::Value::Array(a) => {
            for v in a {
                interpolate(v)?;
            }
        }
        toml::Value::Table(t) => {
            for (_, v) in t.iter_mut() {
                interpolate(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn expand_vars(s: &str) -> std::result::Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find("${") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("unterminated ${{…}} in '{s}'"))?;
        let name = &after[..end];
        let v = std::env::var(name)
            .map_err(|_| format!("'{s}' refers to ${{{name}}}, which is not set"))?;
        out.push_str(&v);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Expand a leading `~/` (or `~\` on Windows) against the home directory.
pub fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p
        .strip_prefix("~/")
        .or_else(|| cfg!(windows).then(|| p.strip_prefix("~\\")).flatten())
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

/// Parse sizes like `512`, `64K`, `256M`, `2G` (binary units).
pub fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') => (&s[..s.len() - 1], 1u64 << 20),
        Some('G') => (&s[..s.len() - 1], 1u64 << 30),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|e| format!("invalid size '{s}': {e}"))
}

/// Parse spans like `90` (seconds), `30m`, `24h` or `7d`. `0` means "no
/// limit" and comes back as a zero duration.
pub fn parse_duration(s: &str) -> std::result::Result<std::time::Duration, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| std::time::Duration::from_secs(n * mult))
        .map_err(|e| format!("invalid duration '{s}': {e} (try 7d, 24h, 30m or 0)"))
}

/// A configured path, with `~/` expanded.
pub fn path(value: &Option<String>) -> Option<PathBuf> {
    value
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| PathBuf::from(expand_tilde(v)))
}

/// Accept both `hostkey = "SHA256:…"` and `hostkey = ["SHA256:…", …]`.
fn string_or_list<'de, D>(d: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_are_read() {
        let cfg = Config::parse(
            r#"
            [defaults]
            timeout = 60
            cache = true
            cache_limit = "1G"

            [policy]
            known_hosts = "accept-new"
            refuse_plaintext_auth = true

            [ssh]
            user = "deploy"
            key = "~/.ssh/id_ed25519"
            hostkey = "SHA256:abc"

            [s3]
            endpoint = "https://minio.example.com"
            path_style = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.defaults.timeout, Some(60));
        assert_eq!(cfg.defaults.cache, Some(true));
        assert_eq!(cfg.policy.known_hosts.as_deref(), Some("accept-new"));
        assert_eq!(cfg.ssh.hostkey, vec!["SHA256:abc"]);
        assert_eq!(cfg.s3.path_style, Some(true));
        assert!(cfg.mail.smtp.is_none());
    }

    #[test]
    fn unknown_keys_are_reported() {
        let err = Config::parse("[defaults]\ntimeut = 5\n").unwrap_err();
        assert!(err.contains("timeut"), "{err}");
        let err = Config::parse("[defualts]\ntimeout = 5\n").unwrap_err();
        assert!(err.contains("defualts"), "{err}");
    }

    #[test]
    fn environment_variables_are_interpolated() {
        // SAFETY: single-threaded test, the variable is only read here.
        unsafe { std::env::set_var("MPT_TEST_REGION", "eu-central-1") };
        let cfg = Config::parse("[s3]\nregion = \"${MPT_TEST_REGION}\"\n").unwrap();
        assert_eq!(cfg.s3.region.as_deref(), Some("eu-central-1"));

        let err = Config::parse("[s3]\nregion = \"${MPT_TEST_UNSET_VAR}\"\n").unwrap_err();
        assert!(err.contains("MPT_TEST_UNSET_VAR"), "{err}");
        // A value that merely looks like a shell expansion stays intact.
        let cfg = Config::parse("[s3]\nregion = \"$HOME/x\"\n").unwrap();
        assert_eq!(cfg.s3.region.as_deref(), Some("$HOME/x"));
    }

    #[test]
    fn durations_carry_units() {
        assert_eq!(parse_duration("90").unwrap().as_secs(), 90);
        assert_eq!(parse_duration("30m").unwrap().as_secs(), 1800);
        assert_eq!(parse_duration("7d").unwrap().as_secs(), 604_800);
        assert!(parse_duration("0").unwrap().is_zero(), "0 is no limit");
        let err = Config::parse("[policy]\nmax_signature_age = \"soon\"\n").unwrap_err();
        assert!(err.contains("max_signature_age"), "{err}");
    }

    #[test]
    fn sizes_carry_units() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("64K").unwrap(), 64 * 1024);
        assert_eq!(parse_size(" 2G ").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_size("big").is_err());
    }

    #[test]
    fn hostkey_takes_a_list_too() {
        let cfg = Config::parse("[ssh]\nhostkey = [\"SHA256:a\", \"SHA256:b\"]\n").unwrap();
        assert_eq!(cfg.ssh.hostkey.len(), 2);
    }

    fn with_profiles() -> Config {
        Config::parse(
            r#"
            [profiles.prod]
            url = "sftp://deploy@srv.example.com/data/?timeout=10"
            key = "/k/prod"
            timeout = 60
            hostkey = ["SHA256:a", "SHA256:b"]
            sign = "ssh:/k/prod"
            hash = "blake3"

            [profiles.boss]
            url = "mailto:boss@example.com"
            subject = "Report"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn a_profile_becomes_a_location() {
        let cfg = with_profiles();
        let loc = cfg.resolve("mpt://prod/incoming/x.pdf").unwrap().unwrap();
        assert_eq!(loc.scheme(), crate::Scheme::Sftp);
        assert_eq!(loc.path(), "/data/incoming/x.pdf");
        assert_eq!(loc.username(), Some("deploy"));
        assert_eq!(loc.opt("key"), Some("/k/prod"));
        assert_eq!(
            loc.opt("timeout"),
            Some("60"),
            "the profile replaces what its own URL says"
        );
        assert_eq!(
            loc.opts("hostkey").collect::<Vec<_>>(),
            ["SHA256:a", "SHA256:b"]
        );

        // Without a path the profile URL stands as it is, directory and all.
        let loc = cfg.resolve("mpt://prod").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/");
        assert!(loc.is_dir_target());
        let loc = cfg.resolve("mpt://prod/reports/").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/reports/");
        assert!(
            loc.is_dir_target(),
            "a trailing slash still means a directory"
        );
    }

    #[test]
    fn the_reference_overrides_profile_options() {
        let loc = with_profiles()
            .resolve("mpt://prod/in/?timeout=120&insecure=true")
            .unwrap()
            .unwrap();
        assert_eq!(loc.opt("timeout"), Some("120"));
        assert_eq!(loc.opt("insecure"), Some("true"));
        assert_eq!(loc.opt("key"), Some("/k/prod"), "the rest is untouched");
    }

    #[test]
    fn a_profile_can_be_a_mail_target() {
        let loc = with_profiles().resolve("mpt://boss").unwrap().unwrap();
        assert_eq!(loc.recipients(), vec!["boss@example.com"]);
        assert_eq!(loc.opt("subject"), Some("Report"));
    }

    #[test]
    fn unusable_references_are_rejected() {
        let cfg = with_profiles();
        let err = cfg.resolve("mpt://staging/x").unwrap_err().to_string();
        assert!(err.contains("boss, prod"), "{err}");
        // Nothing may climb out of the profile's directory.
        let err = cfg.resolve("mpt://prod/../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("unsafe"), "{err}");
        // Nor in its percent-encoded form, which HTTP servers decode.
        for bad in [
            "mpt://prod/%2e%2e/%2e%2e/etc/passwd",
            "mpt://prod/%2E%2E/x",
            "mpt://prod/a/..%2F..%2Fetc",
        ] {
            let err = cfg.resolve(bad).unwrap_err();
            assert!(err.to_string().contains("unsafe"), "{bad}: {err}");
        }
        // Mail has no path to append to.
        assert!(cfg.resolve("mpt://boss/x").is_err());
        // A plain URL is not a profile reference.
        assert!(cfg.resolve("sftp://h/x").unwrap().is_none());
    }

    /// A reference is read like a URL: its path is percent-decoded, a
    /// fragment is not part of it, and the prefix may be in any case.
    #[test]
    fn a_reference_is_read_like_a_url() {
        let cfg = with_profiles();
        let loc = cfg.resolve("mpt://prod/a%20b/c.pdf").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/a b/c.pdf");
        let loc = cfg.resolve("MPT://prod/x.pdf#part").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/x.pdf");
        assert_eq!(loc.profile(), Some("prod"));
        let loc = cfg.resolve("Mpt://prod/in/?timeout=5#x").unwrap().unwrap();
        assert_eq!(loc.opt("timeout"), Some("5"));
        assert_eq!(profile_name("MPT://prod#x"), Some("prod"));

        // Over HTTP an encoded `/` stays a character of its segment.
        let cfg = Config::parse("[profiles.gl]\nurl = \"https://gl.example/api/\"\n").unwrap();
        let loc = cfg
            .resolve("mpt://gl/group%2Fproject/raw")
            .unwrap()
            .unwrap();
        assert_eq!(loc.encoded_path(), "/api/group%2Fproject/raw");
        assert!(is_profile_ref("mPt://prod/"));
        assert!(!is_profile_ref("sftp://prod/"));
    }

    #[test]
    fn profiles_do_not_chain() {
        let cfg =
            Config::parse("[profiles.a]\nurl = \"mpt://b/\"\n[profiles.b]\nurl = \"sftp://h/\"\n")
                .unwrap();
        let err = cfg.resolve("mpt://a/x").unwrap_err().to_string();
        assert!(err.contains("do not chain"), "{err}");
    }

    #[tokio::test]
    async fn a_profile_password_comes_from_its_provider() {
        // SAFETY: single-threaded test, the variable is only read here.
        unsafe { std::env::set_var("MPT_TEST_PROFILE_PW", "s3cret") };
        let mut cfg = Config::parse(
            r#"
            [profiles.prod]
            url = "sftp://deploy@srv.example.com/data/"
            password = { env = "MPT_TEST_PROFILE_PW" }

            [profiles.other]
            url = "ftp://h/"
            password = { cmd = "exit 1" }
            "#,
        )
        .unwrap();
        // Only the profile this command uses is asked for, so the broken
        // provider of the other one does not matter.
        cfg.resolve_secrets(&["mpt://prod/x"], false).await.unwrap();
        let loc = cfg.resolve("mpt://prod/x").unwrap().unwrap();
        assert_eq!(loc.password(), Some("s3cret"));
        assert!(!loc.password_in_url(), "it did not come from the URL");
        assert!(
            cfg.resolve("mpt://other/x")
                .unwrap()
                .unwrap()
                .password()
                .is_none()
        );

        let err = cfg
            .resolve_secrets(&["mpt://other/x"], false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("profile 'other'"), "{err}");
    }

    /// Two resolutions side by side (two submissions to the server) both
    /// end up in the published configuration.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // it keeps the synchronous policy tests out
    async fn concurrent_resolutions_keep_each_others_secrets() {
        let _guard = crate::policy::exclusive();
        install(
            Config::parse(
                r#"
                [profiles.race_a]
                url = "sftp://h/a/"
                password = { cmd = "sleep 0.3; echo pw-a" }

                [profiles.race_b]
                url = "sftp://h/b/"
                password = { cmd = "sleep 0.3; echo pw-b" }
                "#,
            )
            .unwrap(),
        );
        let (a, b) = tokio::join!(
            resolve_more(&["mpt://race_a/x"], false),
            resolve_more(&["mpt://race_b/x"], false)
        );
        a.unwrap();
        b.unwrap();
        let cfg = global();
        let names: Vec<&String> = cfg.resolved.profile_passwords.keys().collect();
        assert_eq!(names, ["race_a", "race_b"]);
        install(Config::default());
    }

    #[test]
    fn credentials_want_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[mail]\npassword = { env = \"X\" }\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let cfg = Config::read(&path).unwrap();
            assert!(
                cfg.warnings
                    .iter()
                    .any(|w| w.contains("readable by others")),
                "{:?}",
                cfg.warnings
            );

            std::fs::write(
                &path,
                "[policy]\nstrict_permissions = true\n[mail]\npassword = { env = \"X\" }\n",
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Config::read(&path).is_err(), "strict makes it an error");

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(Config::read(&path).is_ok());
        }
        // A file without credentials is nobody's business.
        std::fs::write(&path, "[defaults]\ntimeout = 5\n").unwrap();
        assert!(Config::read(&path).unwrap().warnings.is_empty());
    }

    #[test]
    fn a_profile_needs_a_url() {
        let err = Config::parse("[profiles.x]\nkey = \"/k\"\n").unwrap_err();
        assert!(err.contains("url"), "{err}");
    }

    /// Write `text` to a file called `mpt.toml` and read it the way the
    /// working directory's file is read.
    fn local(text: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mpt.toml");
        std::fs::write(&path, text).unwrap();
        let cfg = Config::read_local(&path).unwrap().unwrap();
        (dir, cfg)
    }

    #[test]
    fn a_local_file_may_not_choose_the_relay() {
        let (_dir, cfg) = local("[defaults]\ntimeout = 5\nvia = \"ssh://evil/\"\n");
        assert_eq!(cfg.defaults.timeout, Some(5));
        assert!(cfg.defaults.via.is_none());
        assert!(
            cfg.warnings.iter().any(|w| w.contains("via")),
            "{:?}",
            cfg.warnings
        );
    }

    #[test]
    fn a_local_file_only_contributes_defaults_and_policy() {
        let (_dir, cfg) = local(
            "[defaults]\ntimeout = 5\n[policy]\nknown_hosts = \"off\"\n[ssh]\nuser = \"nobody\"\n",
        );
        assert_eq!(cfg.defaults.timeout, Some(5));
        assert_eq!(cfg.policy.known_hosts.as_deref(), Some("off"));
        assert!(cfg.ssh.user.is_none(), "[ssh] must be dropped");
        assert!(
            cfg.warnings.iter().any(|w| w.contains("[ssh]")),
            "{:?}",
            cfg.warnings
        );
    }

    /// A file in the working directory must not name a target or a
    /// credential command, and being the *only* section in the file must not
    /// let one through: a `[profiles]` block redirects `mpt://name/`
    /// elsewhere and its `password = { cmd = … }` runs on the next transfer.
    #[test]
    fn a_local_file_cannot_smuggle_in_a_profile() {
        let (_dir, cfg) = local(
            r#"
            [profiles.prod]
            url = "sftp://attacker.example/incoming/"
            password = { cmd = "touch /tmp/mpt-should-not-run" }
            "#,
        );
        assert!(cfg.profiles.is_empty(), "[profiles] must be dropped");
        assert!(
            cfg.warnings.iter().any(|w| w.contains("[profiles]")),
            "the reason must be reported: {:?}",
            cfg.warnings
        );
    }

    #[test]
    fn a_local_file_cannot_set_an_http_token() {
        let (_dir, cfg) = local("[http]\ntoken = { cmd = \"echo t\" }\n");
        assert!(cfg.http.token.is_none(), "[http] must be dropped");
        assert!(
            cfg.warnings.iter().any(|w| w.contains("[http]")),
            "{:?}",
            cfg.warnings
        );
    }

    /// Every section but the two allowed ones goes, whether or not it is the
    /// only thing in the file.
    #[test]
    fn a_local_file_drops_every_other_section_on_its_own() {
        for (section, text) in [
            ("signing", "[signing]\nkey = \"ssh:/k\"\n"),
            ("verify", "[verify]\nallowed_signers = \"/a\"\n"),
            ("ssh", "[ssh]\nkey = \"/k\"\n"),
            ("mail", "[mail]\nfrom = \"a@b.c\"\n"),
            ("s3", "[s3]\nendpoint = \"https://x\"\n"),
            ("http", "[http]\ntoken = { env = \"T\" }\n"),
            ("server", "[server]\nbind = \"0.0.0.0:80\"\n"),
            ("profiles", "[profiles.p]\nurl = \"sftp://h/\"\n"),
        ] {
            let (_dir, cfg) = local(text);
            assert!(
                cfg.non_local_sections().is_empty(),
                "[{section}] survived on its own"
            );
            assert!(
                cfg.warnings.iter().any(|w| w.contains(section)),
                "[{section}] was dropped without saying so: {:?}",
                cfg.warnings
            );
        }
    }

    #[test]
    fn the_server_section_is_read_and_checked() {
        let cfg = Config::parse(
            "[server]\nbind = \"127.0.0.1:1\"\ntoken = { env = \"T\" }\nretention = \"7d\"\n\
             urls = \"any\"\nprofiles = \"prod\"\n",
        )
        .unwrap();
        assert_eq!(cfg.server.bind.as_deref(), Some("127.0.0.1:1"));
        assert_eq!(cfg.server.urls, Some(UrlRule::Any));
        assert_eq!(cfg.server.profiles, vec!["prod"]);
        assert!(cfg.holds_credentials());
        assert!(Config::parse("[server]\nurls = \"some\"\n").is_err());
        let err = Config::parse("[server]\nretention = \"soon\"\n").unwrap_err();
        assert!(err.contains("[server] retention"), "{err}");
        assert!(Config::parse("[server]\nparallel = 0\n").is_err());
        assert!(Config::parse("[server]\nmax_transfers = 0\n").is_err());
        assert!(Config::parse("[server]\nmax_queued = 0\n").is_err());
        let cfg = Config::parse("[server]\nallow_delete = true\nmax_queued = 5\n").unwrap();
        assert_eq!(cfg.server.allow_delete, Some(true));
        assert_eq!(cfg.server.max_queued, Some(5));
        assert!(Config::parse("[server]\nmax_body = \"big\"\n").is_err());
    }

    #[test]
    fn the_local_file_wins_over_the_user_file() {
        let mut user = Config::parse("[defaults]\ntimeout = 30\nqueue = 4\n").unwrap();
        let mut local = Config::parse("[defaults]\ntimeout = 5\n").unwrap();
        user.merge(&mut local);
        assert_eq!(user.defaults.timeout, Some(5));
        assert_eq!(user.defaults.queue, Some(4), "untouched values survive");
    }
}
