//! Configuration file: defaults for the flags, security policies and
//! per-protocol settings.
//!
//! The file is TOML and is looked up in this order, the first hit wins:
//!
//! 1. `--config <path>` (an error if it does not exist)
//! 2. `$MPFT_CONFIG` (likewise)
//! 3. `$XDG_CONFIG_HOME/mpft/config.toml`, else `~/.config/mpft/config.toml`
//!
//! In addition, `./mpft.toml` in the working directory contributes
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

use crate::credentials::{Secret, SecretRef};
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
    /// Named targets, addressed as `mpft://<name>/<path>`.
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
    /// Finish transfers through a `.mpft-part` file.
    pub atomic: Option<bool>,
    /// Continue an interrupted transfer from what is in the `.mpft-part` file.
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
    /// OAuth2 bearer token, sent as `Authorization: Bearer …` to `hosts`
    /// over TLS, and to nothing else.
    pub token: Option<Secret>,
    /// The hosts `token` is for, by name (`graph.example.com`), without a
    /// port. Without any, the token is sent nowhere.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// `[server]` — settings for `mpft serve`.
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
    /// Which URLs a job may name: `profiles` (only `mpft://<profile>/…`,
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

/// `[relay]` — settings for `mpft relay --listen`.
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
    /// Refuse to list a directory with more entries than this (default
    /// 100000); 0 for no limit.
    pub max_entries: Option<usize>,
    /// Which way a client may send the targets' passwords: `header` (the
    /// default), `on-demand` or `any`.
    pub credentials: Option<String>,
    /// Take the agent a client forwards (default true).
    pub agent_forwarding: Option<bool>,
    /// Let a session delete the source the relay read (default false).
    pub allow_delete: Option<bool>,
    /// Log in to the SSH hosts a client names with the relay's own identity
    /// too — its agent, default keys, `[ssh] key` (default false).
    pub own_keys: Option<bool>,
    /// Let a client name files on the relay host (default false).
    pub local_files: Option<bool>,
}

/// Which URLs the server accepts in a job.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlRule {
    /// Only `mpft://<profile>/…`: the configuration decides what the API
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
    /// Options of those profiles that are credential references
    /// (`passphrase = { env = … }`), by profile name, in the order of
    /// [`Profile::option_values`]: sorted by option name, not the file's.
    pub profile_options: BTreeMap<String, Vec<(String, SecretString)>>,
}

/// `[profiles.<name>]` — a named target.
///
/// Besides the reserved keys below, every entry becomes a URL option of the
/// resolved location, so a profile can carry anything the scheme understands
/// (`key`, `known_hosts`, `hostkey`, `timeout`, `tls`, `subject`, …).
#[derive(Clone, Deserialize)]
pub struct Profile {
    /// The endpoint this profile stands for.
    pub url: String,
    /// Password for this endpoint.
    pub password: Option<Secret>,
    /// Sign checksum files written to this target (`--sign` syntax).
    pub sign: Option<String>,
    /// Checksum algorithm for this target.
    pub hash: Option<String>,
    /// Finish through a `.mpft-part` file.
    pub atomic: Option<bool>,
    /// The relay this endpoint is reached through (an `ssh://` URL or a
    /// profile with one), instead of `[defaults] via`. A source with one
    /// is read by that relay, a target with one written by it.
    pub via: Option<String>,
    #[serde(flatten)]
    options: BTreeMap<String, toml::Value>,
}

/// The options with a secret written out in them shown as `***`, like a
/// location shows them.
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let options: Vec<(String, String)> = self
            .options
            .keys()
            .map(|k| {
                let shown = match self.options.get(k) {
                    Some(toml::Value::Table(t)) => format!("{t}"),
                    Some(_) if crate::location::is_secret_option(k) || k == "header" => {
                        "***".to_string()
                    }
                    Some(v) => v.to_string(),
                    None => String::new(),
                };
                (k.clone(), shown)
            })
            .collect();
        f.debug_struct("Profile")
            .field("url", &self.url)
            .field("password", &self.password)
            .field("sign", &self.sign)
            .field("hash", &self.hash)
            .field("atomic", &self.atomic)
            .field("via", &self.via)
            .field("options", &options)
            .finish()
    }
}

/// A free-form entry of a profile: a value written out, or a credential
/// reference to fetch it from (`passphrase = { env = "KEY_PW" }`).
#[derive(Debug, Clone)]
pub enum OptionValue {
    Plain(String),
    Secret(SecretRef),
}

impl Profile {
    /// The free-form entries as URL options, sorted by name (the file's
    /// order is not kept). A value may be a list, which repeats the option
    /// (`hostkey`, `header`). A credential reference is left out: its value
    /// is only known once it has been fetched (see [`Config::resolve`]).
    pub fn options(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .option_values()?
            .into_iter()
            .filter_map(|(k, v)| match v {
                OptionValue::Plain(v) => Some((k, v)),
                OptionValue::Secret(_) => None,
            })
            .collect())
    }

    /// Every free-form entry, credential references included.
    pub fn option_values(&self) -> Result<Vec<(String, OptionValue)>> {
        let mut out = Vec::new();
        for (k, v) in &self.options {
            match v {
                toml::Value::Array(items) => {
                    for item in items {
                        out.push((k.clone(), option_value(k, item)?));
                    }
                }
                other => out.push((k.clone(), option_value(k, other)?)),
            }
        }
        Ok(out)
    }

    /// Whether the profile carries a credential: a password, an option that
    /// is a credential reference, or a secret option written out
    /// (`passphrase`, `token`, `header = "Authorization:…"`).
    fn holds_credentials(&self) -> bool {
        self.password.is_some()
            || self.option_values().is_ok_and(|opts| {
                opts.iter().any(|(k, v)| match v {
                    OptionValue::Secret(_) => true,
                    OptionValue::Plain(v) => {
                        crate::location::is_secret_option(k)
                            || (k == "header"
                                && v.split_once(':')
                                    .is_some_and(|(n, _)| crate::location::is_secret_option(n)))
                    }
                })
            })
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

/// A profile option must be something that can stand in a URL, or a
/// credential reference that produces one.
fn option_value(key: &str, v: &toml::Value) -> Result<OptionValue> {
    Ok(OptionValue::Plain(match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Table(_) => {
            return SecretRef::deserialize(v.clone())
                .map(OptionValue::Secret)
                .map_err(|e| {
                    Error::Config(format!(
                        "profile option '{key}' is a table, but not a credential reference \
                         ({{ env = … }}, {{ file = … }}, {{ cmd = … }}, …): {e}"
                    ))
                });
        }
        other => {
            return Err(Error::Config(format!(
                "profile option '{key}' must be a string, number, boolean or credential \
                 reference, not {}",
                other.type_str()
            )));
        }
    }))
}

/// The prefix that addresses a profile instead of a protocol.
pub const PROFILE_PREFIX: &str = "mpft://";

impl Config {
    /// Turn `mpft://<profile>/<path>?<options>` into the location the profile
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
                .map_err(|e| Error::Config(format!("mpft://{name}/{path}: {e}")))?;
        }
        if let Some(pw) = self.resolved.profile_passwords.get(name)
            && !loc.password_in_url()
        {
            use secrecy::ExposeSecret;
            loc.set_password(pw.expose_secret());
        }
        loc.set_profile(name);
        override_options(&mut loc, self.profile_options(name, profile)?);
        if let Some(q) = query {
            override_options(&mut loc, crate::location::parse_query(q));
        }
        debug!(%name, %loc, "profile resolved");
        Ok(Some(loc))
    }

    /// A profile's options with its credential references filled in from
    /// what [`Config::resolve_secrets`] fetched. One that has not been
    /// fetched is left out, as a profile password is.
    fn profile_options(&self, name: &str, profile: &Profile) -> Result<Vec<(String, String)>> {
        use secrecy::ExposeSecret;
        let mut fetched = self
            .resolved
            .profile_options
            .get(name)
            .map(|v| v.iter())
            .into_iter()
            .flatten();
        let mut out = Vec::new();
        for (k, v) in profile.option_values()? {
            match v {
                OptionValue::Plain(v) => out.push((k, v)),
                OptionValue::Secret(_) => {
                    if let Some((_, value)) = fetched.next() {
                        out.push((k, value.expose_secret().to_string()));
                    }
                }
            }
        }
        Ok(out)
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
        if let Some(p) = std::env::var_os("MPFT_CONFIG").filter(|v| !v.is_empty()) {
            let p = PathBuf::from(expand_tilde(&p.to_string_lossy()));
            return if p.exists() {
                Ok(Some(p))
            } else {
                Err(Error::Config(format!(
                    "MPFT_CONFIG points at {}, which does not exist",
                    p.display()
                )))
            };
        }
        Ok(Config::default_path().filter(|p| p.exists()))
    }

    /// `$XDG_CONFIG_HOME/mpft/config.toml`, else `~/.config/mpft/config.toml`.
    pub fn default_path() -> Option<PathBuf> {
        let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(v) => PathBuf::from(v),
            None => std::env::home_dir()?.join(".config"),
        };
        Some(base.join("mpft").join("config.toml"))
    }

    fn local_file() -> Option<PathBuf> {
        let p = PathBuf::from("mpft.toml");
        p.exists().then_some(p)
    }

    /// Read `./mpft.toml`, keeping only the sections that are safe to take
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
        // A directory one happens to stand in must not turn every copy
        // into a move: the source is gone once the copy is done.
        if local.defaults.delete_source.take().is_some() {
            local.warnings.push(format!(
                "{}: ignoring [defaults] delete_source — a configuration file in the working \
                 directory may not have sources deleted",
                path.display()
            ));
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

    /// Sections that `./mpft.toml` is not allowed to set.
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
        let HttpSection { token, hosts } = &self.http;
        if token.is_some() || !hosts.is_empty() {
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
            max_entries,
            credentials,
            agent_forwarding,
            allow_delete,
            own_keys,
            local_files,
        } = &self.relay;
        if host_key.is_some()
            || authorized_keys.is_some()
            || parallel.is_some()
            || grace.is_some()
            || max_size.is_some()
            || max_entries.is_some()
            || credentials.is_some()
            || agent_forwarding.is_some()
            || allow_delete.is_some()
            || own_keys.is_some()
            || local_files.is_some()
        {
            out.push("relay");
        }
        if !self.profiles.is_empty() {
            out.push("profiles");
        }
        out
    }

    /// Parse one file. Errors mention the path, so `mpft config check` can be
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
        for (name, profile) in &cfg.profiles {
            profile
                .option_values()
                .map_err(|e| format!("[profiles.{name}]: {e}"))?;
        }
        if let Some(v) = &cfg.server.max_body {
            parse_size(v).map_err(|e| format!("[server] max_body: {e}"))?;
        }
        if let Some(v) = &cfg.relay.grace {
            parse_duration(v).map_err(|e| format!("[relay] grace: {e}"))?;
        }
        if let Some(v) = &cfg.relay.max_size {
            parse_size(v).map_err(|e| format!("[relay] max_size: {e}"))?;
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

    /// Take every value `other` sets; used to lay `./mpft.toml` over the user file.
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
            defaults.skip_existing,
            defaults.delete_source,
            defaults.log,
            defaults.json,
            defaults.parallel,
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
        self.tighten_policy(other);
        if !other.profiles.is_empty() {
            self.profiles.append(&mut other.profiles);
        }
        if !other.ssh.hostkey.is_empty() {
            self.ssh.hostkey = std::mem::take(&mut other.ssh.hostkey);
        }
        self.sources.append(&mut other.sources);
        self.warnings.append(&mut other.warnings);
    }

    /// Lay the `[policy]` of `other` (`./mpft.toml`) over this one's, taking a
    /// value only where it is stricter than what is in force already: a
    /// directory one happens to stand in may tighten the rules, never
    /// loosen them. A value that would is ignored with a warning.
    fn tighten_policy(&mut self, other: &mut Config) {
        let from = other
            .sources
            .first()
            .map_or_else(|| "mpft.toml".to_string(), |p| p.display().to_string());
        let mut refused = Vec::new();
        let theirs = std::mem::take(&mut other.policy);
        let ours = &mut self.policy;

        // strict > accept-new > off; strict is the built-in default.
        let rank = |v: &str| match v.trim().to_ascii_lowercase().as_str() {
            "off" | "no" | "false" => 0,
            "accept-new" | "accept_new" => 1,
            _ => 2,
        };
        if let Some(v) = theirs.known_hosts {
            let current = ours.known_hosts.as_deref().map_or(2, rank);
            if rank(&v) >= current {
                ours.known_hosts = Some(v);
            } else {
                refused.push(format!("known_hosts = \"{v}\""));
            }
        }
        // For the switches, true is the strict side and false the default.
        for (name, mine, wanted) in [
            (
                "refuse_plaintext_auth",
                &mut ours.refuse_plaintext_auth,
                theirs.refuse_plaintext_auth,
            ),
            (
                "refuse_insecure_tls",
                &mut ours.refuse_insecure_tls,
                theirs.refuse_insecure_tls,
            ),
            (
                "require_signature",
                &mut ours.require_signature,
                theirs.require_signature,
            ),
            (
                "strict_permissions",
                &mut ours.strict_permissions,
                theirs.strict_permissions,
            ),
        ] {
            match wanted {
                Some(true) => *mine = Some(true),
                Some(false) if *mine == Some(true) => refused.push(format!("{name} = false")),
                Some(false) | None => {}
            }
        }
        // A shorter limit is stricter; 0 is no limit at all. Both values
        // were checked when their files were read.
        if let Some(v) = theirs.max_signature_age {
            let limit = |v: &str| parse_duration(v).ok().filter(|d| !d.is_zero());
            let looser = match (ours.max_signature_age.as_deref().and_then(limit), limit(&v)) {
                (Some(_), None) => true,
                (Some(current), Some(new)) => new > current,
                (None, _) => false,
            };
            if looser {
                refused.push(format!("max_signature_age = \"{v}\""));
            } else {
                ours.max_signature_age = Some(v);
            }
        }
        for what in refused {
            self.warnings.push(format!(
                "{from}: ignoring [policy] {what} — a configuration file in the working \
                 directory may only make the policy stricter"
            ));
        }
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
        // This configuration's rule, which is not installed yet at the start.
        let strict = self.policy().strict_permissions;
        // A profile can ask for signing on its own.
        let signing = signing
            || names
                .iter()
                .filter_map(|n| self.profiles.get(n))
                .any(|p| p.sign.is_some());

        for name in names {
            let Some(profile) = self.profiles.get(&name).cloned() else {
                continue;
            };
            if let Some(secret) = &profile.password {
                let pw = secret
                    .resolve_under(&format!("password of profile '{name}'"), strict)
                    .await?;
                self.resolved.profile_passwords.insert(name.clone(), pw);
            }
            let mut options = Vec::new();
            for (key, value) in profile.option_values()? {
                if let OptionValue::Secret(r) = value {
                    let v = Secret::Reference(r)
                        .resolve_under(&format!("{key} of profile '{name}'"), strict)
                        .await?;
                    options.push((key, v));
                }
            }
            if !options.is_empty() {
                self.resolved.profile_options.insert(name, options);
            }
        }
        if uses(&[crate::Scheme::Sftp, crate::Scheme::Scp, crate::Scheme::Ssh])
            && let Some(s) = &self.ssh.passphrase
        {
            self.resolved.ssh_passphrase = Some(s.resolve_under("[ssh] passphrase", strict).await?);
        }
        if uses(&[
            crate::Scheme::Mailto,
            crate::Scheme::Smtp,
            crate::Scheme::Smtps,
        ]) && let Some(s) = &self.mail.password
        {
            self.resolved.mail_password = Some(s.resolve_under("[mail] password", strict).await?);
        }
        if uses(&[
            crate::Scheme::Http,
            crate::Scheme::Https,
            crate::Scheme::WebDav,
            crate::Scheme::WebDavs,
        ]) && let Some(s) = &self.http.token
        {
            self.resolved.http_token = Some(s.resolve_under("[http] token", strict).await?);
        }
        if uses(&[crate::Scheme::S3]) {
            if let Some(s) = &self.s3.access_key_id {
                self.resolved.s3_access_key_id =
                    Some(s.resolve_under("[s3] access_key_id", strict).await?);
            }
            if let Some(s) = &self.s3.secret_access_key {
                self.resolved.s3_secret_access_key =
                    Some(s.resolve_under("[s3] secret_access_key", strict).await?);
            }
        }
        if signing && let Some(s) = &self.signing.passphrase {
            self.resolved.signing_passphrase =
                Some(s.resolve_under("[signing] passphrase", strict).await?);
        }
        Ok(())
    }

    /// `[http] token` for an endpoint at `loc`: only over TLS (`https://`,
    /// `webdavs://`), and only to a host `[http] hosts` names, so a token
    /// meant for one API never reaches a download mirror or the network in
    /// the clear. The first time a token is held back because no host is
    /// named at all, a warning says so.
    pub fn http_token_for(&self, loc: &Location) -> Option<&SecretString> {
        let token = self.resolved.http_token.as_ref()?;
        if !matches!(loc.scheme(), crate::Scheme::Https | crate::Scheme::WebDavs) {
            return None;
        }
        if self.http.hosts.is_empty() {
            crate::policy::warn_once(
                "http-token-hosts".into(),
                "[http] token is sent to no host: name the hosts it is for in [http] hosts",
            );
            return None;
        }
        let host = loc.host()?;
        self.http
            .hosts
            .iter()
            .any(|h| h.trim().eq_ignore_ascii_case(host))
            .then_some(token)
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
            || self.profiles.values().any(Profile::holds_credentials)
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
        // The variable can only switch the refusal on, for one run; the
        // file cannot switch it off again.
        if let Some(v) = self.policy.refuse_plaintext_auth {
            p.refuse_plaintext_auth |= v;
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

/// Parse a URL, resolving `mpft://<profile>/…` against the loaded
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

/// The profile name a `mpft://` URL names, without looking it up.
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

/// Whether a profile reference carries `?options` of its own. They replace
/// what the profile fixes (`?key=`, `?known_hosts=off`, `?endpoint=`) with
/// the profile's credentials still attached, which is why neither a
/// server's nor a relay's clients may send them.
pub fn profile_ref_has_options(url: &str) -> bool {
    strip_profile_prefix(url).is_some_and(|rest| {
        rest.split_once('#')
            .map_or(rest, |(before, _)| before)
            .contains('?')
    })
}

/// What follows `mpft://`, if `url` starts with it in any case.
fn strip_profile_prefix(url: &str) -> Option<&str> {
    let url = url.trim();
    let head = url.get(..PROFILE_PREFIX.len())?;
    head.eq_ignore_ascii_case(PROFILE_PREFIX)
        .then(|| &url[PROFILE_PREFIX.len()..])
}

impl Resolved {
    /// Whether both hold the same secrets: what tells whether a resolution
    /// pass found anything new, or anything fetched anew because its time
    /// to live was over.
    fn same_as(&self, other: &Resolved) -> bool {
        use secrecy::ExposeSecret;
        fn one(a: &Option<SecretString>, b: &Option<SecretString>) -> bool {
            a.as_ref().map(|s| s.expose_secret()) == b.as_ref().map(|s| s.expose_secret())
        }
        fn map<V>(
            a: &BTreeMap<String, V>,
            b: &BTreeMap<String, V>,
            same: impl Fn(&V, &V) -> bool,
        ) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((ka, va), (kb, vb))| ka == kb && same(va, vb))
        }
        one(&self.ssh_passphrase, &other.ssh_passphrase)
            && one(&self.signing_passphrase, &other.signing_passphrase)
            && one(&self.mail_password, &other.mail_password)
            && one(&self.http_token, &other.http_token)
            && one(&self.s3_access_key_id, &other.s3_access_key_id)
            && one(&self.s3_secret_access_key, &other.s3_secret_access_key)
            && map(&self.profile_passwords, &other.profile_passwords, |a, b| {
                a.expose_secret() == b.expose_secret()
            })
            && map(&self.profile_options, &other.profile_options, |a, b| {
                a.len() == b.len()
                    && a.iter().zip(b).all(|((ka, va), (kb, vb))| {
                        ka == kb && va.expose_secret() == vb.expose_secret()
                    })
            })
    }
}

/// Fetch the secrets that `urls` need on top of what the installed
/// configuration already has, and publish the result. For endpoints that
/// turn up after the start (a job list read as it arrives, a submission to
/// the server); references already fetched come from the process-wide
/// cache while their time to live lasts, so this is cheap when there is
/// nothing new, and a value that expired is fetched and published anew.
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
    if !cfg.resolved.same_as(&current.resolved) {
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
        .map_err(|e| format!("invalid size '{s}': {e}"))?
        .checked_mul(mult)
        .ok_or_else(|| format!("invalid size '{s}': too large"))
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
        .map_err(|e| format!("invalid duration '{s}': {e} (try 7d, 24h, 30m or 0)"))?
        .checked_mul(mult)
        .map(std::time::Duration::from_secs)
        .ok_or_else(|| format!("invalid duration '{s}': too long"))
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
        unsafe { std::env::set_var("MPFT_TEST_REGION", "eu-central-1") };
        let cfg = Config::parse("[s3]\nregion = \"${MPFT_TEST_REGION}\"\n").unwrap();
        assert_eq!(cfg.s3.region.as_deref(), Some("eu-central-1"));

        let err = Config::parse("[s3]\nregion = \"${MPFT_TEST_UNSET_VAR}\"\n").unwrap_err();
        assert!(err.contains("MPFT_TEST_UNSET_VAR"), "{err}");
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
        // Too large for a u64 is an error, not a wrapped number or a panic.
        let err = Config::parse("[server]\nmax_body = \"20000000000G\"\n").unwrap_err();
        assert!(err.contains("too large"), "{err}");
        assert!(parse_duration("999999999999999999d").is_err());
        let err = Config::parse("[relay]\ngrace = \"soon\"\n").unwrap_err();
        assert!(err.contains("[relay] grace"), "{err}");
        let err = Config::parse("[relay]\nmax_size = \"big\"\n").unwrap_err();
        assert!(err.contains("[relay] max_size"), "{err}");
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
        let loc = cfg.resolve("mpft://prod/incoming/x.pdf").unwrap().unwrap();
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
        let loc = cfg.resolve("mpft://prod").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/");
        assert!(loc.is_dir_target());
        let loc = cfg.resolve("mpft://prod/reports/").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/reports/");
        assert!(
            loc.is_dir_target(),
            "a trailing slash still means a directory"
        );
    }

    #[test]
    fn the_reference_overrides_profile_options() {
        let loc = with_profiles()
            .resolve("mpft://prod/in/?timeout=120&insecure=true")
            .unwrap()
            .unwrap();
        assert_eq!(loc.opt("timeout"), Some("120"));
        assert_eq!(loc.opt("insecure"), Some("true"));
        assert_eq!(loc.opt("key"), Some("/k/prod"), "the rest is untouched");
    }

    #[test]
    fn a_profile_can_be_a_mail_target() {
        let loc = with_profiles().resolve("mpft://boss").unwrap().unwrap();
        assert_eq!(loc.recipients(), vec!["boss@example.com"]);
        assert_eq!(loc.opt("subject"), Some("Report"));
    }

    #[test]
    fn unusable_references_are_rejected() {
        let cfg = with_profiles();
        let err = cfg.resolve("mpft://staging/x").unwrap_err().to_string();
        assert!(err.contains("boss, prod"), "{err}");
        // Nothing may climb out of the profile's directory.
        let err = cfg.resolve("mpft://prod/../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("unsafe"), "{err}");
        // Nor in its percent-encoded form, which HTTP servers decode.
        for bad in [
            "mpft://prod/%2e%2e/%2e%2e/etc/passwd",
            "mpft://prod/%2E%2E/x",
            "mpft://prod/a/..%2F..%2Fetc",
        ] {
            let err = cfg.resolve(bad).unwrap_err();
            assert!(err.to_string().contains("unsafe"), "{bad}: {err}");
        }
        // Mail has no path to append to.
        assert!(cfg.resolve("mpft://boss/x").is_err());
        // A plain URL is not a profile reference.
        assert!(cfg.resolve("sftp://h/x").unwrap().is_none());
    }

    /// A reference is read like a URL: its path is percent-decoded, a
    /// fragment is not part of it, and the prefix may be in any case.
    #[test]
    fn a_reference_is_read_like_a_url() {
        let cfg = with_profiles();
        let loc = cfg.resolve("mpft://prod/a%20b/c.pdf").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/a b/c.pdf");
        let loc = cfg.resolve("MPFT://prod/x.pdf#part").unwrap().unwrap();
        assert_eq!(loc.path(), "/data/x.pdf");
        assert_eq!(loc.profile(), Some("prod"));
        let loc = cfg.resolve("Mpft://prod/in/?timeout=5#x").unwrap().unwrap();
        assert_eq!(loc.opt("timeout"), Some("5"));
        assert_eq!(profile_name("MPFT://prod#x"), Some("prod"));

        // Over HTTP an encoded `/` stays a character of its segment.
        let cfg = Config::parse("[profiles.gl]\nurl = \"https://gl.example/api/\"\n").unwrap();
        let loc = cfg
            .resolve("mpft://gl/group%2Fproject/raw")
            .unwrap()
            .unwrap();
        assert_eq!(loc.encoded_path(), "/api/group%2Fproject/raw");
        assert!(is_profile_ref("mPfT://prod/"));
        assert!(!is_profile_ref("sftp://prod/"));
    }

    #[test]
    fn profiles_do_not_chain() {
        let cfg =
            Config::parse("[profiles.a]\nurl = \"mpft://b/\"\n[profiles.b]\nurl = \"sftp://h/\"\n")
                .unwrap();
        let err = cfg.resolve("mpft://a/x").unwrap_err().to_string();
        assert!(err.contains("do not chain"), "{err}");
    }

    #[tokio::test]
    async fn a_profile_password_comes_from_its_provider() {
        // SAFETY: single-threaded test, the variable is only read here.
        unsafe { std::env::set_var("MPFT_TEST_PROFILE_PW", "s3cret") };
        let mut cfg = Config::parse(
            r#"
            [profiles.prod]
            url = "sftp://deploy@srv.example.com/data/"
            password = { env = "MPFT_TEST_PROFILE_PW" }

            [profiles.other]
            url = "ftp://h/"
            password = { cmd = "exit 1" }
            "#,
        )
        .unwrap();
        // Only the profile this command uses is asked for, so the broken
        // provider of the other one does not matter.
        cfg.resolve_secrets(&["mpft://prod/x"], false)
            .await
            .unwrap();
        let loc = cfg.resolve("mpft://prod/x").unwrap().unwrap();
        assert_eq!(loc.password(), Some("s3cret"));
        assert!(!loc.password_in_url(), "it did not come from the URL");
        assert!(
            cfg.resolve("mpft://other/x")
                .unwrap()
                .unwrap()
                .password()
                .is_none()
        );

        let err = cfg
            .resolve_secrets(&["mpft://other/x"], false)
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
            resolve_more(&["mpft://race_a/x"], false),
            resolve_more(&["mpft://race_b/x"], false)
        );
        a.unwrap();
        b.unwrap();
        let cfg = global();
        let names: Vec<&String> = cfg.resolved.profile_passwords.keys().collect();
        assert_eq!(names, ["race_a", "race_b"]);
        install(Config::default());
    }

    /// `passphrase`, `token` and `header` may come from a provider like a
    /// password, and count as credentials of the file either way.
    #[tokio::test]
    async fn secret_profile_options_come_from_their_providers() {
        // SAFETY: single-threaded test, the variables are only read here.
        unsafe {
            std::env::set_var("MPFT_TEST_OPT_PASSPHRASE", "pass+phrase");
            std::env::set_var("MPFT_TEST_OPT_HEADER", "Authorization: Bearer abc");
        }
        let mut cfg = Config::parse(
            r#"
            [profiles.api]
            url = "https://api.example.com/in/"
            token = { cmd = "printf 't0k'" }
            header = [{ env = "MPFT_TEST_OPT_HEADER" }, "Accept:text/plain"]

            [profiles.box]
            url = "sftp://h/in/"
            passphrase = { env = "MPFT_TEST_OPT_PASSPHRASE" }
            "#,
        )
        .unwrap();
        assert!(cfg.holds_credentials());
        // Not fetched yet: left out rather than sent as a table.
        let loc = cfg.resolve("mpft://box/x").unwrap().unwrap();
        assert_eq!(loc.opt("passphrase"), None);

        cfg.resolve_secrets(&["mpft://api/x", "mpft://box/x"], false)
            .await
            .unwrap();
        let loc = cfg.resolve("mpft://box/x").unwrap().unwrap();
        assert_eq!(loc.opt("passphrase"), Some("pass+phrase"));
        assert!(!loc.to_string().contains("pass+phrase"), "{loc}");
        let loc = cfg.resolve("mpft://api/x").unwrap().unwrap();
        assert_eq!(loc.opt("token"), Some("t0k"));
        assert_eq!(
            loc.opts("header").collect::<Vec<_>>(),
            ["Authorization: Bearer abc", "Accept:text/plain"]
        );

        // A literal secret option is a credential too, and does not show in
        // debug output; a plain profile is neither.
        let debug = format!(
            "{:?}",
            Config::parse(
                "[profiles.p]\nurl = \"sftp://u:pw1@h/\"\npassword = \"pw2\"\npassphrase = \"pw3\"\n\
                 header = \"Authorization: pw4\"\n[ssh]\npassphrase = \"pw5\"\n"
            )
            .unwrap()
        );
        for secret in ["pw2", "pw3", "pw4", "pw5"] {
            assert!(!debug.contains(secret), "{secret} in {debug}");
        }
        let literal = Config::parse("[profiles.p]\nurl = \"sftp://h/\"\npassphrase = \"x\"\n");
        assert!(literal.unwrap().holds_credentials());
        let header = Config::parse(
            "[profiles.p]\nurl = \"https://h/\"\nheader = \"Authorization: Bearer x\"\n",
        );
        assert!(header.unwrap().holds_credentials());
        let plain = Config::parse("[profiles.p]\nurl = \"sftp://h/\"\nkey = \"/k\"\n");
        assert!(!plain.unwrap().holds_credentials());
        // A table that is not a reference is refused when the file is read.
        let err = Config::parse("[profiles.p]\nurl = \"sftp://h/\"\ntoken = { envv = \"X\" }\n")
            .unwrap_err();
        assert!(err.contains("token"), "{err}");
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

    /// Write `text` to a file called `mpft.toml` and read it the way the
    /// working directory's file is read.
    fn local(text: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mpft.toml");
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
    fn a_local_file_may_not_have_sources_deleted() {
        let (_dir, cfg) = local("[defaults]\ntimeout = 5\ndelete_source = true\n");
        assert_eq!(cfg.defaults.timeout, Some(5));
        assert!(cfg.defaults.delete_source.is_none());
        assert!(
            cfg.warnings.iter().any(|w| w.contains("delete_source")),
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
    /// let one through: a `[profiles]` block redirects `mpft://name/`
    /// elsewhere and its `password = { cmd = … }` runs on the next transfer.
    #[test]
    fn a_local_file_cannot_smuggle_in_a_profile() {
        let (_dir, cfg) = local(
            r#"
            [profiles.prod]
            url = "sftp://attacker.example/incoming/"
            password = { cmd = "touch /tmp/mpft-should-not-run" }
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
    fn the_http_token_goes_only_to_its_hosts_over_tls() {
        let mut cfg =
            Config::parse("[http]\ntoken = { env = \"T\" }\nhosts = [\"api.example.com\"]\n")
                .unwrap();
        cfg.resolved.http_token = Some(SecretString::from("t"));
        let loc = |u: &str| Location::parse(u).unwrap();
        assert!(
            cfg.http_token_for(&loc("https://API.example.com/x"))
                .is_some()
        );
        assert!(
            cfg.http_token_for(&loc("webdavs://api.example.com/x"))
                .is_some()
        );
        assert!(
            cfg.http_token_for(&loc("http://api.example.com/x"))
                .is_none(),
            "never in the clear"
        );
        assert!(
            cfg.http_token_for(&loc("https://mirror.example.org/x"))
                .is_none(),
            "never to another host"
        );
        cfg.http.hosts.clear();
        assert!(
            cfg.http_token_for(&loc("https://api.example.com/x"))
                .is_none(),
            "no host named, no token sent"
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

    /// `./mpft.toml` may tighten the policy of the user file, never loosen
    /// it, and says so when it tries.
    #[test]
    fn a_local_file_only_tightens_the_policy() {
        let mut user = Config::parse(
            "[policy]\nknown_hosts = \"accept-new\"\nrefuse_plaintext_auth = true\n\
             require_signature = true\nmax_signature_age = \"7d\"\n",
        )
        .unwrap();
        let mut local = Config::parse(
            "[policy]\nknown_hosts = \"off\"\nrefuse_plaintext_auth = false\n\
             require_signature = false\nmax_signature_age = \"0\"\nrefuse_insecure_tls = true\n",
        )
        .unwrap();
        user.merge(&mut local);
        let p = &user.policy;
        assert_eq!(p.known_hosts.as_deref(), Some("accept-new"));
        assert_eq!(p.refuse_plaintext_auth, Some(true));
        assert_eq!(p.require_signature, Some(true));
        assert_eq!(p.max_signature_age.as_deref(), Some("7d"));
        assert_eq!(p.refuse_insecure_tls, Some(true), "tightening is taken");
        for key in [
            "known_hosts",
            "refuse_plaintext_auth",
            "require_signature",
            "max_signature_age",
        ] {
            assert!(
                user.warnings.iter().any(|w| w.contains(key)),
                "{key}: {:?}",
                user.warnings
            );
        }
        assert!(
            !user
                .warnings
                .iter()
                .any(|w| w.contains("refuse_insecure_tls"))
        );

        // Against the built-in defaults: `off` loosens strict, a shorter
        // signature age tightens a longer one.
        let mut user = Config::parse("[policy]\nmax_signature_age = \"7d\"\n").unwrap();
        let mut local =
            Config::parse("[policy]\nknown_hosts = \"off\"\nmax_signature_age = \"1d\"\n").unwrap();
        user.merge(&mut local);
        assert_eq!(user.policy.known_hosts, None);
        assert_eq!(user.policy.max_signature_age.as_deref(), Some("1d"));
        let mut local = Config::parse("[policy]\nknown_hosts = \"strict\"\n").unwrap();
        user.merge(&mut local);
        assert_eq!(user.policy.known_hosts.as_deref(), Some("strict"));
    }

    /// The environment can switch the refusal of plaintext credentials on
    /// for a run; the file cannot switch it off again.
    #[test]
    fn the_file_cannot_undo_the_environment_refusal() {
        let _guard = crate::policy::exclusive();
        // SAFETY: the policy lock keeps the other readers of the variable out.
        unsafe { std::env::set_var("MPFT_REFUSE_PLAINTEXT_AUTH", "1") };
        let cfg = Config::parse("[policy]\nrefuse_plaintext_auth = false\n").unwrap();
        let refused = cfg.policy().refuse_plaintext_auth;
        unsafe { std::env::remove_var("MPFT_REFUSE_PLAINTEXT_AUTH") };
        assert!(refused);
        assert!(!cfg.policy().refuse_plaintext_auth);
    }

    #[test]
    fn the_local_file_wins_over_the_user_file() {
        let mut user = Config::parse("[defaults]\ntimeout = 30\nqueue = 4\n").unwrap();
        let mut local = Config::parse("[defaults]\ntimeout = 5\n").unwrap();
        user.merge(&mut local);
        assert_eq!(user.defaults.timeout, Some(5));
        assert_eq!(user.defaults.queue, Some(4), "untouched values survive");
    }

    /// Every key of `[defaults]` a working directory may set reaches the
    /// merged configuration; the three relay keys and `delete_source` are
    /// dropped earlier, in `read_local`.
    #[test]
    fn every_local_default_is_merged() {
        let (_dir, mut local) = local(
            r#"
            [defaults]
            color = "never"
            hash = "blake3"
            cache = true
            cache_limit = "1M"
            retries = 3
            chunk = "8K"
            queue = 2
            timeout = 9
            atomic = false
            resume = true
            skip_existing = true
            delete_source = true
            log = "debug"
            json = true
            parallel = 7
            "#,
        );
        let mut user = Config::default();
        user.merge(&mut local);
        let Defaults {
            color,
            hash,
            cache,
            cache_limit,
            retries,
            chunk,
            queue,
            timeout,
            atomic,
            resume,
            skip_existing,
            delete_source,
            log,
            json,
            parallel,
            via: _,
            via_credentials: _,
            via_agent: _,
        } = user.defaults;
        assert_eq!(color.as_deref(), Some("never"));
        assert_eq!(hash.as_deref(), Some("blake3"));
        assert_eq!(cache, Some(true));
        assert_eq!(cache_limit.as_deref(), Some("1M"));
        assert_eq!(retries, Some(3));
        assert_eq!(chunk.as_deref(), Some("8K"));
        assert_eq!(queue, Some(2));
        assert_eq!(timeout, Some(9));
        assert_eq!(atomic, Some(false));
        assert_eq!(resume, Some(true));
        assert_eq!(skip_existing, Some(true));
        assert_eq!(delete_source, None, "dropped by read_local");
        assert_eq!(log.as_deref(), Some("debug"));
        assert_eq!(json, Some(true));
        assert_eq!(parallel, Some(7));
    }
}
