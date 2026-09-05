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

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use tracing::debug;

use crate::{Error, Result};

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
    /// Log level, either a bare level or `RUST_LOG` syntax.
    pub log: Option<String>,
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
}

/// `[signing]` — defaults for `--sign`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSection {
    /// Signing key in the `--sign` syntax: `ssh`, `ssh:<file>`, `pgp:<file>`.
    pub key: Option<String>,
    /// Which ssh-agent identity to sign with (`SHA256:…`).
    pub agent_fingerprint: Option<String>,
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
    pub from: Option<String>,
    /// Attachment size limit with a unit, e.g. `25M`.
    pub max_attachment: Option<String>,
}

/// `[s3]` — defaults for `s3://`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Section {
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub path_style: Option<bool>,
}

impl Config {
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
        let mut cfg = Config::read(path)?;
        let ignored = cfg.non_local_sections();
        if !ignored.is_empty() {
            cfg.warnings.push(format!(
                "{}: ignoring [{}] — a configuration file in the working directory \
                 only contributes [defaults] and [policy]",
                path.display(),
                ignored.join("], [")
            ));
            cfg.signing = SigningSection::default();
            cfg.verify = VerifySection::default();
            cfg.ssh = SshSection::default();
            cfg.mail = MailSection::default();
            cfg.s3 = S3Section::default();
        }
        Ok(Some(cfg))
    }

    /// Sections that `./mpt.toml` is not allowed to set.
    fn non_local_sections(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let SigningSection {
            key,
            agent_fingerprint,
        } = &self.signing;
        if key.is_some() || agent_fingerprint.is_some() {
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
            known_hosts_file,
            hostkey,
        } = &self.ssh;
        if user.is_some() || key.is_some() || known_hosts_file.is_some() || !hostkey.is_empty() {
            out.push("ssh");
        }
        let MailSection {
            smtp,
            from,
            max_attachment,
        } = &self.mail;
        if smtp.is_some() || from.is_some() || max_attachment.is_some() {
            out.push("mail");
        }
        let S3Section {
            endpoint,
            region,
            path_style,
        } = &self.s3;
        if endpoint.is_some() || region.is_some() || path_style.is_some() {
            out.push("s3");
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
        debug!(path = %path.display(), "configuration loaded");
        cfg.sources.push(path.to_path_buf());
        Ok(cfg)
    }

    /// Parse configuration text (no file, no environment lookup beyond the
    /// `${VAR}` interpolation).
    pub fn parse(text: &str) -> std::result::Result<Config, String> {
        let mut value: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        interpolate(&mut value)?;
        Config::deserialize(value).map_err(|e| e.to_string())
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
            defaults.log,
            policy.known_hosts,
            policy.refuse_plaintext_auth,
            policy.refuse_insecure_tls,
            policy.require_signature,
            signing.key,
            signing.agent_fingerprint,
            verify.allowed_signers,
            verify.keyring,
            ssh.user,
            ssh.key,
            ssh.known_hosts_file,
            mail.smtp,
            mail.from,
            mail.max_attachment,
            s3.endpoint,
            s3.region,
            s3.path_style,
        );
        if !other.ssh.hostkey.is_empty() {
            self.ssh.hostkey = std::mem::take(&mut other.ssh.hostkey);
        }
        self.sources.append(&mut other.sources);
        self.warnings.append(&mut other.warnings);
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
        if let Some(v) = &self.policy.known_hosts {
            p.known_hosts = Some(v.clone());
        }
        p
    }
}

static GLOBAL: OnceLock<Config> = OnceLock::new();

/// The configuration this process runs with. Empty unless [`install`] was
/// called, so the library keeps working without a configuration file.
pub fn global() -> &'static Config {
    GLOBAL.get_or_init(Config::default)
}

/// Publish the loaded configuration for the rest of the process, and install
/// its `[policy]` section. Only the first call has an effect.
pub fn install(cfg: Config) {
    crate::policy::set_policy(cfg.policy());
    let _ = GLOBAL.set(cfg);
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

/// Expand a leading `~/` against the home directory.
pub fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
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

    #[test]
    fn a_local_file_only_contributes_defaults_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mpt.toml");
        std::fs::write(&path, "[defaults]\ntimeout = 5\n[ssh]\nuser = \"nobody\"\n").unwrap();
        let cfg = Config::read_local(&path).unwrap().unwrap();
        assert_eq!(cfg.defaults.timeout, Some(5));
        assert!(cfg.ssh.user.is_none(), "[ssh] must be dropped");
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
