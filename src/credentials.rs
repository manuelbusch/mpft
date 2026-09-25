//! Where a secret comes from.
//!
//! The configuration file should not hold passwords. It holds a reference
//! instead, and the secret is fetched when the endpoint is about to be used:
//!
//! ```toml
//! [profiles.prod]
//! url      = "sftp://deploy@srv.example.com/data/"
//! password = { env = "PROD_PW" }                    # environment variable
//! # password = { file = "~/.config/mpt/prod.pw" }   # first line of a file
//! # password = { cmd = "op read op://Infra/prod/password" }   # any secret manager
//! # password = { keyring = "mpt/prod" }             # OS key store  (feature "keyring")
//! # password = { vault = "secret/data/mpt/prod#password" }    # (feature "vault")
//! ```
//!
//! `cmd` runs what the file says, which is why the file's permissions are
//! checked and why `./mpt.toml` may not carry credentials at all.
//!
//! What `cmd`, `keyring` and `vault` return is kept for a while, ten minutes
//! unless the reference says otherwise (`{ cmd = "…", ttl = "1h" }`), so that
//! endpoints sharing a reference do not fetch it again each, and so that a
//! short-lived access token is fetched anew in a process that runs longer.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{Error, Result};

/// A password, passphrase or access key in the configuration. Its `Debug`
/// shows a literal as `***`, so a configuration can be logged.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum Secret {
    /// Written out in the file. Works, but warns: anyone who can read the
    /// file has the password, and backups keep it.
    Literal(String),
    /// Fetched when it is needed.
    Reference(SecretRef),
}

/// Where to get a secret from, and how long a fetched value may be used.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawRef")]
pub struct SecretRef {
    pub source: Source,
    /// How long a value from `cmd`, `keyring` or `vault` is used before it
    /// is fetched again; zero fetches it every time. `None` is the default,
    /// [`DEFAULT_TTL`].
    pub ttl: Option<Duration>,
}

/// How long a fetched secret is kept unless its reference says otherwise.
pub const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// A reference as it is written: one provider key, and `ttl`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRef {
    env: Option<String>,
    file: Option<String>,
    cmd: Option<String>,
    keyring: Option<String>,
    vault: Option<String>,
    ttl: Option<String>,
}

impl TryFrom<RawRef> for SecretRef {
    type Error = String;
    fn try_from(raw: RawRef) -> std::result::Result<SecretRef, String> {
        let mut sources: Vec<Source> = [
            raw.env.map(Source::Env),
            raw.file.map(Source::File),
            raw.cmd.map(Source::Cmd),
            raw.keyring.map(Source::Keyring),
            raw.vault.map(Source::Vault),
        ]
        .into_iter()
        .flatten()
        .collect();
        if sources.len() != 1 {
            return Err(
                "a credential reference names exactly one of env, file, cmd, keyring, vault".into(),
            );
        }
        let ttl = raw
            .ttl
            .map(|v| crate::config::parse_duration(&v).map_err(|e| format!("ttl: {e}")))
            .transpose()?;
        Ok(SecretRef {
            source: sources.remove(0),
            ttl,
        })
    }
}

impl From<Source> for SecretRef {
    fn from(source: Source) -> SecretRef {
        SecretRef { source, ttl: None }
    }
}

/// The provider of a secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    /// Environment variable, for CI, containers and systemd `LoadCredential`.
    Env(String),
    /// First line of a file. The file's permissions are checked.
    File(String),
    /// Standard output of a command: `op read …`, `bw get …`, `pass show …`,
    /// `gcloud auth print-access-token`, … Run through `sh -c`.
    Cmd(String),
    /// `<service>/<user>` in the OS key store (macOS Keychain, Windows
    /// Credential Manager, Linux Secret Service).
    Keyring(String),
    /// `<path>#<field>` in HashiCorp Vault, read with `$VAULT_TOKEN` from
    /// `$VAULT_ADDR`.
    Vault(String),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Secret::Literal(_) => f.write_str("Literal(***)"),
            Secret::Reference(r) => f.debug_tuple("Reference").field(r).finish(),
        }
    }
}

impl Secret {
    /// The secret itself, fetching it if necessary. Results of the providers
    /// that cost something (a process, a network call) are kept for a while
    /// (see [`DEFAULT_TTL`]), so several endpoints can share one reference.
    /// A secret file others can read is refused under the installed
    /// policy's `strict_permissions`, and warned about otherwise.
    pub async fn resolve(&self, what: &str) -> Result<SecretString> {
        self.resolve_under(what, crate::policy::policy().strict_permissions)
            .await
    }

    /// [`Secret::resolve`] with `strict_permissions` given rather than taken
    /// from the installed policy: for a configuration that is not installed
    /// yet.
    pub async fn resolve_under(
        &self,
        what: &str,
        strict_permissions: bool,
    ) -> Result<SecretString> {
        match self {
            Secret::Literal(v) => {
                warn!(
                    "{what} is in the configuration file in the clear; \
                     prefer {{ env = … }}, {{ file = … }} or {{ cmd = … }}"
                );
                Ok(SecretString::from(v.clone()))
            }
            Secret::Reference(r) => r.resolve(what, strict_permissions).await,
        }
    }

    /// Whether this is a secret the file itself holds.
    pub fn is_literal(&self) -> bool {
        matches!(self, Secret::Literal(_))
    }
}

impl SecretRef {
    async fn resolve(&self, what: &str, strict_permissions: bool) -> Result<SecretString> {
        let ttl = self.ttl.unwrap_or(DEFAULT_TTL);
        if let Some(hit) = cached(&self.source, ttl) {
            debug!(%what, "secret already fetched");
            return Ok(hit);
        }
        // Every provider reports plainly what went wrong; what it was needed
        // for is added here, once.
        let fail = |e: String| Error::Auth(format!("{what}: {e}"));
        let value = match &self.source {
            Source::Env(name) => from_env(name),
            Source::File(path) => from_file(path, strict_permissions),
            Source::Cmd(cmd) => from_cmd(cmd).await,
            Source::Keyring(entry) => from_keyring(entry).await,
            Source::Vault(path) => from_vault(path).await,
        }
        .map_err(fail)?;
        if value.expose_secret().is_empty() {
            return Err(Error::Auth(format!("{what}: {} is empty", self.origin())));
        }
        debug!(%what, origin = %self.origin(), "secret fetched");
        // An environment variable and a file cost nothing to read again.
        if !matches!(self.source, Source::Env(_) | Source::File(_)) && !ttl.is_zero() {
            remember(&self.source, &value);
        }
        Ok(value)
    }

    /// Where the secret comes from, for messages. Never the secret itself.
    pub fn origin(&self) -> String {
        match &self.source {
            Source::Env(v) => format!("${v}"),
            Source::File(v) => v.clone(),
            Source::Cmd(v) => format!("`{v}`"),
            Source::Keyring(v) => format!("keyring {v}"),
            Source::Vault(v) => format!("vault {v}"),
        }
    }
}

/// Fetched secrets, with the moment each one was fetched.
type Cache = HashMap<Source, (SecretString, Instant)>;

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The value fetched for `source`, if it was fetched less than `ttl` ago.
fn cached(source: &Source, ttl: Duration) -> Option<SecretString> {
    let mut c = cache().lock().ok()?;
    match c.get(source) {
        Some((v, at)) if at.elapsed() < ttl => Some(v.clone()),
        Some(_) => {
            c.remove(source);
            None
        }
        None => None,
    }
}

fn remember(source: &Source, v: &SecretString) {
    if let Ok(mut c) = cache().lock() {
        c.insert(source.clone(), (v.clone(), Instant::now()));
    }
}

/// What a provider hands back: the secret, or plainly what went wrong.
type Fetched = std::result::Result<SecretString, String>;

fn from_env(name: &str) -> Fetched {
    std::env::var(name)
        .map(SecretString::from)
        .map_err(|_| format!("${name} is not set"))
}

fn from_file(path: &str, strict_permissions: bool) -> Fetched {
    let path = std::path::PathBuf::from(crate::config::expand_tilde(path));
    match exposure(&path) {
        Some(complaint) if strict_permissions => {
            return Err(format!(
                "{complaint} (refused by policy.strict_permissions)"
            ));
        }
        Some(complaint) => warn!("{complaint}"),
        None => {}
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(SecretString::from(first_line(&text)))
}

async fn from_cmd(cmd: &str) -> Fetched {
    debug!(%cmd, "running the credential command");
    // The shell of the platform: `sh -c` reads the command as written
    // everywhere but Windows, where `cmd /C` is the equivalent.
    let (shell, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let out = tokio::process::Command::new(shell)
        .arg(flag)
        .arg(cmd)
        .stdin(std::process::Stdio::null())
        // A caller that stops waiting (a server job that is cancelled)
        // takes the command down with it.
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("running `{cmd}`: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("`{cmd}` failed ({}): {}", out.status, err.trim()));
    }
    Ok(SecretString::from(first_line(&String::from_utf8_lossy(
        &out.stdout,
    ))))
}

#[cfg(feature = "keyring")]
async fn from_keyring(entry: &str) -> Fetched {
    let (service, user) = split_keyring_entry(entry).map_err(|e| e.to_string())?;
    // The key stores are synchronous and may prompt the user.
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(&service, &user)
            .map_err(|e| format!("keyring {service}/{user}: {e}"))?;
        entry
            .get_password()
            .map(SecretString::from)
            .map_err(|e| format!("keyring {service}/{user}: {e}"))
    })
    .await
    .map_err(|e| format!("keyring: {e}"))?
}

#[cfg(not(feature = "keyring"))]
async fn from_keyring(entry: &str) -> Fetched {
    split_keyring_entry(entry).map_err(|e| e.to_string())?;
    Err("keyring credentials need the 'keyring' feature, which is not compiled in".into())
}

/// `<service>/<user>`, the shape `mpt credentials` uses as well.
fn split_keyring_entry(entry: &str) -> Result<(String, String)> {
    match entry.rsplit_once('/') {
        Some((s, u)) if !s.is_empty() && !u.is_empty() => Ok((s.to_string(), u.to_string())),
        _ => Err(Error::Config(format!(
            "keyring reference '{entry}' must be <service>/<user>"
        ))),
    }
}

/// `<path>#<field>`, e.g. `secret/data/mpt/prod#password`.
fn split_vault_ref(reference: &str) -> Result<(&str, &str)> {
    match reference.split_once('#') {
        Some((p, f)) if !p.is_empty() && !f.is_empty() => Ok((p, f)),
        _ => Err(Error::Config(format!(
            "vault reference '{reference}' must be <path>#<field>, \
             e.g. secret/data/mpt/prod#password"
        ))),
    }
}

/// The field out of a Vault KV answer, which nests the data twice in v2
/// (`data.data.<field>`) and once in v1 (`data.<field>`).
#[cfg(feature = "vault")]
fn vault_field(body: &serde_json::Value, field: &str) -> Option<String> {
    let data = body.get("data")?;
    let holder = data.get("data").unwrap_or(data);
    holder.get(field)?.as_str().map(String::from)
}

#[cfg(feature = "vault")]
async fn from_vault(reference: &str) -> Fetched {
    let (path, field) = split_vault_ref(reference).map_err(|e| e.to_string())?;
    let addr = std::env::var("VAULT_ADDR").map_err(|_| "$VAULT_ADDR is not set".to_string())?;
    let token = std::env::var("VAULT_TOKEN").map_err(|_| "$VAULT_TOKEN is not set".to_string())?;
    let url = format!(
        "{}/v1/{}",
        addr.trim_end_matches('/'),
        path.trim_matches('/')
    );
    debug!(%url, "reading from vault");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Vault-Token", token)
        .send()
        .await
        .map_err(|e| format!("vault {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("vault {url}: {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("vault {url}: {e}"))?;
    vault_field(&body, field)
        .map(SecretString::from)
        .ok_or_else(|| format!("vault {url}: no field '{field}' in the answer"))
}

#[cfg(not(feature = "vault"))]
async fn from_vault(reference: &str) -> Fetched {
    split_vault_ref(reference).map_err(|e| e.to_string())?;
    Err("vault credentials need the 'vault' feature, which is not compiled in".into())
}

/// Store a secret in the OS key store, so that `{ keyring = "…" }` can find
/// it later. `entry` is `<service>/<user>`.
#[cfg(feature = "keyring")]
pub fn keyring_set(entry: &str, secret: &SecretString) -> Result<()> {
    let (service, user) = split_keyring_entry(entry)?;
    keyring::Entry::new(&service, &user)
        .and_then(|e| e.set_password(secret.expose_secret()))
        .map_err(|e| Error::Auth(format!("keyring {entry}: {e}")))
}

/// Remove a secret from the OS key store.
#[cfg(feature = "keyring")]
pub fn keyring_delete(entry: &str) -> Result<()> {
    let (service, user) = split_keyring_entry(entry)?;
    keyring::Entry::new(&service, &user)
        .and_then(|e| e.delete_credential())
        .map_err(|e| Error::Auth(format!("keyring {entry}: {e}")))
}

/// Read a secret back from the OS key store.
#[cfg(feature = "keyring")]
pub async fn keyring_get(entry: &str) -> Result<SecretString> {
    SecretRef::from(Source::Keyring(entry.to_string()))
        .resolve(&format!("keyring {entry}"), false)
        .await
}

/// First line without its line ending; a password file written by an editor
/// or by `echo` ends in a newline that is not part of the password.
pub fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

/// A secret file that others can read is a secret everyone has.
pub fn warn_if_world_readable(path: &std::path::Path) {
    if let Some(complaint) = exposure(path) {
        warn!("{complaint}");
    }
}

/// [`warn_if_world_readable`], or with `strict_permissions` a refusal to
/// use the file at all.
pub fn check_secret_file(path: &std::path::Path, strict_permissions: bool) -> Result<()> {
    match exposure(path) {
        Some(complaint) if strict_permissions => Err(Error::Config(format!(
            "{complaint} (refused by policy.strict_permissions)"
        ))),
        Some(complaint) => {
            warn!("{complaint}");
            Ok(())
        }
        None => Ok(()),
    }
}

/// What is wrong with where a secret file lies, if anything.
///
/// Windows has no mode bits to look at; the nearest useful check there is
/// whether the file lies outside the user's own profile, where the
/// inherited permissions are anybody's guess.
fn exposure(path: &std::path::Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path).ok()?;
        let mode = md.permissions().mode() & 0o777;
        (mode & 0o077 != 0).then(|| {
            format!(
                "{} is readable by others (mode {mode:o}); chmod 600 it",
                path.display()
            )
        })
    }
    #[cfg(not(unix))]
    outside_home(path).then(|| {
        format!(
            "{} holds a secret and lies outside your profile directory; \
             check who else can read it",
            path.display()
        )
    })
}

/// Whether `path` is outside the user's home directory (`%USERPROFILE%`).
#[cfg_attr(unix, allow(dead_code))]
fn outside_home(path: &std::path::Path) -> bool {
    let Some(home) = std::env::home_dir() else {
        return false;
    };
    match (std::fs::canonicalize(path), std::fs::canonicalize(&home)) {
        (Ok(p), Ok(h)) => !p.starts_with(h),
        _ => !path.starts_with(&home),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Holder {
        password: Secret,
    }

    fn parse(toml: &str) -> Secret {
        toml::from_str::<Holder>(toml).unwrap().password
    }

    #[test]
    fn references_and_literals() {
        assert!(matches!(
            parse("password = { env = \"PW\" }"),
            Secret::Reference(SecretRef { source: Source::Env(v), ttl: None }) if v == "PW"
        ));
        assert!(matches!(
            parse("password = { cmd = \"op read x\" }"),
            Secret::Reference(SecretRef {
                source: Source::Cmd(_),
                ..
            })
        ));
        assert!(matches!(
            parse("password = { cmd = \"op read x\", ttl = \"1h\" }"),
            Secret::Reference(SecretRef { ttl: Some(t), .. }) if t.as_secs() == 3600
        ));
        for bad in [
            "password = { cmd = \"a\", env = \"B\" }",
            "password = { ttl = \"1h\" }",
            "password = { cmd = \"a\", ttl = \"soon\" }",
        ] {
            assert!(toml::from_str::<Holder>(bad).is_err(), "{bad}");
        }
        assert!(parse("password = \"hunter2\"").is_literal());
        let err = toml::from_str::<Holder>("password = { keychain = \"x\" }").unwrap_err();
        assert!(err.to_string().contains("keychain"), "{err}");
    }

    #[tokio::test]
    async fn the_environment_and_a_file() {
        // SAFETY: single-threaded test, the variable is only read here.
        unsafe { std::env::set_var("MPT_TEST_SECRET", "from-env") };
        let s = parse("password = { env = \"MPT_TEST_SECRET\" }")
            .resolve("test")
            .await
            .unwrap();
        assert_eq!(s.expose_secret(), "from-env");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "from-file\nsecond line\n").unwrap();
        let s = Secret::Reference(SecretRef::from(Source::File(path.display().to_string())))
            .resolve("test")
            .await
            .unwrap();
        assert_eq!(s.expose_secret(), "from-file", "only the first line");

        let err = parse("password = { env = \"MPT_TEST_UNSET\" }")
            .resolve("test")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("MPT_TEST_UNSET"), "{err}");
    }

    #[tokio::test]
    async fn a_command_provides_and_may_fail() {
        let s = parse("password = { cmd = \"printf 'from-cmd\\n'\" }")
            .resolve("test")
            .await
            .unwrap();
        assert_eq!(s.expose_secret(), "from-cmd");

        let err = parse("password = { cmd = \"echo nope >&2; exit 3\" }")
            .resolve("test")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"), "{err}");

        let err = parse("password = { cmd = \"true\" }")
            .resolve("test")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "{err}");
    }

    /// A command's answer is kept for its reference's time to live, and
    /// fetched again after it; `ttl = "0"` fetches it every time.
    #[tokio::test]
    async fn a_fetched_secret_expires() {
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("n");
        let cmd = format!("echo x >> '{0}'; wc -l < '{0}'", counter.display());
        let fetch = |ttl: Option<Duration>| {
            let r = SecretRef {
                source: Source::Cmd(cmd.clone()),
                ttl,
            };
            async move {
                r.resolve("test", false)
                    .await
                    .unwrap()
                    .expose_secret()
                    .trim()
                    .to_string()
            }
        };
        let long = Some(Duration::from_secs(60));
        assert_eq!(fetch(long).await, "1");
        assert_eq!(fetch(long).await, "1", "kept");
        // A shorter time to live finds the same value too old.
        assert_eq!(fetch(Some(Duration::from_nanos(1))).await, "2");
        assert_eq!(fetch(Some(Duration::ZERO)).await, "3");
        assert_eq!(fetch(Some(Duration::ZERO)).await, "4", "never kept");
    }

    /// A literal does not show in debug output, and a secret file others
    /// can read is refused under strict_permissions.
    #[tokio::test]
    async fn literals_are_redacted_and_loose_files_refused() {
        let literal = parse("password = \"hunter2\"");
        assert!(!format!("{literal:?}").contains("hunter2"));
        let r = parse("password = { env = \"PW\" }");
        assert!(format!("{r:?}").contains("PW"), "a reference is shown");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pw");
            std::fs::write(&path, "s3cret\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let file = Secret::Reference(SecretRef::from(Source::File(path.display().to_string())));
            assert!(file.resolve_under("test", false).await.is_ok(), "a warning");
            let err = file
                .resolve_under("test", true)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("readable by others"), "{err}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(file.resolve_under("test", true).await.is_ok());
        }
    }

    #[test]
    fn references_are_checked_before_they_are_used() {
        assert!(split_keyring_entry("mpt/prod").is_ok());
        assert!(split_keyring_entry("prod").is_err());
        assert_eq!(
            split_vault_ref("secret/data/mpt/prod#password").unwrap(),
            ("secret/data/mpt/prod", "password")
        );
        assert!(split_vault_ref("secret/data/mpt/prod").is_err());
    }

    #[cfg(feature = "vault")]
    #[test]
    fn vault_answers_are_unwrapped() {
        let v2 = serde_json::json!({"data": {"data": {"password": "p2"}}});
        assert_eq!(vault_field(&v2, "password").unwrap(), "p2");
        let v1 = serde_json::json!({"data": {"password": "p1"}});
        assert_eq!(vault_field(&v1, "password").unwrap(), "p1");
        assert!(vault_field(&v1, "other").is_none());
    }
}
