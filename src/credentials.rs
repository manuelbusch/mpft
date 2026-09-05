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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{Error, Result};

/// A password, passphrase or access key in the configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Secret {
    /// Written out in the file. Works, but warns: anyone who can read the
    /// file has the password, and backups keep it.
    Literal(String),
    /// Fetched when it is needed.
    Reference(SecretRef),
}

/// Where to get a secret from.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SecretRef {
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

impl Secret {
    /// The secret itself, fetching it if necessary. Results of the providers
    /// that cost something (a process, a network call) are kept for the rest
    /// of the process, so several endpoints can share one reference.
    pub async fn resolve(&self, what: &str) -> Result<SecretString> {
        match self {
            Secret::Literal(v) => {
                warn!(
                    "{what} stands in the configuration file in the clear; \
                     prefer {{ env = … }}, {{ file = … }} or {{ cmd = … }}"
                );
                Ok(SecretString::from(v.clone()))
            }
            Secret::Reference(r) => r.resolve(what).await,
        }
    }

    /// Whether this is a secret the file itself holds.
    pub fn is_literal(&self) -> bool {
        matches!(self, Secret::Literal(_))
    }
}

impl SecretRef {
    async fn resolve(&self, what: &str) -> Result<SecretString> {
        if let Some(hit) = cached(self) {
            debug!(%what, "secret already fetched");
            return Ok(hit);
        }
        // Every provider reports plainly what went wrong; what it was needed
        // for is added here, once.
        let fail = |e: String| Error::Auth(format!("{what}: {e}"));
        let value = match self {
            SecretRef::Env(name) => from_env(name),
            SecretRef::File(path) => from_file(path),
            SecretRef::Cmd(cmd) => from_cmd(cmd).await,
            SecretRef::Keyring(entry) => from_keyring(entry).await,
            SecretRef::Vault(path) => from_vault(path).await,
        }
        .map_err(fail)?;
        if value.expose_secret().is_empty() {
            return Err(Error::Auth(format!("{what}: {} is empty", self.origin())));
        }
        debug!(%what, origin = %self.origin(), "secret fetched");
        if !matches!(self, SecretRef::Env(_) | SecretRef::File(_)) {
            remember(self, &value);
        }
        Ok(value)
    }

    /// Where the secret comes from, for messages. Never the secret itself.
    pub fn origin(&self) -> String {
        match self {
            SecretRef::Env(v) => format!("${v}"),
            SecretRef::File(v) => v.clone(),
            SecretRef::Cmd(v) => format!("`{v}`"),
            SecretRef::Keyring(v) => format!("keyring {v}"),
            SecretRef::Vault(v) => format!("vault {v}"),
        }
    }
}

fn cache() -> &'static Mutex<HashMap<SecretRef, SecretString>> {
    static CACHE: OnceLock<Mutex<HashMap<SecretRef, SecretString>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached(r: &SecretRef) -> Option<SecretString> {
    cache().lock().ok()?.get(r).cloned()
}

fn remember(r: &SecretRef, v: &SecretString) {
    if let Ok(mut c) = cache().lock() {
        c.insert(r.clone(), v.clone());
    }
}

/// What a provider hands back: the secret, or plainly what went wrong.
type Fetched = std::result::Result<SecretString, String>;

fn from_env(name: &str) -> Fetched {
    std::env::var(name)
        .map(SecretString::from)
        .map_err(|_| format!("${name} is not set"))
}

fn from_file(path: &str) -> Fetched {
    let path = std::path::PathBuf::from(crate::config::expand_tilde(path));
    warn_if_world_readable(&path);
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
    SecretRef::Keyring(entry.to_string())
        .resolve(&format!("keyring {entry}"))
        .await
}

/// First line without its line ending; a password file written by an editor
/// or by `echo` ends in a newline that is not part of the password.
pub fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

/// A secret file that others can read is a secret everyone has.
///
/// Windows has no mode bits to look at; the nearest useful check there is
/// whether the file lies outside the user's own profile, where the
/// inherited permissions are anybody's guess.
pub fn warn_if_world_readable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path)
            && md.permissions().mode() & 0o077 != 0
        {
            warn!(
                "{} is readable by others (mode {:o}); chmod 600 it",
                path.display(),
                md.permissions().mode() & 0o777
            );
        }
    }
    #[cfg(not(unix))]
    if outside_home(path) {
        warn!(
            "{} holds a secret and lies outside your profile directory; \
             check who else can read it",
            path.display()
        );
    }
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
            Secret::Reference(SecretRef::Env(v)) if v == "PW"
        ));
        assert!(matches!(
            parse("password = { cmd = \"op read x\" }"),
            Secret::Reference(SecretRef::Cmd(_))
        ));
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
        let s = Secret::Reference(SecretRef::File(path.display().to_string()))
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
