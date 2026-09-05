//! Shared SSH session handling for `sftp://` and `scp://`.
//!
//! Authentication order: explicit key (`?key=` / `MPT_SSH_KEY`) → ssh-agent
//! (`SSH_AUTH_SOCK`) → default key files in `~/.ssh` → password.
//! Host keys are verified against `~/.ssh/known_hosts` according to the
//! `known_hosts` option: `strict` (default), `accept-new` or `off`.
//! `?hostkey=SHA256:…` pins one or more expected host keys and then replaces
//! the `known_hosts` lookup entirely.

pub mod scp;
pub mod sftp;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::known_hosts::{check_known_hosts, learn_known_hosts};
use russh::keys::{
    HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate, load_secret_key,
};
use tracing::{debug, info, warn};

use crate::{Error, Location, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostsPolicy {
    Strict,
    AcceptNew,
    Off,
}

impl KnownHostsPolicy {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "strict" | "yes" => KnownHostsPolicy::Strict,
            "accept-new" | "accept_new" | "acceptnew" => KnownHostsPolicy::AcceptNew,
            "off" | "no" | "false" | "none" => KnownHostsPolicy::Off,
            other => {
                return Err(Error::invalid_option(
                    "known_hosts",
                    format!("unknown policy '{other}'"),
                ));
            }
        })
    }
}

/// Everything needed to open an SSH session, derived from a [`Location`].
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub key_file: Option<PathBuf>,
    pub key_passphrase: Option<String>,
    pub known_hosts: KnownHostsPolicy,
    /// Expected host-key fingerprints (`SHA256:…`). Non-empty means the
    /// `known_hosts` file is not consulted at all.
    pub pinned_host_keys: Vec<String>,
    pub timeout: Duration,
}

impl SshConfig {
    pub fn from_location(loc: &Location) -> Result<Self> {
        let host = loc.host_required()?.to_string();
        let user = loc
            .username()
            .map(String::from)
            .or_else(|| std::env::var("MPT_SSH_USER").ok())
            .or_else(|| std::env::var("USER").ok())
            .ok_or_else(|| Error::Auth("no user name in URL and $USER is unset".into()))?;
        let key_file = loc
            .opt("key")
            .map(String::from)
            .or_else(|| std::env::var("MPT_SSH_KEY").ok())
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(expand_tilde(&s)));
        let key_passphrase = loc
            .opt("passphrase")
            .map(String::from)
            .or_else(|| std::env::var("MPT_SSH_KEY_PASSPHRASE").ok());
        let known_hosts = match loc
            .opt("known_hosts")
            .map(String::from)
            .or_else(|| std::env::var("MPT_SSH_KNOWN_HOSTS").ok())
        {
            Some(v) => KnownHostsPolicy::parse(&v)?,
            None => KnownHostsPolicy::Strict,
        };
        let mut pinned = Vec::new();
        for v in loc.opts("hostkey") {
            pinned.push(normalize_fingerprint(v)?);
        }
        if pinned.is_empty()
            && let Ok(v) = std::env::var("MPT_SSH_HOSTKEY")
            && !v.is_empty()
        {
            for part in v.split(',') {
                pinned.push(normalize_fingerprint(part)?);
            }
        }
        let timeout = loc
            .opt("timeout")
            .map(|t| {
                t.parse::<u64>()
                    .map_err(|e| Error::invalid_option("timeout", e))
            })
            .transpose()?
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        Ok(SshConfig {
            host,
            port: loc.port_or_default(),
            user,
            password: loc.password().map(String::from),
            key_file,
            key_passphrase,
            known_hosts,
            pinned_host_keys: pinned,
            timeout,
        })
    }

    /// Connect and authenticate.
    pub async fn connect(&self) -> Result<Handle<ClientHandler>> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(self.timeout.max(Duration::from_secs(60))),
            keepalive_interval: Some(Duration::from_secs(15)),
            ..Default::default()
        });
        let rejection: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let handler = ClientHandler {
            host: self.host.clone(),
            port: self.port,
            policy: self.known_hosts,
            pinned: self.pinned_host_keys.clone(),
            rejection: Arc::clone(&rejection),
        };
        debug!(host = %self.host, port = self.port, user = %self.user, "ssh connect");
        let mut handle = tokio::time::timeout(
            self.timeout,
            client::connect(config, (self.host.as_str(), self.port), handler),
        )
        .await
        .map_err(|_| {
            Error::Remote(format!(
                "connection to {}:{} timed out",
                self.host, self.port
            ))
        })?
        .map_err(|e| match rejection.lock().ok().and_then(|mut r| r.take()) {
            Some(why) => Error::Auth(why),
            None => ssh_err(e),
        })?;

        self.authenticate(&mut handle).await?;
        Ok(handle)
    }

    async fn authenticate(&self, handle: &mut Handle<ClientHandler>) -> Result<()> {
        let rsa_hash = handle
            .best_supported_rsa_hash()
            .await
            .map_err(ssh_err)?
            .flatten();
        let mut tried = Vec::new();

        // 1. explicit key file
        if let Some(path) = &self.key_file {
            tried.push(format!("key {}", path.display()));
            if self.try_key_file(handle, path, rsa_hash).await? {
                return Ok(());
            }
        } else {
            // 2. ssh-agent
            if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                tried.push("ssh-agent".into());
                match self.try_agent(handle, rsa_hash).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(e) => warn!("ssh-agent authentication failed: {e}"),
                }
            }
            // 3. default key files
            if let Some(home) = dirs::home_dir() {
                for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                    let path = home.join(".ssh").join(name);
                    if path.exists() {
                        tried.push(format!("key {}", path.display()));
                        match self.try_key_file(handle, &path, rsa_hash).await {
                            Ok(true) => return Ok(()),
                            Ok(false) => {}
                            Err(e) => warn!("key {} unusable: {e}", path.display()),
                        }
                    }
                }
            }
        }

        // 4. password
        if let Some(pw) = &self.password {
            tried.push("password".into());
            let res = handle
                .authenticate_password(self.user.clone(), pw.clone())
                .await
                .map_err(ssh_err)?;
            if res.success() {
                info!("ssh: authenticated with password");
                return Ok(());
            }
        }

        Err(Error::Auth(format!(
            "no accepted method for {}@{} (tried: {})",
            self.user,
            self.host,
            if tried.is_empty() {
                "nothing — provide a password, key or ssh-agent".to_string()
            } else {
                tried.join(", ")
            }
        )))
    }

    async fn try_key_file(
        &self,
        handle: &mut Handle<ClientHandler>,
        path: &PathBuf,
        rsa_hash: Option<HashAlg>,
    ) -> Result<bool> {
        let key = load_secret_key(path, self.key_passphrase.as_deref())
            .map_err(|e| Error::Auth(format!("cannot load key {}: {e}", path.display())))?;
        let res = handle
            .authenticate_publickey(
                self.user.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash),
            )
            .await
            .map_err(ssh_err)?;
        if res.success() {
            info!(key = %path.display(), "ssh: authenticated with key file");
        }
        Ok(res.success())
    }

    async fn try_agent(
        &self,
        handle: &mut Handle<ClientHandler>,
        rsa_hash: Option<HashAlg>,
    ) -> Result<bool> {
        let mut agent = AgentClient::connect_env()
            .await
            .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
        let identities = agent
            .request_identities()
            .await
            .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
        debug!(count = identities.len(), "ssh-agent identities");
        for id in identities {
            let key: PublicKey = id.public_key().into_owned();
            let res = handle
                .authenticate_publickey_with(self.user.clone(), key, rsa_hash, &mut agent)
                .await
                .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
            if res.success() {
                info!("ssh: authenticated via ssh-agent");
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// russh client handler: performs host-key verification.
pub struct ClientHandler {
    host: String,
    port: u16,
    policy: KnownHostsPolicy,
    pinned: Vec<String>,
    /// Filled with the reason when a host key is refused, so that `connect`
    /// can report it instead of russh's generic "unknown key".
    rejection: Arc<Mutex<Option<String>>>,
}

impl ClientHandler {
    /// Record why the host key was refused and return `false`. The reason
    /// travels out through `connect`, so it is only logged at debug level.
    fn reject(&self, why: String) -> bool {
        debug!("{why}");
        if let Ok(mut slot) = self.rejection.lock() {
            *slot = Some(why);
        }
        false
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key: PublicKey = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
        };
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let host = &self.host;
        let port = self.port;

        // An explicit pin replaces the known_hosts lookup.
        if !self.pinned.is_empty() {
            return Ok(if self.pinned.contains(&fp) {
                debug!(%host, %fp, "host key matches the pinned fingerprint");
                true
            } else {
                self.reject(format!(
                    "host key of {host}:{port} is {fp}, but hostkey= pins {}",
                    self.pinned.join(", ")
                ))
            });
        }
        if self.policy == KnownHostsPolicy::Off {
            warn!(%host, %fp, "host key not verified (known_hosts=off)");
            return Ok(true);
        }
        match check_known_hosts(host, port, &key) {
            Ok(true) => {
                debug!(%host, %fp, "host key found in known_hosts");
                Ok(true)
            }
            Ok(false) => match self.policy {
                KnownHostsPolicy::AcceptNew => {
                    warn!("adding new host key for {host}:{port} to known_hosts: {fp}");
                    if let Err(e) = learn_known_hosts(host, port, &key) {
                        warn!("could not write known_hosts: {e}");
                    }
                    Ok(true)
                }
                _ => Ok(self.reject(format!(
                    "host key of {host}:{port} is not in known_hosts: {fp}. \
                     Verify it, then add it with `ssh-keyscan -p {port} {host} >> ~/.ssh/known_hosts`, \
                     or connect with ?hostkey={fp} or ?known_hosts=accept-new"
                ))),
            },
            Err(russh::keys::Error::KeyChanged { line }) => Ok(self.reject(format!(
                "HOST KEY CHANGED for {host}:{port}: the server offers {fp}, \
                 but known_hosts line {line} holds a different key — refusing to connect"
            ))),
            // Unreadable or missing known_hosts must not silently grant trust.
            Err(e) => Ok(self.reject(format!(
                "cannot verify the host key of {host}:{port} ({fp}): {e}"
            ))),
        }
    }
}

/// Bring a user-supplied fingerprint into `SHA256:<base64>` form.
fn normalize_fingerprint(raw: &str) -> Result<String> {
    let v = raw.trim();
    // Query strings are form-decoded, so a literal '+' of the base64 arrives
    // as a space; spaces are never valid in a fingerprint, so map them back.
    let v = &v.replace(' ', "+");
    let body = v.strip_prefix("SHA256:").unwrap_or(v);
    let bad = || {
        Error::invalid_option(
            "hostkey",
            format!("'{v}' is not a SHA256 fingerprint (expected SHA256:<43 base64 chars>)"),
        )
    };
    if body.len() != 43
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(bad());
    }
    Ok(format!("SHA256:{body}"))
}

pub(crate) fn ssh_err(e: russh::Error) -> Error {
    match e {
        russh::Error::NotAuthenticated => Error::Auth("not authenticated".into()),
        russh::Error::UnknownKey => Error::Auth(
            "server host key rejected (add it to known_hosts, pin it with ?hostkey=SHA256:… \
             or use ?known_hosts=accept-new)"
                .into(),
        ),
        other => Error::transport("ssh", other),
    }
}

/// Gracefully disconnect; errors are logged, not propagated.
pub(crate) async fn disconnect(handle: &Handle<ClientHandler>) {
    if let Err(e) = handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
    {
        debug!("ssh disconnect: {e}");
    }
}

fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

/// Quote a path for a remote POSIX shell.
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_normalized() {
        let body = "f29GJDwDP5hekqa22VhNdaNPBM+q6AzG3FvQaBCJnmg";
        assert_eq!(
            normalize_fingerprint(body).unwrap(),
            format!("SHA256:{body}")
        );
        assert_eq!(
            normalize_fingerprint(&format!("  SHA256:{body} ")).unwrap(),
            format!("SHA256:{body}")
        );
        for bad in [
            "",
            "SHA256:",
            "MD5:aa:bb",
            "SHA256:tooshort",
            body.replace('+', "!").as_str(),
        ] {
            assert!(
                normalize_fingerprint(bad).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn default_policy_is_strict() {
        let loc = Location::parse("sftp://u@example.com/x").unwrap();
        let cfg = SshConfig::from_location(&loc).unwrap();
        assert_eq!(cfg.known_hosts, KnownHostsPolicy::Strict);
        assert!(cfg.pinned_host_keys.is_empty());
    }

    #[test]
    fn hostkey_option_is_collected() {
        let body = "f29GJDwDP5hekqa22VhNdaNPBM+q6AzG3FvQaBCJnmg";
        let loc =
            Location::parse(&format!("sftp://u@example.com/x?hostkey=SHA256:{body}")).unwrap();
        let cfg = SshConfig::from_location(&loc).unwrap();
        assert_eq!(cfg.pinned_host_keys, vec![format!("SHA256:{body}")]);
        let bad = Location::parse("sftp://u@example.com/x?hostkey=nonsense").unwrap();
        assert!(SshConfig::from_location(&bad).is_err());
    }
}
