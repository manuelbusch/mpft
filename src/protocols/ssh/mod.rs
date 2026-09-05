//! Shared SSH session handling for `sftp://` and `scp://`.
//!
//! Authentication order: explicit key (`?key=` / `MPT_SSH_KEY`) → ssh-agent
//! (`SSH_AUTH_SOCK`) → default key files in `~/.ssh` → password.
//! Host keys are verified against `~/.ssh/known_hosts` according to the
//! `known_hosts` option: `strict`, `accept-new` (default) or `off`.

pub mod scp;
pub mod sftp;

use std::path::PathBuf;
use std::sync::Arc;
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
            None => KnownHostsPolicy::AcceptNew,
        };
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
        let handler = ClientHandler {
            host: self.host.clone(),
            port: self.port,
            policy: self.known_hosts,
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
        .map_err(ssh_err)?;

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
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if self.policy == KnownHostsPolicy::Off {
            return Ok(true);
        }
        let key: PublicKey = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
        };
        match check_known_hosts(&self.host, self.port, &key) {
            Ok(true) => Ok(true),
            Ok(false) => match self.policy {
                KnownHostsPolicy::AcceptNew => {
                    warn!(host = %self.host, "host key not in known_hosts; adding it (known_hosts=accept-new)");
                    if let Err(e) = learn_known_hosts(&self.host, self.port, &key) {
                        warn!("could not write known_hosts: {e}");
                    }
                    Ok(true)
                }
                _ => {
                    warn!(host = %self.host, "host key unknown and known_hosts=strict");
                    Ok(false)
                }
            },
            Err(russh::keys::Error::KeyChanged { line }) => {
                warn!(host = %self.host, line, "HOST KEY CHANGED — refusing to connect");
                Ok(false)
            }
            Err(e) => {
                warn!("known_hosts check failed: {e}");
                Ok(self.policy != KnownHostsPolicy::Strict)
            }
        }
    }
}

pub(crate) fn ssh_err(e: russh::Error) -> Error {
    match e {
        russh::Error::NotAuthenticated => Error::Auth("not authenticated".into()),
        russh::Error::UnknownKey => Error::Auth(
            "server host key rejected (check known_hosts or use ?known_hosts=accept-new)".into(),
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
