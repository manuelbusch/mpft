//! Shared SSH session handling for `sftp://` and `scp://`.
//!
//! Authentication order: explicit key (`?key=` / `MPFT_SSH_KEY`) → the
//! ssh-agent a relay client forwarded → the local ssh-agent (`SSH_AUTH_SOCK`)
//! → default key files in `~/.ssh` → password. A URL a relay's client named
//! ([`Location::is_client_named`]) may not name a key file, and skips the
//! local agent, the default keys and the configured key unless the relay
//! runs with `--own-keys` ([`Location::own_keys`]).
//! Host keys are verified against `~/.ssh/known_hosts` according to the
//! `known_hosts` option: `strict` (default), `accept-new` or `off`.
//! `?hostkey=SHA256:…` pins one or more expected host keys and then replaces
//! the `known_hosts` lookup entirely.

pub mod agent;
pub mod scp;
pub mod sftp;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::known_hosts::{
    check_known_hosts, check_known_hosts_path, learn_known_hosts, learn_known_hosts_path,
};
use russh::keys::ssh_key::Certificate;
use russh::keys::{
    HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate, load_secret_key,
};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, warn};

use crate::broker::{AgentSource, AgentStream, Brokers};
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

    /// How much checking the policy does: `off` least, `strict` most.
    fn rank(self) -> u8 {
        match self {
            KnownHostsPolicy::Off => 0,
            KnownHostsPolicy::AcceptNew => 1,
            KnownHostsPolicy::Strict => 2,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            KnownHostsPolicy::Strict => "strict",
            KnownHostsPolicy::AcceptNew => "accept-new",
            KnownHostsPolicy::Off => "off",
        }
    }

    /// The host-key policy for `loc`: its `?known_hosts=`, else
    /// `MPFT_SSH_KNOWN_HOSTS`, else `[policy] known_hosts`, else `strict`.
    /// `[policy] known_hosts` is also the least any of them may ask for:
    /// one that would check less is refused, as `?insecure=true` is under
    /// `refuse_insecure_tls`.
    fn for_location(loc: &Location) -> Result<Self> {
        let floor = crate::policy::policy()
            .known_hosts
            .as_deref()
            .map(KnownHostsPolicy::parse)
            .transpose()?;
        let asked = match loc.opt("known_hosts") {
            Some(v) => Some(("known_hosts", v.to_string())),
            None => std::env::var("MPFT_SSH_KNOWN_HOSTS")
                .ok()
                .map(|v| ("MPFT_SSH_KNOWN_HOSTS", v)),
        };
        KnownHostsPolicy::within(floor, asked, loc)
    }

    /// What `asked` for (where from, and the value) comes to under the
    /// policy's `floor`.
    fn within(
        floor: Option<KnownHostsPolicy>,
        asked: Option<(&str, String)>,
        loc: &Location,
    ) -> Result<Self> {
        let Some((from, value)) = asked else {
            return Ok(floor.unwrap_or(KnownHostsPolicy::Strict));
        };
        let policy = KnownHostsPolicy::parse(&value)?;
        match floor {
            Some(floor) if policy.rank() < floor.rank() => Err(Error::Config(format!(
                "{}: {from}={value} would check host keys less than \
                 policy.known_hosts = \"{}\" allows",
                loc.masked(),
                floor.as_str()
            ))),
            _ => Ok(policy),
        }
    }
}

/// Everything needed to open an SSH session, derived from a [`Location`].
#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_file: Option<PathBuf>,
    /// OpenSSH certificate for `key_file` (`<key>-cert.pub`), which lets a CA
    /// vouch for the key instead of `authorized_keys` listing it.
    pub cert_file: Option<PathBuf>,
    pub key_passphrase: Option<SecretString>,
    pub known_hosts: KnownHostsPolicy,
    /// Expected host-key fingerprints (`SHA256:…`). Non-empty means the
    /// `known_hosts` file is not consulted at all.
    pub pinned_host_keys: Vec<String>,
    /// `known_hosts` file to consult; `None` uses OpenSSH's own default.
    pub known_hosts_file: Option<PathBuf>,
    /// Deadline for connecting and authenticating.
    pub timeout: Duration,
    /// Inactivity limit for the data streams; `None` disables it.
    pub idle: Option<Duration>,
    /// How often to retry connecting after a transient failure.
    pub connect_retries: u32,
    /// Where to get the password and an agent at login time when the
    /// location does not carry them: the client behind a relay session.
    pub brokers: Brokers,
    /// An agent to serve to the server when it asks for one: what a relay
    /// client forwards so the relay can authenticate with the client's
    /// keys. Nothing is offered unless the session asks for forwarding.
    pub forward: Option<Arc<dyn AgentSource>>,
    /// The location itself, for the password it carries or asks for.
    loc: Location,
    /// Logins so far, shared by the clones of this config, so a password
    /// broker can tell the reconnects apart.
    logins: Arc<AtomicU32>,
}

/// By hand, so the location's query options (a passphrase among them) stay
/// out of the output.
impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.loc.has_password())
            .field("key_file", &self.key_file)
            .field("cert_file", &self.cert_file)
            .field("key_passphrase", &self.key_passphrase.is_some())
            .field("known_hosts", &self.known_hosts)
            .field("pinned_host_keys", &self.pinned_host_keys)
            .field("known_hosts_file", &self.known_hosts_file)
            .field("timeout", &self.timeout)
            .field("idle", &self.idle)
            .field("connect_retries", &self.connect_retries)
            .field("brokers", &self.brokers)
            .field("forward", &self.forward.is_some())
            .finish()
    }
}

impl SshConfig {
    pub fn from_location(loc: &Location) -> Result<Self> {
        let cfg = crate::config::global();
        let host = loc.host_required()?.to_string();
        let user = loc
            .username()
            .map(String::from)
            .or_else(|| std::env::var("MPFT_SSH_USER").ok())
            .or_else(|| cfg.ssh.user.clone())
            .or_else(|| std::env::var("USER").ok())
            .ok_or_else(|| Error::Auth("no user name in URL and $USER is unset".into()))?;
        // A URL a relay's client named may not point at files on the relay
        // host, and gets the relay's own identity only when the relay
        // allows it; the forwarded agent and a password remain.
        if loc.is_client_named() {
            for opt in ["key", "cert", "passphrase"] {
                if loc.opt(opt).is_some() {
                    return Err(Error::invalid_option(
                        opt,
                        format!(
                            "{loc}: names a file on the relay host, which a client may not use; \
                             let the relay use the forwarded agent, or give the target a password"
                        ),
                    ));
                }
            }
        }
        let own = loc.own_keys();
        let configured = |value: Option<String>| value.filter(|_| own);
        let key_file = loc
            .opt("key")
            .map(String::from)
            .or_else(|| configured(std::env::var("MPFT_SSH_KEY").ok()))
            .or_else(|| configured(cfg.ssh.key.clone()))
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(expand_tilde(&s)));
        // OpenSSH looks for <key>-cert.pub next to the key; so do we.
        let cert_file = loc
            .opt("cert")
            .map(String::from)
            .or_else(|| configured(std::env::var("MPFT_SSH_CERT").ok()))
            .or_else(|| configured(cfg.ssh.cert.clone()))
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(expand_tilde(&s)))
            .or_else(|| {
                let beside = PathBuf::from(format!("{}-cert.pub", key_file.as_ref()?.display()));
                beside.exists().then_some(beside)
            });
        let key_passphrase = loc
            .opt("passphrase")
            .map(String::from)
            .or_else(|| configured(std::env::var("MPFT_SSH_KEY_PASSPHRASE").ok()))
            .map(SecretString::from)
            .or_else(|| cfg.resolved.ssh_passphrase.clone().filter(|_| own));
        let known_hosts = KnownHostsPolicy::for_location(loc)?;
        let mut pinned = Vec::new();
        for v in loc.opts("hostkey") {
            pinned.push(normalize_fingerprint(v)?);
        }
        if pinned.is_empty()
            && let Ok(v) = std::env::var("MPFT_SSH_HOSTKEY")
            && !v.is_empty()
        {
            for part in v.split(',') {
                pinned.push(normalize_fingerprint(part)?);
            }
        }
        if pinned.is_empty() {
            for v in &cfg.ssh.hostkey {
                pinned.push(normalize_fingerprint(v)?);
            }
        }
        let timeout = loc.timeout_or(Duration::from_secs(30))?;
        // `?timeout=0` means "no inactivity limit" for the data streams; the
        // connect phase still needs a deadline.
        let idle = loc.timeout()?;
        Ok(SshConfig {
            host,
            port: loc.port_or_default(),
            user,
            key_file,
            cert_file,
            key_passphrase,
            known_hosts,
            pinned_host_keys: pinned,
            known_hosts_file: crate::config::path(&cfg.ssh.known_hosts_file),
            timeout,
            idle,
            connect_retries: loc.connect_retries()?,
            brokers: loc.brokers().clone(),
            forward: None,
            loc: loc.clone(),
            logins: Arc::new(AtomicU32::new(0)),
        })
    }

    /// Connect and authenticate, retrying transient failures.
    pub async fn connect(&self) -> Result<Handle<ClientHandler>> {
        crate::protocols::with_connect_retries(self.connect_retries, "ssh connect", || {
            self.connect_once()
        })
        .await
    }

    async fn connect_once(&self) -> Result<Handle<ClientHandler>> {
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
            known_hosts_file: self.known_hosts_file.clone(),
            rejection: Arc::clone(&rejection),
            forward: self.forward.clone(),
        };
        debug!(host = %self.host, port = self.port, user = %self.user, "ssh connect");
        let mut handle = tokio::time::timeout(
            self.timeout,
            client::connect(config, (self.host.as_str(), self.port), handler),
        )
        .await
        .map_err(|_| {
            // Io/TimedOut rather than Remote: a timeout is worth retrying.
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "connection to {}:{} timed out",
                    crate::location::bracket_host(&self.host),
                    self.port
                ),
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
            // 2. the agent a relay client forwarded
            if let Some(source) = &self.brokers.agent {
                tried.push("forwarded ssh-agent".into());
                match source.open().await {
                    Ok(stream) => match self.try_agent(handle, rsa_hash, stream).await {
                        Ok(true) => {
                            info!("ssh: authenticated via the forwarded ssh-agent");
                            return Ok(());
                        }
                        Ok(false) => {}
                        Err(e) => warn!("forwarded ssh-agent authentication failed: {e}"),
                    },
                    Err(e) => warn!("forwarded ssh-agent: {e}"),
                }
            }
            // 3. the local ssh-agent — this process's own identity, which
            // a URL a relay's client named gets only when the relay allows
            // it (`--own-keys`); the same goes for the default key files.
            if self.loc.own_keys() && agent::available() {
                tried.push("ssh-agent".into());
                match agent::connect_raw().await {
                    Ok(stream) => match self.try_agent(handle, rsa_hash, Box::new(stream)).await {
                        Ok(true) => {
                            info!("ssh: authenticated via ssh-agent");
                            return Ok(());
                        }
                        Ok(false) => {}
                        Err(e) => warn!("ssh-agent authentication failed: {e}"),
                    },
                    Err(e) => warn!("{e}"),
                }
            }
            // 4. default key files
            if self.loc.own_keys()
                && let Some(home) = dirs::home_dir()
            {
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

        // 5. password, fetched for this login only
        let attempt = self.logins.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(pw) = self.loc.login_password(attempt).await? {
            tried.push("password".into());
            let res = handle
                .authenticate_password(self.user.clone(), pw.expose_secret().to_string())
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
        let key = load_secret_key(
            path,
            self.key_passphrase.as_ref().map(|p| p.expose_secret()),
        )
        .map_err(|e| Error::Auth(format!("cannot load key {}: {e}", path.display())))?;
        // A certificate first: the server may trust the CA without knowing
        // this key. If it will not have it, the bare key still gets a turn.
        if let Some(cert_path) = &self.cert_file {
            let cert = Certificate::read_file(cert_path).map_err(|e| {
                Error::Auth(format!(
                    "cannot load certificate {}: {e}",
                    cert_path.display()
                ))
            })?;
            debug!(cert = %cert_path.display(), key_id = cert.key_id(), "ssh certificate");
            let res = handle
                .authenticate_openssh_cert(self.user.clone(), Arc::new(key.clone()), cert)
                .await
                .map_err(ssh_err)?;
            if res.success() {
                info!(cert = %cert_path.display(), "ssh: authenticated with a certificate");
                return Ok(true);
            }
            debug!("the server did not accept the certificate; trying the key itself");
        }
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

    /// Offer every identity the agent holds. A certificate is offered as a
    /// certificate: the server may trust its CA without knowing the key.
    async fn try_agent(
        &self,
        handle: &mut Handle<ClientHandler>,
        rsa_hash: Option<HashAlg>,
        stream: AgentStream,
    ) -> Result<bool> {
        let mut agent = AgentClient::connect(stream);
        let identities = agent
            .request_identities()
            .await
            .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
        debug!(count = identities.len(), "ssh-agent identities");
        for id in identities {
            let res = match &id {
                AgentIdentity::Certificate { certificate, .. } => {
                    debug!(key_id = certificate.key_id(), "ssh-agent certificate");
                    handle
                        .authenticate_certificate_with(
                            self.user.clone(),
                            certificate.clone(),
                            rsa_hash,
                            &mut agent,
                        )
                        .await
                }
                AgentIdentity::PublicKey { key, .. } => {
                    handle
                        .authenticate_publickey_with(
                            self.user.clone(),
                            key.clone(),
                            rsa_hash,
                            &mut agent,
                        )
                        .await
                }
            }
            .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
            if res.success() {
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
    known_hosts_file: Option<PathBuf>,
    /// Filled with the reason when a host key is refused, so that `connect`
    /// can report it instead of russh's generic "unknown key".
    rejection: Arc<Mutex<Option<String>>>,
    /// Served on every agent channel the server opens, when set.
    forward: Option<Arc<dyn AgentSource>>,
}

impl ClientHandler {
    /// Record why the host key was refused and return `false`. The reason
    /// travels out through `connect`, so it is only logged at debug level.
    /// Look the host up in the configured `known_hosts` file, or in the one
    /// OpenSSH itself would use.
    fn check_known_hosts(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> std::result::Result<bool, russh::keys::Error> {
        match &self.known_hosts_file {
            Some(path) => check_known_hosts_path(host, port, key, path),
            None => check_known_hosts(host, port, key),
        }
    }

    fn learn_known_hosts(
        &self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> std::result::Result<(), russh::keys::Error> {
        match &self.known_hosts_file {
            Some(path) => learn_known_hosts_path(host, port, key, path),
            None => learn_known_hosts(host, port, key),
        }
    }

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

    /// The server wants the agent that was forwarded: connect it to a
    /// fresh agent stream and copy both ways until either side is done.
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        let Some(source) = self.forward.clone() else {
            debug!("agent channel refused: nothing forwarded");
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut agent = match source.open().await {
                Ok(a) => a,
                Err(e) => {
                    debug!("agent channel: {e}");
                    return;
                }
            };
            let mut stream = channel.into_stream();
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut agent).await {
                debug!("agent channel ended: {e}");
            }
        });
        Ok(())
    }

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
        match self.check_known_hosts(host, port, &key) {
            Ok(true) => {
                debug!(%host, %fp, "host key found in known_hosts");
                Ok(true)
            }
            Ok(false) => match self.policy {
                KnownHostsPolicy::AcceptNew => {
                    warn!("adding new host key for {host}:{port} to known_hosts: {fp}");
                    if let Err(e) = self.learn_known_hosts(host, port, &key) {
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

    /// `[policy] known_hosts` is the least a URL or the variable may ask
    /// for; more is fine, and without a policy anything is.
    #[test]
    fn a_url_cannot_check_host_keys_less_than_the_policy() {
        use KnownHostsPolicy::{AcceptNew, Off, Strict};
        let loc = Location::parse("sftp://u:pw@h/x?known_hosts=off").unwrap();
        let asked = |floor, from: &'static str, value: Option<&str>| {
            KnownHostsPolicy::within(floor, value.map(|v| (from, v.to_string())), &loc)
                .map(KnownHostsPolicy::as_str)
        };
        let err = asked(Some(AcceptNew), "known_hosts", Some("off"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("known_hosts=off"), "{err}");
        assert!(err.contains("policy.known_hosts = \"accept-new\""), "{err}");
        assert!(!err.contains("pw"), "{err}");
        let err = asked(Some(Strict), "MPFT_SSH_KNOWN_HOSTS", Some("accept-new"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("MPFT_SSH_KNOWN_HOSTS=accept-new"), "{err}");
        assert_eq!(
            asked(Some(AcceptNew), "known_hosts", Some("strict")).unwrap(),
            "strict"
        );
        assert_eq!(
            asked(Some(AcceptNew), "known_hosts", Some("accept-new")).unwrap(),
            "accept-new"
        );
        assert_eq!(
            asked(Some(AcceptNew), "known_hosts", None).unwrap(),
            "accept-new"
        );
        assert_eq!(asked(Some(Off), "known_hosts", Some("off")).unwrap(), "off");
        assert_eq!(asked(None, "known_hosts", Some("off")).unwrap(), "off");
        assert_eq!(asked(None, "known_hosts", None).unwrap(), "strict");
    }

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
    fn secrets_stay_out_of_debug_output() {
        let loc = Location::parse("sftp://u:hunter2@example.com/x?passphrase=letmein").unwrap();
        let cfg = SshConfig::from_location(&loc).unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!debug.contains("letmein"), "{debug}");
        assert_eq!(
            cfg.key_passphrase.as_ref().map(|p| p.expose_secret()),
            Some("letmein")
        );
    }

    /// A URL a relay's client named may not point at a key file on the
    /// relay host, and gets the relay's own identity only with `--own-keys`.
    #[test]
    fn a_client_named_url_gets_none_of_the_relays_identity() {
        for opt in [
            "key=~/.ssh/id_ed25519",
            "cert=/etc/mpft/c.pub",
            "passphrase=x",
        ] {
            let mut loc = Location::parse(&format!("sftp://u@example.com/x?{opt}")).unwrap();
            loc.set_client_named(true);
            let err = SshConfig::from_location(&loc).unwrap_err().to_string();
            assert!(
                err.contains("names a file on the relay host"),
                "{opt}: {err}"
            );
            assert!(!err.contains("passphrase=x"), "{err}");
        }
        // The relay's own settings: `MPFT_SSH_KEY_PASSPHRASE` stands in for
        // `[ssh] key`, which the global configuration would carry.
        unsafe { std::env::set_var("MPFT_SSH_KEY_PASSPHRASE", "relay-secret") };
        let mut loc = Location::parse("sftp://u@example.com/x").unwrap();
        loc.set_client_named(false);
        let cfg = SshConfig::from_location(&loc).unwrap();
        assert!(cfg.key_passphrase.is_none());
        assert!(!cfg.loc.own_keys());
        loc.set_client_named(true);
        let cfg = SshConfig::from_location(&loc).unwrap();
        assert_eq!(
            cfg.key_passphrase.as_ref().map(|p| p.expose_secret()),
            Some("relay-secret")
        );
        assert!(cfg.loc.own_keys());
        unsafe { std::env::remove_var("MPFT_SSH_KEY_PASSPHRASE") };
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
