//! The relay's own SSH server: a host key, an `authorized_keys` file, and
//! nothing but `exec "mpt relay"` on a session channel. No shell, no port
//! forwarding, no sftp — a client that is in the file may relay, and that
//! is all. The user name of the login is not looked at: the key decides,
//! as the file has no accounts to tell apart, and the name is only logged.
//! Agent forwarding is taken, unless switched off: it is how the relay
//! authenticates against the SSH targets with the client's keys.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use russh::keys::ssh_key::{self, LineEnding};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::Relay;
use super::authorized_keys::Keys;
use crate::{Error, Result};

/// Relays one connection may have running or waiting for a slot at once.
/// Each holds a `--parallel` slot or a place in its queue; without a bound
/// one client could open sessions until nobody else gets a turn.
pub const MAX_SESSIONS_PER_CONNECTION: usize = 4;

/// Authentication attempts before the connection is dropped: what `sshd`
/// allows by default, enough for a client that offers several keys.
const MAX_AUTH_ATTEMPTS: usize = 6;

/// What `mpt relay --listen` needs.
#[derive(Debug, Clone)]
pub struct Listener {
    /// Address to listen on; port 0 picks a free one, see `port_file`.
    pub listen: std::net::SocketAddr,
    /// The host key; generated (ed25519) when the file is missing.
    pub host_key: PathBuf,
    /// OpenSSH `authorized_keys`: who may relay.
    pub authorized_keys: PathBuf,
    /// Relays running at once; further sessions wait for a slot.
    pub parallel: usize,
    /// How long a shutdown waits for running relays before cancelling them.
    pub grace: Duration,
    /// Write the port actually bound to this file.
    pub port_file: Option<PathBuf>,
    /// Accept a forwarded agent from the client.
    pub agent_forwarding: bool,
}

/// Listen until `cancel` fires, then stop accepting, wait `grace` for the
/// running relays and cancel what is left. `abort` cancels them at once.
pub async fn serve(
    cfg: Listener,
    relay: Arc<Relay>,
    cancel: CancellationToken,
    abort: CancellationToken,
) -> Result<()> {
    let key = load_or_create_host_key(&cfg.host_key)?;
    let keys = Arc::new(Keys::new(&cfg.authorized_keys)?);
    info!(
        fingerprint = %key.public_key().fingerprint(HashAlg::Sha256),
        authorized_keys = %cfg.authorized_keys.display(),
        "relay host key"
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    let bound = listener.local_addr()?;
    if let Some(path) = &cfg.port_file {
        std::fs::write(path, format!("{}\n", bound.port()))?;
    }
    info!(%bound, parallel = cfg.parallel, "relay listening");
    let ssh = Arc::new(russh::server::Config {
        methods: {
            let mut m = russh::MethodSet::empty();
            m.push(russh::MethodKind::PublicKey);
            m
        },
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(500),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: MAX_AUTH_ATTEMPTS,
        inactivity_timeout: Some(Duration::from_secs(600)),
        keepalive_interval: Some(Duration::from_secs(15)),
        ..Default::default()
    });
    let shared = Arc::new(Shared {
        relay,
        keys,
        slots: Semaphore::new(cfg.parallel.max(1)),
        running: AtomicUsize::new(0),
        idle: Notify::new(),
        stopping: cancel.clone(),
        abort: abort.clone(),
        agent_forwarding: cfg.agent_forwarding,
    });
    loop {
        let (socket, peer) = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    warn!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        debug!(%peer, "ssh connection");
        let handler = Connection {
            shared: Arc::clone(&shared),
            peer,
            channel: None,
            sessions: Arc::new(AtomicUsize::new(0)),
            agent: false,
            agent_allowed: false,
        };
        let ssh = Arc::clone(&ssh);
        tokio::spawn(async move {
            match russh::server::run_stream(ssh, socket, handler).await {
                Ok(session) => {
                    if let Err(e) = session.await {
                        debug!(%peer, "ssh session ended: {e}");
                    }
                }
                Err(e) => debug!(%peer, "ssh handshake failed: {e}"),
            }
        });
    }
    drop(listener);
    // A relay starting from here on sees `stopping` and is refused, or it
    // was counted before this load (see `Connection::start`).
    let running = shared.running.load(Ordering::SeqCst);
    if running > 0 {
        info!(running, grace = ?cfg.grace, "no longer accepting, waiting for the running relays");
        let wait = async {
            loop {
                // Registered before the count is read, so the last relay
                // ending in between still wakes it.
                let idle = shared.idle.notified();
                tokio::pin!(idle);
                idle.as_mut().enable();
                if shared.running.load(Ordering::SeqCst) == 0 {
                    break;
                }
                idle.await;
            }
        };
        tokio::select! {
            () = wait => {}
            () = abort.cancelled() => {}
            () = tokio::time::sleep(cfg.grace) => {
                warn!("grace period over, cancelling the running relays");
                abort.cancel();
            }
        }
    }
    Ok(())
}

/// What every connection shares.
struct Shared {
    relay: Arc<Relay>,
    keys: Arc<Keys>,
    slots: Semaphore,
    running: AtomicUsize,
    idle: Notify,
    /// No new sessions: the server is shutting down.
    stopping: CancellationToken,
    abort: CancellationToken,
    agent_forwarding: bool,
}

/// One client connection: authenticated by a key in the file, then session
/// channels that run relays, at most [`MAX_SESSIONS_PER_CONNECTION`] at a
/// time.
struct Connection {
    shared: Arc<Shared>,
    peer: std::net::SocketAddr,
    /// A session channel opened and not yet started.
    channel: Option<Channel<Msg>>,
    /// Relays of this connection running or waiting for a slot.
    sessions: Arc<AtomicUsize>,
    /// The client forwarded its agent and this server took it.
    agent: bool,
    /// The key the client logged in with may forward an agent (no
    /// `no-agent-forwarding` or `restrict` in `authorized_keys`).
    agent_allowed: bool,
}

/// The agent the client forwarded, reached by opening an agent channel
/// back to it for every login.
struct ForwardedAgent {
    handle: Handle,
}

#[async_trait::async_trait]
impl crate::broker::AgentSource for ForwardedAgent {
    async fn open(&self) -> Result<crate::broker::AgentStream> {
        let channel = self
            .handle
            .channel_open_agent()
            .await
            .map_err(|e| Error::Auth(format!("forwarded ssh-agent: {e}")))?;
        Ok(Box::new(channel.into_stream()))
    }
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        if let Some(grant) = self.shared.keys.allows(key, self.peer.ip()) {
            info!(peer = %self.peer, user, fingerprint = %key.fingerprint(HashAlg::Sha256), "relay login");
            self.agent_allowed = grant.agent_forwarding;
            Ok(Auth::Accept)
        } else {
            warn!(peer = %self.peer, user, fingerprint = %key.fingerprint(HashAlg::Sha256), "key not in authorized_keys");
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if self.channel.is_some()
            || self.sessions.load(Ordering::SeqCst) >= MAX_SESSIONS_PER_CONNECTION
        {
            debug!(peer = %self.peer, "session refused: too many at once on this connection");
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.channel = Some(channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        // `mpt relay`, the program possibly by its path; nothing else runs
        // here, and no argument is taken.
        let command = String::from_utf8_lossy(data);
        let words: Vec<&str> = command.split_whitespace().collect();
        let is_relay = matches!(
            words.as_slice(),
            [program, "relay"] if *program == "mpt" || program.ends_with("/mpt")
        );
        if is_relay {
            self.start(channel, session)
        } else {
            debug!(peer = %self.peer, %command, "exec refused");
            session.channel_failure(channel)
        }
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        if name == "mpt" {
            self.start(channel, session)
        } else {
            debug!(peer = %self.peer, name, "subsystem refused");
            session.channel_failure(channel)
        }
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<bool, Self::Error> {
        // The reply is a channel reply, which russh does not send for the
        // bool alone (it would answer a global request instead), so it is
        // sent here, and the bool is kept at `true` so nothing else goes
        // out.
        if !self.shared.agent_forwarding {
            debug!(peer = %self.peer, "agent forwarding refused (switched off)");
            session.channel_failure(channel)?;
        } else if !self.agent_allowed {
            debug!(peer = %self.peer, "agent forwarding refused (not for this key)");
            session.channel_failure(channel)?;
        } else {
            debug!(peer = %self.peer, "agent forwarding accepted");
            self.agent = true;
            session.channel_success(channel)?;
        }
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_failure(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> std::result::Result<(), Self::Error> {
        session.channel_failure(channel)
    }
}

impl Connection {
    /// Run the relay on the session's channel: stdin and stdout are the
    /// channel's data, the exit status is the relay's.
    fn start(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> std::result::Result<(), russh::Error> {
        let Some(channel) = self.channel.take() else {
            return session.channel_failure(id);
        };
        // Counted before the check, so a shutdown either waits for this
        // relay or has it refused (see `serve`).
        self.shared.running.fetch_add(1, Ordering::SeqCst);
        if self.shared.stopping.is_cancelled() {
            debug!(peer = %self.peer, "relay refused: shutting down");
            self.shared.finished();
            return session.channel_failure(id);
        }
        session.channel_success(id)?;
        let handle = session.handle();
        let shared = Arc::clone(&self.shared);
        let sessions = Arc::clone(&self.sessions);
        sessions.fetch_add(1, Ordering::SeqCst);
        let peer = self.peer;
        let agent: Option<Arc<dyn crate::broker::AgentSource>> = self.agent.then(|| {
            Arc::new(ForwardedAgent {
                handle: handle.clone(),
            }) as Arc<dyn crate::broker::AgentSource>
        });
        tokio::spawn(async move {
            let code = relay_on(&shared, channel, &handle, id, agent).await;
            sessions.fetch_sub(1, Ordering::SeqCst);
            debug!(%peer, code, "relay over");
        });
        Ok(())
    }
}

impl Shared {
    /// One relay less; the shutdown is told when it was the last.
    fn finished(&self) {
        if self.running.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.idle.notify_waiters();
        }
    }
}

/// The relay itself, one slot at a time; counted in [`Connection::start`].
async fn relay_on(
    shared: &Shared,
    channel: Channel<Msg>,
    handle: &Handle,
    id: ChannelId,
    agent: Option<Arc<dyn crate::broker::AgentSource>>,
) -> u8 {
    let code = {
        let permit = tokio::select! {
            biased;
            () = shared.abort.cancelled() => None,
            p = shared.slots.acquire() => p.ok(),
        };
        match permit {
            None => 130,
            Some(_permit) => {
                let (reader, mut writer) = tokio::io::split(channel.into_stream());
                let relay = Relay {
                    copy: shared.relay.copy.clone(),
                    locate: Arc::clone(&shared.relay.locate),
                    max_size: shared.relay.max_size,
                    max_entries: shared.relay.max_entries,
                    credentials: shared.relay.credentials,
                    allow_delete: shared.relay.allow_delete,
                    local_files: shared.relay.local_files,
                    cancel: shared.abort.child_token(),
                };
                let code = super::run_with(&relay, reader, &mut writer, agent).await;
                let _ = writer.flush().await;
                code
            }
        }
    };
    let _ = handle.exit_status_request(id, u32::from(code)).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
    shared.finished();
    code
}

/// The host key from `path`, or a new ed25519 key written there (mode
/// 0600) when there is none yet.
fn load_or_create_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        return PrivateKey::read_openssh_file(path)
            .map_err(|e| Error::Config(format!("host key {}: {e}", path.display())));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let key = PrivateKey::random(&mut OsRandom, Algorithm::Ed25519)
        .map_err(|e| Error::Config(format!("generating a host key: {e}")))?;
    key.write_openssh_file(path, LineEnding::LF)
        .map_err(|e| Error::Config(format!("writing the host key {}: {e}", path.display())))?;
    info!(path = %path.display(), "host key generated");
    Ok(key)
}

/// The operating system's randomness, as the key generator wants it.
pub(super) struct OsRandom;

impl ssh_key::rand_core::TryRng for OsRandom {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        getrandom::fill(dst).expect("the operating system's random source");
        Ok(())
    }
}

impl ssh_key::rand_core::TryCryptoRng for OsRandom {}

/// A fresh ed25519 key, for tests and tooling.
#[doc(hidden)]
pub fn generate_key() -> Result<PrivateKey> {
    PrivateKey::random(&mut OsRandom, Algorithm::Ed25519)
        .map_err(|e| Error::Config(format!("generating a key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ssh::{SshConfig, disconnect};
    use crate::relay::Header;
    use crate::relay::broker::NoAnswer;
    use crate::relay::client::{Session, send};
    use crate::transfer::CopyOptions;

    fn session<'a>(
        via: &'a crate::Location,
        header: &'a Header,
        body: Vec<u8>,
        cancel: &'a CancellationToken,
    ) -> Session<'a> {
        Session {
            via,
            header,
            body: Some(Box::pin(std::io::Cursor::new(body))),
            cancel,
            answer: Arc::new(NoAnswer),
            agent: None,
        }
    }

    /// A listener on a free port with `keys` authorized; the client's key
    /// file and the port come back with it.
    struct Fixture {
        dir: tempfile::TempDir,
        port: u16,
        cancel: CancellationToken,
        abort: CancellationToken,
        task: tokio::task::JoinHandle<Result<()>>,
    }

    impl Fixture {
        async fn start(parallel: usize) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let key = generate_key().unwrap();
            let key_path = dir.path().join("client_key");
            key.write_openssh_file(&key_path, LineEnding::LF).unwrap();
            let stranger = generate_key().unwrap();
            stranger
                .write_openssh_file(dir.path().join("stranger_key"), LineEnding::LF)
                .unwrap();
            std::fs::write(
                dir.path().join("authorized_keys"),
                format!(
                    "# a comment\n\nno-pty {} tester\n",
                    key.public_key().to_openssh().unwrap()
                ),
            )
            .unwrap();
            let cfg = Listener {
                listen: "127.0.0.1:0".parse().unwrap(),
                host_key: dir.path().join("keys").join("host_key"),
                authorized_keys: dir.path().join("authorized_keys"),
                parallel,
                grace: Duration::from_secs(5),
                port_file: Some(dir.path().join("port")),
                agent_forwarding: true,
            };
            let relay = Arc::new(Relay {
                copy: CopyOptions::default(),
                locate: Arc::new(|url, _| crate::Location::parse(url)),
                max_size: 0,
                max_entries: 0,
                credentials: super::super::RelayCredentials::Header,
                allow_delete: false,
                local_files: true,
                cancel: CancellationToken::new(),
            });
            let cancel = CancellationToken::new();
            let abort = CancellationToken::new();
            let task = tokio::spawn(serve(cfg, relay, cancel.clone(), abort.clone()));
            let port_file = dir.path().join("port");
            let started = std::time::Instant::now();
            let port = loop {
                if let Ok(text) = std::fs::read_to_string(&port_file)
                    && let Ok(p) = text.trim().parse::<u16>()
                {
                    break p;
                }
                assert!(started.elapsed() < Duration::from_secs(10), "no port file");
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            Fixture {
                dir,
                port,
                cancel,
                abort,
                task,
            }
        }

        fn via(&self, key: &str) -> crate::Location {
            crate::Location::parse(&format!(
                "ssh://relay@127.0.0.1:{}/?key={}&known_hosts=off",
                self.port,
                self.dir.path().join(key).display()
            ))
            .unwrap()
        }

        async fn stop(self) {
            self.cancel.cancel();
            self.abort.cancel();
            self.task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn a_key_in_the_file_may_relay() {
        let f = Fixture::start(2).await;
        assert!(f.dir.path().join("keys").join("host_key").exists());
        let out = f.dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let header = Header::stream(
            "blob.bin",
            payload.len() as u64,
            vec![format!("{}/", out.display())],
        );
        let mut lines = Vec::new();
        let via = f.via("client_key");
        let cancel = CancellationToken::new();
        let outcome = send(session(&via, &header, payload.clone(), &cancel), |l| {
            lines.push(l.clone())
        })
        .await
        .unwrap();
        assert_eq!(outcome.exit, 0, "{outcome:?}");
        assert_eq!(outcome.report.as_ref().unwrap()["ok"], true);
        assert!(outcome.error.is_none());
        assert_eq!(std::fs::read(out.join("blob.bin")).unwrap(), payload);
        assert!(lines.iter().any(|l| l.get("progress").is_some()));
        f.stop().await;
    }

    /// More than the initial credit: the relay has to grant more as the
    /// target takes the data, or the client's feeder waits forever.
    #[tokio::test]
    async fn credit_keeps_a_large_payload_flowing() {
        let f = Fixture::start(1).await;
        let out = f.dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let payload: Vec<u8> = (0..(super::super::protocol::INITIAL_CREDIT as usize * 2 + 777))
            .map(|i| (i % 251) as u8)
            .collect();
        let header = Header::stream(
            "big.bin",
            payload.len() as u64,
            vec![format!("{}/", out.display())],
        );
        let via = f.via("client_key");
        let cancel = CancellationToken::new();
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            send(session(&via, &header, payload.clone(), &cancel), |_| {}),
        )
        .await
        .expect("the copy does not stall")
        .unwrap();
        assert_eq!(outcome.exit, 0, "{outcome:?}");
        assert_eq!(std::fs::read(out.join("big.bin")).unwrap(), payload);
        f.stop().await;
    }

    #[tokio::test]
    async fn a_stranger_is_refused_and_so_is_a_shell() {
        let f = Fixture::start(1).await;
        let header = Header::stream("x", 1, vec!["/tmp/".into()]);
        let via = f.via("stranger_key");
        let cancel = CancellationToken::new();
        let err = send(session(&via, &header, vec![0u8], &cancel), |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Auth(_)), "{err}");

        // The right key, but something other than the relay.
        for (command, runs) in [
            ("ls", false),
            ("xmpt relay", false),
            ("mpt relay --allow-delete", false),
            ("mpt relay; ls", false),
            ("mpt", false),
            ("/usr/local/bin/mpt relay", true),
            ("mpt relay", true),
        ] {
            assert_eq!(exec(&f, command).await, runs, "{command}");
        }
        f.stop().await;
    }

    /// Whether the relay's server takes `command` on a new session.
    async fn exec(f: &Fixture, command: &str) -> bool {
        let cfg = SshConfig::from_location(&f.via("client_key")).unwrap();
        let handle = cfg.connect().await.unwrap();
        let mut channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, command).await.unwrap();
        let mut runs = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Failure => {
                    runs = Some(false);
                    break;
                }
                russh::ChannelMsg::Success => {
                    runs = Some(true);
                    break;
                }
                _ => {}
            }
        }
        disconnect(&handle).await;
        runs.expect("an answer to the command")
    }

    /// A connection that was open before the shutdown cannot start a
    /// relay after it, which the shutdown would not wait for.
    #[tokio::test]
    async fn no_relay_starts_once_the_server_stops() {
        let f = Fixture::start(1).await;
        let cfg = SshConfig::from_location(&f.via("client_key")).unwrap();
        let handle = cfg.connect().await.unwrap();
        let mut channel = handle.channel_open_session().await.unwrap();
        f.cancel.cancel();
        let Fixture { task, dir, .. } = f;
        task.await.unwrap().unwrap();
        channel.exec(true, "mpt relay").await.unwrap();
        let mut refused = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Failure => {
                    refused = true;
                    break;
                }
                russh::ChannelMsg::Success => break,
                _ => {}
            }
        }
        assert!(refused, "a relay started after the shutdown");
        disconnect(&handle).await;
        drop(dir);
    }

    /// `from=` in authorized_keys holds for the relay's own server: the
    /// key is refused from anywhere else, and the file is read anew for
    /// every login.
    #[tokio::test]
    async fn a_key_is_only_good_from_where_the_file_says() {
        let f = Fixture::start(1).await;
        let public = PrivateKey::read_openssh_file(f.dir.path().join("client_key"))
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let out = f.dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let header = Header::stream("x.bin", 1, vec![format!("{}/", out.display())]);
        let via = f.via("client_key");
        let cancel = CancellationToken::new();
        std::fs::write(
            f.dir.path().join("authorized_keys"),
            format!("from=\"10.0.0.0/8\" {public}\n"),
        )
        .unwrap();
        let err = send(session(&via, &header, vec![1u8], &cancel), |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Auth(_)), "{err}");
        std::fs::write(
            f.dir.path().join("authorized_keys"),
            format!("from=\"10.0.0.0/8,127.0.0.1\" {public}\n"),
        )
        .unwrap();
        let outcome = send(session(&via, &header, vec![1u8], &cancel), |_| {})
            .await
            .unwrap();
        assert_eq!(outcome.exit, 0, "{outcome:?}");
        f.stop().await;
    }

    /// A body that yields `good` bytes and then fails.
    struct Failing {
        good: usize,
    }

    impl tokio::io::AsyncRead for Failing {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.good == 0 {
                return std::task::Poll::Ready(Err(std::io::Error::other("disk on fire")));
            }
            let n = self.good.min(buf.remaining()).min(1000);
            buf.put_slice(&vec![7u8; n]);
            self.good -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A body that cannot be read ends the session with that error, and
    /// the relay fails its target instead of waiting for the rest.
    #[tokio::test]
    async fn a_read_error_on_this_side_ends_the_session() {
        let f = Fixture::start(1).await;
        let out = f.dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let header = Header::stream("x.bin", 100_000, vec![format!("{}/", out.display())]);
        let via = f.via("client_key");
        let cancel = CancellationToken::new();
        let mut s = session(&via, &header, Vec::new(), &cancel);
        s.body = Some(Box::pin(Failing { good: 5_000 }));
        let err = tokio::time::timeout(Duration::from_secs(20), send(s, |_| {}))
            .await
            .expect("the session ends")
            .unwrap_err();
        assert!(err.to_string().contains("disk on fire"), "{err}");
        // The relay notices the end and cleans up.
        let started = std::time::Instant::now();
        while std::fs::read_dir(&out).unwrap().next().is_some() {
            assert!(started.elapsed() < Duration::from_secs(10), "left behind");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        f.stop().await;
    }

    /// A body that has more or fewer bytes than the header says — a file
    /// that changed while it was sent — is an error of this side, and the
    /// relay finishes no target with it.
    #[tokio::test]
    async fn a_body_of_another_size_than_announced_is_not_delivered() {
        let f = Fixture::start(1).await;
        let out = f.dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let via = f.via("client_key");
        let cancel = CancellationToken::new();
        for (announced, actual, what) in [
            (100_000u64, 100_001usize, "grew"),
            (100_000, 150_000, "grew"),
            (100_000, 99_999, "ended after 99999 of 100000"),
        ] {
            let header = Header::stream("x.bin", announced, vec![format!("{}/", out.display())]);
            let s = session(&via, &header, vec![3u8; actual], &cancel);
            let err = tokio::time::timeout(Duration::from_secs(20), send(s, |_| {}))
                .await
                .expect("the session ends")
                .unwrap_err();
            assert!(
                err.to_string().contains(what),
                "{announced}/{actual}: {err}"
            );
            let started = std::time::Instant::now();
            while std::fs::read_dir(&out).unwrap().next().is_some() {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "{announced}/{actual}: delivered or left behind"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        f.stop().await;
    }

    /// One connection may have only so many relays running or waiting:
    /// past that, a session channel is refused until one is over.
    #[tokio::test]
    async fn a_connection_gets_only_so_many_sessions_at_once() {
        let f = Fixture::start(1).await;
        let cfg = SshConfig::from_location(&f.via("client_key")).unwrap();
        let handle = cfg.connect().await.unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_SESSIONS_PER_CONNECTION {
            let channel = handle.channel_open_session().await.unwrap();
            // Started (`exec` waits for the channel reply), so it holds a
            // place; the header never comes.
            channel.exec(true, "mpt relay").await.unwrap();
            held.push(channel);
        }
        assert!(
            handle.channel_open_session().await.is_err(),
            "one session too many was accepted"
        );
        // Once a session is over — its header never came — there is room
        // again.
        let started = std::time::Instant::now();
        loop {
            if handle.channel_open_session().await.is_ok() {
                break;
            }
            assert!(
                started.elapsed() < super::super::HEADER_TIMEOUT + Duration::from_secs(10),
                "no room again"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        f.stop().await;
    }

    #[tokio::test]
    async fn a_refused_header_comes_back_as_the_relays_error() {
        let f = Fixture::start(1).await;
        let header = Header::stream("x", 1, vec![]);
        let via = f.via("client_key");
        let cancel = CancellationToken::new();
        let outcome = send(session(&via, &header, vec![0u8], &cancel), |_| {})
            .await
            .unwrap();
        assert_eq!(outcome.exit, 2);
        assert_eq!(outcome.error.as_ref().unwrap()["kind"], "invalid_option");
        f.stop().await;
    }
}
