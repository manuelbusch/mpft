//! The relay's own SSH server: a host key, an `authorized_keys` file, and
//! nothing but `exec "mpt relay"` on a session channel. No shell, no
//! forwarding, no sftp — a client that is in the file may relay, and that
//! is all.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use russh::keys::ssh_key::{self, AuthorizedKeys, LineEnding};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::Relay;
use crate::{Error, Result};

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
        abort: abort.clone(),
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
    let running = shared.running.load(Ordering::SeqCst);
    if running > 0 {
        info!(running, grace = ?cfg.grace, "no longer accepting, waiting for the running relays");
        let wait = async {
            while shared.running.load(Ordering::SeqCst) > 0 {
                shared.idle.notified().await;
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
    abort: CancellationToken,
}

/// One client connection: authenticated by a key in the file, then one
/// session channel that runs the relay.
struct Connection {
    shared: Arc<Shared>,
    peer: std::net::SocketAddr,
    channel: Option<Channel<Msg>>,
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        if self.shared.keys.allows(key) {
            info!(peer = %self.peer, user, fingerprint = %key.fingerprint(HashAlg::Sha256), "relay login");
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
        if self.channel.is_some() {
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
        // `mpt relay` with or without arguments; nothing else runs here.
        let command = String::from_utf8_lossy(data);
        let mut words = command.split_whitespace();
        let is_relay =
            words.next().is_some_and(|w| w.ends_with("mpt")) && words.next() == Some("relay");
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
        session.channel_success(id)?;
        let handle = session.handle();
        let shared = Arc::clone(&self.shared);
        let peer = self.peer;
        tokio::spawn(async move {
            let code = relay_on(&shared, channel, &handle, id).await;
            debug!(%peer, code, "relay over");
        });
        Ok(())
    }
}

/// The relay itself, counted for the shutdown, one slot at a time.
async fn relay_on(shared: &Shared, channel: Channel<Msg>, handle: &Handle, id: ChannelId) -> u8 {
    shared.running.fetch_add(1, Ordering::SeqCst);
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
                    cache_limit: shared.relay.cache_limit,
                    locate: Arc::clone(&shared.relay.locate),
                    max_size: shared.relay.max_size,
                    credentials: shared.relay.credentials,
                    cancel: shared.abort.child_token(),
                };
                let code = super::run(&relay, reader, &mut writer).await;
                let _ = writer.flush().await;
                code
            }
        }
    };
    let _ = handle.exit_status_request(id, u32::from(code)).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
    if shared.running.fetch_sub(1, Ordering::SeqCst) == 1 {
        shared.idle.notify_waiters();
    }
    code
}

/// The `authorized_keys` file, re-read whenever it changes.
struct Keys {
    path: PathBuf,
    state: Mutex<(Option<SystemTime>, Vec<PublicKey>)>,
}

impl Keys {
    fn new(path: &Path) -> Result<Keys> {
        let keys = Keys {
            path: path.to_path_buf(),
            state: Mutex::new((None, Vec::new())),
        };
        keys.reload()?;
        Ok(keys)
    }

    fn reload(&self) -> Result<()> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .map_err(|e| Error::Config(format!("authorized_keys {}: {e}", self.path.display())))?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.0 == Some(modified) {
            return Ok(());
        }
        let entries = AuthorizedKeys::read_file(&self.path)
            .map_err(|e| Error::Config(format!("authorized_keys {}: {e}", self.path.display())))?;
        let keys: Vec<PublicKey> = entries
            .into_iter()
            .map(|e| e.public_key().clone())
            .collect();
        info!(keys = keys.len(), path = %self.path.display(), "authorized_keys read");
        *state = (Some(modified), keys);
        Ok(())
    }

    fn allows(&self, key: &PublicKey) -> bool {
        if let Err(e) = self.reload() {
            warn!("{e}");
        }
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.1.iter().any(|k| k.key_data() == key.key_data())
    }
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
struct OsRandom;

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
            };
            let relay = Arc::new(Relay {
                copy: CopyOptions::default(),
                cache_limit: 1 << 20,
                locate: Arc::new(|url, _| crate::Location::parse(url)),
                max_size: 0,
                credentials: super::super::RelayCredentials::Header,
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
        let cfg = SshConfig::from_location(&f.via("client_key")).unwrap();
        let handle = cfg.connect().await.unwrap();
        let mut channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "ls").await.unwrap();
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
        assert!(refused, "a shell command must be refused");
        disconnect(&handle).await;
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
