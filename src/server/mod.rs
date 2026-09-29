//! `mpft serve`: jobs over HTTP, progress by polling or WebSocket.
//!
//! A job is one transfer (a source and its targets) or a batch of them.
//! `POST /v1/jobs` and `POST /v1/batches` take one in and answer at once
//! with its id; the job is then prepared (URLs resolved, patterns and
//! trees expanded) and its transfers run under a server-wide limit.
//! `GET /v1/jobs/{id}` shows where it stands, transfer by transfer, and a
//! WebSocket on `/v1/jobs/{id}/events` pushes the same as it happens.
//!
//! [`serve`] runs the whole thing; [`router`] is the HTTP side alone, for
//! embedding in another axum application.

pub mod api;
pub mod model;
mod scheduler;
pub mod store;
mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::SecretString;
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::batch::Targets;
use crate::config::UrlRule;
use crate::transfer::CopyOptions;
use crate::{Error, Result};
use model::{ApiError, Event, JobId};
use store::{Journal, Store};

pub use api::router;

/// How the server is set up: the `[server]` section and the flags of
/// `mpft serve`, resolved.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Where to listen. Port 0 picks a free one; see `port_file`.
    pub bind: SocketAddr,
    /// The bearer token every request but the health check must carry.
    /// Without one, `bind` must be a loopback address.
    pub token: Option<SecretString>,
    /// JSONL journal of submitted jobs, for a restart to pick up what was
    /// left open. `None` keeps jobs in memory only.
    pub journal: Option<PathBuf>,
    /// How long finished jobs stay available; zero keeps them until the
    /// server stops.
    pub retention: Duration,
    /// Transfers in flight at once, over all jobs.
    pub parallel: usize,
    /// Largest request body in bytes.
    pub max_body: usize,
    /// How long a shutdown waits for running jobs before cancelling them.
    pub grace: Duration,
    /// Write the port actually bound to this file, for `bind` with port 0.
    pub port_file: Option<PathBuf>,
    /// Which URLs a job may name.
    pub urls: UrlRule,
    /// With [`UrlRule::Profiles`]: only these; empty means every profile.
    pub profiles: Vec<String>,
    /// Whether a job may set `delete_source`.
    pub allow_delete: bool,
    /// Transfers one job may hold after patterns and trees are expanded.
    pub max_transfers: usize,
    /// Jobs not yet finished before new ones are refused with 429.
    pub max_queued: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 7788)),
            token: None,
            journal: None,
            retention: Duration::from_secs(24 * 3600),
            parallel: 4,
            max_body: 8 << 20,
            grace: Duration::from_secs(30),
            port_file: None,
            urls: UrlRule::Profiles,
            profiles: Vec::new(),
            allow_delete: false,
            max_transfers: 10_000,
            max_queued: 1000,
        }
    }
}

impl ServerConfig {
    /// Refuse a setup that would expose the API: no token on an address
    /// others can reach.
    pub fn check(&self) -> Result<()> {
        if self.token.is_none() && !self.bind.ip().is_loopback() {
            return Err(Error::Config(format!(
                "refusing to listen on {} without a token: set [server] token \
                 (or --token-env), or bind to 127.0.0.1",
                self.bind
            )));
        }
        for (what, v) in [
            ("parallel", self.parallel),
            ("max_transfers", self.max_transfers),
            ("max_queued", self.max_queued),
        ] {
            if v == 0 {
                return Err(Error::Config(format!("[server] {what} must be at least 1")));
            }
        }
        if self.urls == UrlRule::Any && self.journal.is_some() {
            warn!(
                "[server] urls = \"any\" with a journal: a password given in a job's URL \
                 is written to the journal file"
            );
        }
        Ok(())
    }

    /// Whether every URL a job names may be used, under `urls` and
    /// `profiles`. The message says what to change.
    pub fn allow_url(&self, url: &str) -> Result<()> {
        let name = crate::config::profile_name(url);
        match (self.urls, name) {
            (UrlRule::Any, _) => Ok(()),
            (UrlRule::Profiles, None) => Err(Error::InvalidUrl(format!(
                "{url}: only mpft://<profile>/ endpoints are accepted \
                 (set [server] urls = \"any\" or --allow-any-url to allow others)"
            ))),
            (UrlRule::Profiles, Some(name)) => {
                // Options in the reference replace the profile's (`?key=`,
                // `?known_hosts=off`, `?endpoint=`), which would let a
                // client undo what the profile fixes.
                if crate::config::profile_ref_has_options(url) {
                    return Err(Error::InvalidUrl(format!(
                        "{url}: a job may not add ?options to a profile; set them in the profile"
                    )));
                }
                if !self.profiles.is_empty() && !self.profiles.iter().any(|p| p == name) {
                    return Err(Error::InvalidUrl(format!(
                        "{url}: profile '{name}' is not among those the server allows ({})",
                        self.profiles.join(", ")
                    )));
                }
                if !crate::config::global().profiles.contains_key(name) {
                    return Err(Error::InvalidUrl(format!(
                        "{url}: no profile '{name}' in the configuration"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// A URL to a location, with the job's options at hand.
pub use crate::options::LocateFn;

/// How jobs are run: the copy options every job starts from and how a URL
/// becomes a location.
#[derive(Clone)]
pub struct Runtime {
    /// The options a job's own lay over (see [`JobOptions::apply`]).
    pub copy: CopyOptions,
    /// URL to location, with whatever the server adds (a default timeout,
    /// `insecure`, a password from a flag). The job's options are there
    /// for `timeout`.
    pub locate: Arc<LocateFn>,
    /// Fetch signing secrets along with the endpoints' (`--sign` given).
    pub signing: bool,
    /// Transfers of one job in flight at once, unless the job says.
    pub parallel: usize,
    /// The relays of the profiles that name one: a job's source or target
    /// behind a relay is read, listed or written by it. `None` copies
    /// every job from here.
    #[cfg(feature = "relay")]
    pub via: Option<Arc<crate::relay::via::Via>>,
}

impl Runtime {
    /// Plain defaults: [`crate::config::locate`] with the job's `timeout`
    /// applied, no signing, four transfers per job.
    pub fn new(copy: CopyOptions) -> Runtime {
        Runtime {
            copy,
            locate: Arc::new(|url, opts| {
                let mut loc = crate::config::locate(url)?;
                if let Some(t) = opts.timeout
                    && loc.opt("timeout").is_none()
                {
                    loc.set_option("timeout", t.to_string());
                }
                Ok(loc)
            }),
            signing: false,
            parallel: 4,
            #[cfg(feature = "relay")]
            via: None,
        }
    }
}

/// Everything the handlers and the scheduler share.
pub struct AppState {
    cfg: ServerConfig,
    rt: Runtime,
    store: Store,
    /// The server-wide limit on transfers in flight; preparation holds a
    /// permit too, so a flood of submissions does not open a flood of
    /// listings.
    slots: Arc<Semaphore>,
    /// The files jobs are writing right now, so two jobs never share one.
    targets: Mutex<Targets>,
    /// Parent of every job's token: cancelled when the server stops
    /// waiting for them.
    work: CancellationToken,
    /// Cancelled when the server is about to exit; WebSocket clients are
    /// told to go.
    closing: CancellationToken,
    /// False once a shutdown has begun: submissions are refused.
    accepting: AtomicBool,
    /// WebSocket clients connected, so the progress ticker can rest when
    /// there are none.
    watchers: AtomicUsize,
    /// Jobs the journal handed over, to start with [`AppState::run`].
    recovered: Mutex<Vec<JobId>>,
    /// Held while a wrong token is answered: only so many guesses wait
    /// at once, the rest are refused outright (see `api::slow_down`).
    guesses: tokio::sync::Semaphore,
}

impl AppState {
    /// Set up the state, opening the journal if there is one.
    pub fn new(cfg: ServerConfig, rt: Runtime) -> Result<Arc<AppState>> {
        cfg.check()?;
        let (events, _) = broadcast::channel::<Event>(1024);
        let (journal, recovered) = match &cfg.journal {
            Some(path) => {
                let (j, r) = Journal::open(path)?;
                (Some(j), r)
            }
            None => (None, Vec::new()),
        };
        let store = Store::new(journal, events);
        let work = CancellationToken::new();
        let mut ids = Vec::with_capacity(recovered.len());
        for r in recovered {
            ids.push(r.id.clone());
            store.recover(r, work.child_token());
        }
        Ok(Arc::new(AppState {
            slots: Arc::new(Semaphore::new(cfg.parallel)),
            cfg,
            rt,
            store,
            targets: Mutex::new(Targets::shared()),
            work,
            closing: CancellationToken::new(),
            accepting: AtomicBool::new(true),
            watchers: AtomicUsize::new(0),
            recovered: Mutex::new(ids),
            guesses: tokio::sync::Semaphore::new(api::GUESSES_AT_ONCE),
        }))
    }

    /// Start what runs beside the handlers: the jobs the journal handed
    /// over, the progress ticker and the retention sweep. Call once, from
    /// inside a tokio runtime.
    pub fn run(self: &Arc<Self>) {
        let recovered =
            std::mem::take(&mut *self.recovered.lock().unwrap_or_else(|e| e.into_inner()));
        for id in recovered {
            // The configuration may have changed since the job was taken:
            // it runs again only if it would be accepted now.
            let refused = self
                .store
                .submission(&id)
                .and_then(|(s, _)| self.admit(&s).err());
            if let Some(e) = refused {
                warn!(%id, "not re-running a job the journal left open: {}", e.message);
                let e = ApiError::new(
                    e.kind,
                    format!("not run again after the restart: {}", e.message),
                );
                self.store.fail(&id, e, true);
                continue;
            }
            info!(%id, "re-running a job the journal left open");
            scheduler::spawn_job(Arc::clone(self), id);
        }
        ws::spawn_ticker(Arc::clone(self));
        if !self.cfg.retention.is_zero() {
            let state = Arc::clone(self);
            tokio::spawn(async move {
                let every = (state.cfg.retention / 10).min(Duration::from_secs(60));
                let mut tick = tokio::time::interval(every.max(Duration::from_secs(1)));
                loop {
                    tick.tick().await;
                    let gone = state.store.sweep(state.cfg.retention);
                    if gone > 0 {
                        info!(gone, "forgot finished jobs older than the retention");
                    }
                }
            });
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.cfg
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Take a job in and start it, unless `max_queued` jobs are open. The
    /// token the job runs under is a child of the server's.
    ///
    /// The submission runs in a task of its own, so a request that is
    /// abandoned while the journal is written (the client went away) still
    /// ends with the job taken and started, not with a journal record of a
    /// job nobody runs.
    pub async fn submit(
        self: &Arc<Self>,
        submission: model::Submission,
    ) -> std::result::Result<JobId, store::SubmitError> {
        let state = Arc::clone(self);
        let task = tokio::spawn(async move {
            let id = state
                .store
                .submit_within(submission, state.work.child_token(), state.cfg.max_queued)
                .await?;
            scheduler::spawn_job(Arc::clone(&state), id.clone());
            Ok(id)
        });
        task.await.unwrap_or_else(|e| {
            Err(store::SubmitError::Journal(Error::Io(
                std::io::Error::other(format!("submitting: {e}")),
            )))
        })
    }

    /// What the server's settings say about a submission, before anything
    /// is resolved: the options it would run with, `delete_source`, the
    /// number of transfers and every URL. Checked when a job is taken and
    /// again when the journal hands one over after a restart.
    pub fn admit(&self, submission: &model::Submission) -> std::result::Result<(), ApiError> {
        submission.options.apply(&self.rt.copy)?;
        if submission.options.delete_source == Some(true) && !self.cfg.allow_delete {
            return Err(ApiError::new(
                "invalid_option",
                "delete_source is not allowed on this server ([server] allow_delete)",
            ));
        }
        if submission.specs.len() > self.cfg.max_transfers {
            return Err(ApiError::new(
                "too_many_transfers",
                format!(
                    "{} transfers in one job; the limit is {} ([server] max_transfers)",
                    submission.specs.len(),
                    self.cfg.max_transfers
                ),
            ));
        }
        for url in submission.urls() {
            self.cfg.allow_url(url)?;
        }
        Ok(())
    }

    pub fn accepting(&self) -> bool {
        self.accepting.load(Ordering::Relaxed)
    }

    fn cancel_all(&self) {
        self.work.cancel();
    }

    /// Stop taking jobs, wait up to `grace` for the open ones, cancel
    /// the rest, and send the WebSocket clients away.
    pub async fn drain(&self, grace: Duration) {
        self.accepting.store(false, Ordering::Relaxed);
        let open = self.store.unfinished();
        if open > 0 {
            info!(jobs = open, "shutting down: waiting for open jobs");
            if tokio::time::timeout(grace, self.store.drained())
                .await
                .is_err()
            {
                warn!(
                    jobs = self.store.unfinished(),
                    "still open after {grace:?}, cancelling (a journal runs them again)"
                );
                self.cancel_all();
                let _ = tokio::time::timeout(Duration::from_secs(5), self.store.drained()).await;
            }
        }
        // The last jobs' `done` records, so a restart does not run them again.
        let _ = tokio::time::timeout(Duration::from_secs(5), self.store.flush()).await;
        self.closing.cancel();
    }
}

/// Run the server until `shutdown` fires, then drain and return. A second
/// signal on `abort` cancels every job at once instead of waiting.
pub async fn serve(
    cfg: ServerConfig,
    rt: Runtime,
    shutdown: CancellationToken,
    abort: CancellationToken,
) -> Result<()> {
    let state = AppState::new(cfg, rt)?;
    let listener = tokio::net::TcpListener::bind(state.cfg.bind)
        .await
        .map_err(|e| Error::Config(format!("cannot listen on {}: {e}", state.cfg.bind)))?;
    let addr = listener.local_addr()?;
    if let Some(p) = &state.cfg.port_file {
        std::fs::write(p, format!("{}\n", addr.port()))?;
    }
    info!(
        %addr,
        token = state.cfg.token.is_some(),
        urls = %state.cfg.urls,
        journal = state.cfg.journal.as_ref().map(|p| p.display().to_string()),
        "listening"
    );
    state.run();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            tokio::select! {
                biased;
                () = abort.cancelled() => {
                    warn!("aborting: cancelling every job");
                    state.cancel_all();
                    state.closing.cancel();
                }
                () = state.closing.cancelled() => {}
            }
        });
    }
    let app = router(Arc::clone(&state));
    let graceful = {
        let state = Arc::clone(&state);
        async move {
            shutdown.cancelled().await;
            state.drain(state.cfg.grace).await;
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(graceful)
        .await?;
    info!("stopped");
    Ok(())
}
