//! `mpt relay`: one upload, fanned out by the relay.
//!
//! A relay is `cp` with its stdin as the source. The first line on stdin
//! is a JSON [`Header`] — the file's name and size, the targets, the
//! options — and the file follows. While the copy runs the relay writes
//! JSON lines to stdout: `{"progress": …}` four times a second, then
//! `{"report": …}` (the shape of `--json`) or `{"error": …}`, and it exits
//! the way `cp` would. A relay listens on stdin because that is what an
//! SSH channel looks like from inside: [`sshd`] runs it on a channel of
//! its own server, and a plain sshd runs the binary.
//!
//! Version 1 of the protocol sends the file as exactly `size` raw bytes
//! after the header. Version 2 sends it in frames (see [`protocol`]) with
//! control frames in between, which is what lets the relay ask the client
//! for a password at every login instead of holding one: the header says
//! `"credentials": "on-demand"`, the relay writes `{"need": …}` lines and
//! the client answers each in a control frame. Both sides have to allow
//! that; a relay set to `header` refuses a client that asks for it, and
//! the other way round.
//!
//! Version 3 adds sessions that are not copies ([`Op`]): a listing, a
//! size, directories created. That is how a client expands a pattern or a
//! tree that only the relay can reach.
//!
//! A target of the header may name a relay of its own. The relay then
//! writes it through that one ([`endpoint`]), with the same protocol and
//! the same questions — which it passes on to the client — so a file goes
//! from one relay's reach to another's without coming through the client.
//!
//! Nothing is spooled: the targets read the payload as it arrives, so the
//! slowest of them sets the pace, and the source ending early (the client
//! going away) fails them all. The one exception is a chained target of a
//! source whose size is unknown: the protocol needs the size up front, so
//! [`endpoint`] spools that file, as far as `--max-size` allows. Everything
//! `cp` does — checksums, atomic finishing, the memory cache with retries,
//! timeouts — applies unchanged.

pub mod agent;
mod authorized_keys;
pub mod broker;
pub mod client;
pub mod endpoint;
pub mod plan;
pub mod protocol;
pub mod sshd;
pub mod via;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::broker::AgentSource;
use crate::options::{JobOptions, LocateFn};
use crate::stream::{Idle, ReaderEndpoint};
use crate::transfer::{CopyOptions, FanoutReport, Progress};
use crate::{Endpoint, Error, Location, Result};
use broker::{RemoteBroker, Who};
use protocol::{ChannelReader, Frame};

/// The newest protocol version, which a relay speaks along with the older
/// ones. Version 3 adds the operations besides the copy: [`Op::List`],
/// [`Op::Size`] and [`Op::Mkdir`].
pub const VERSION: u32 = 3;

/// The version a client sends for a copy. A copy needs nothing of version
/// 3, so relays of an older release keep taking it.
pub const COPY_VERSION: u32 = 2;

/// The longest header line a relay reads.
pub const MAX_HEADER: usize = 64 * 1024;

/// How long a relay waits for the header line. A client writes it right
/// after the command starts; one that does not would hold a `--parallel`
/// slot for as long as its connection lives.
pub const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The first line on stdin: what to call the file, how many bytes follow,
/// where they go and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    #[serde(default = "version")]
    pub v: u32,
    /// What the session does: a copy unless it says otherwise.
    #[serde(default, skip_serializing_if = "Op::is_copy")]
    pub op: Op,
    /// The source the relay reads itself, instead of a payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// The file's name, when a payload follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// How many bytes the payload has, when one follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The targets of a copy, or the directories of a `mkdir`.
    #[serde(default, alias = "dsts", skip_serializing_if = "Vec::is_empty")]
    pub dst: Vec<Dst>,
    /// Where the targets' passwords come from.
    #[serde(default, skip_serializing_if = "Credentials::is_header")]
    pub credentials: Credentials,
    /// The client forwards its ssh-agent for the SSH targets.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub agent: bool,
    /// The relay may forward that agent on to the relays of its chained
    /// targets. Without it, it only logs in to them with it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub agent_onward: bool,
    #[serde(default, skip_serializing_if = "is_default")]
    pub options: JobOptions,
}

impl Header {
    /// A header for a payload of `size` bytes called `name`.
    pub fn stream(name: impl Into<String>, size: u64, dst: Vec<String>) -> Header {
        Header {
            v: COPY_VERSION,
            op: Op::Copy,
            src: None,
            name: Some(name.into()),
            size: Some(size),
            dst: dst.into_iter().map(Dst::Url).collect(),
            credentials: Credentials::Header,
            agent: false,
            agent_onward: false,
            options: JobOptions::default(),
        }
    }

    /// A header that asks for the directory `src` to be listed.
    pub fn list(src: impl Into<String>) -> Header {
        Header::op(Op::List, Some(src.into()), Vec::new())
    }

    /// A header that asks for the size of `src`.
    pub fn size_of(src: impl Into<String>) -> Header {
        Header::op(Op::Size, Some(src.into()), Vec::new())
    }

    /// A header that asks for the directories `dst` to be created.
    pub fn mkdir(dst: Vec<String>) -> Header {
        Header::op(Op::Mkdir, None, dst.into_iter().map(Dst::Url).collect())
    }

    fn op(op: Op, src: Option<String>, dst: Vec<Dst>) -> Header {
        Header {
            v: VERSION,
            op,
            src,
            name: None,
            size: None,
            dst,
            credentials: Credentials::Header,
            agent: false,
            agent_onward: false,
            options: JobOptions::default(),
        }
    }

    /// The payload's name, for logs: the file's, or the source's last part.
    fn what(&self) -> String {
        match (&self.name, &self.src) {
            (Some(name), _) => name.clone(),
            (None, Some(src)) => src.clone(),
            (None, None) => String::new(),
        }
    }
}

/// What a session does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// Copy the payload, or the source the relay reads, to the targets.
    #[default]
    Copy,
    /// List the directory `src` names: an `entry` line for each of its
    /// entries, then a `listed` line (version 3).
    List,
    /// The size of `src`, in a `size` line: `null` for a directory or a
    /// size the protocol does not tell (version 3).
    Size,
    /// Create the directories `dst` names, with their parents, then a
    /// `made` line (version 3).
    Mkdir,
}

impl Op {
    fn is_copy(&self) -> bool {
        *self == Op::Copy
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Op::Copy => "copy",
            Op::List => "list",
            Op::Size => "size",
            Op::Mkdir => "mkdir",
        }
    }
}

/// One target of a header: a URL, or a URL behind a relay of its own.
/// Strict like the header: a field it does not know is an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Dst {
    Url(String),
    Via { url: String, via: String },
}

impl Dst {
    pub fn url(&self) -> &str {
        match self {
            Dst::Url(url) | Dst::Via { url, .. } => url,
        }
    }
}

/// Where a session's passwords come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Credentials {
    /// In the target URLs of the header, the relay holds them for the copy.
    #[default]
    Header,
    /// Asked of the client at every login, never held.
    OnDemand,
}

impl Credentials {
    fn is_header(&self) -> bool {
        *self == Credentials::Header
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Credentials::Header => "header",
            Credentials::OnDemand => "on-demand",
        }
    }
}

impl std::str::FromStr for Credentials {
    type Err = Error;

    fn from_str(s: &str) -> Result<Credentials> {
        match s.trim().to_ascii_lowercase().as_str() {
            "header" => Ok(Credentials::Header),
            "on-demand" | "on_demand" | "ondemand" => Ok(Credentials::OnDemand),
            other => Err(Error::Config(format!(
                "credentials: expected header or on-demand, got '{other}'"
            ))),
        }
    }
}

/// What a relay accepts: passwords in the header, on demand, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayCredentials {
    #[default]
    Header,
    OnDemand,
    Any,
}

impl RelayCredentials {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelayCredentials::Header => "header",
            RelayCredentials::OnDemand => "on-demand",
            RelayCredentials::Any => "any",
        }
    }

    /// Whether a session with `asked` may run here, with the message that
    /// names both settings when it may not.
    fn allows(&self, asked: Credentials) -> Result<()> {
        match (self, asked) {
            (RelayCredentials::Any, _)
            | (RelayCredentials::Header, Credentials::Header)
            | (RelayCredentials::OnDemand, Credentials::OnDemand) => Ok(()),
            (RelayCredentials::Header, Credentials::OnDemand) => Err(Error::invalid_option(
                "credentials",
                "the client asks for on-demand passwords, but this relay is set to \
                 credentials = \"header\"; start the relay with --credentials on-demand or any",
            )),
            (RelayCredentials::OnDemand, Credentials::Header) => Err(Error::invalid_option(
                "credentials",
                "this relay takes passwords on demand only, but the client sends them in the \
                 header; run cp with --via-credentials on-demand",
            )),
        }
    }
}

impl std::str::FromStr for RelayCredentials {
    type Err = Error;

    fn from_str(s: &str) -> Result<RelayCredentials> {
        match s.trim().to_ascii_lowercase().as_str() {
            "header" => Ok(RelayCredentials::Header),
            "on-demand" | "on_demand" | "ondemand" => Ok(RelayCredentials::OnDemand),
            "any" | "both" => Ok(RelayCredentials::Any),
            other => Err(Error::Config(format!(
                "credentials: expected header, on-demand or any, got '{other}'"
            ))),
        }
    }
}

fn version() -> u32 {
    VERSION
}

fn is_default(o: &JobOptions) -> bool {
    *o == JobOptions::default()
}

/// What a relay adds to every job it runs: the flags of the process and
/// its configuration, the way `cp` would have them.
pub struct Relay {
    /// The options a header's own lay over (see [`JobOptions::apply`]).
    /// `cancel` and `progress` are set per job.
    pub copy: CopyOptions,
    /// Bound for the memory cache when a header asks for `cache`.
    pub cache_limit: u64,
    /// URL to location, with what the process adds (`--insecure`, a
    /// default timeout).
    pub locate: Arc<LocateFn>,
    /// Refuse a header whose `size` is larger; 0 sets no limit.
    pub max_size: u64,
    /// Which way the passwords may come.
    pub credentials: RelayCredentials,
    /// A header may ask for the source to be deleted (`--allow-delete`).
    /// Only a source the relay read itself, and never a local file.
    pub allow_delete: bool,
    /// Stops the running copy: Ctrl-C on the relay.
    pub cancel: CancellationToken,
}

/// Everything `prepare` works out before a byte of payload is read.
struct Prepared {
    copy: CopyOptions,
    /// The source the relay reads itself, when the header names one.
    source: Option<Box<dyn Endpoint>>,
    targets: Vec<Box<dyn Endpoint>>,
}

/// Run one relay: read the header and the payload from `reader`, write
/// progress and the outcome to `writer`, and return the exit code `cp`
/// would give — 0 when every target has the file.
pub async fn run<R, W>(relay: &Relay, reader: R, writer: W) -> u8
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    run_with(relay, reader, writer, None).await
}

/// [`run`] with the agent the client forwarded, which the SSH targets
/// authenticate with when the header asks for it.
pub async fn run_with<R, W>(
    relay: &Relay,
    reader: R,
    mut writer: W,
    agent: Option<Arc<dyn AgentSource>>,
) -> u8
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    // Lines for the client from wherever they arise: progress and the
    // outcome here, credit from the intake, `need` from the broker. They
    // are written alongside the session, so a client that is slow to read
    // them holds up nothing but its own lines.
    let (lines, lines_rx) = mpsc::unbounded_channel::<Value>();
    let (last_tx, last_rx) = tokio::sync::oneshot::channel();
    let running = async move {
        let (code, last) = session(relay, reader, lines, agent).await;
        let _ = last_tx.send(last);
        code
    };
    let (code, ()) = tokio::join!(running, write_lines(&mut writer, lines_rx, last_rx));
    code
}

/// Write the lines as they come, the session's last one after every line
/// that came before it, and return once that is written.
async fn write_lines<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut lines: mpsc::UnboundedReceiver<Value>,
    last: tokio::sync::oneshot::Receiver<Value>,
) {
    tokio::pin!(last);
    let mut reading = true;
    loop {
        tokio::select! {
            biased;
            Some(value) = lines.recv() => {
                if reading && line(writer, &value).await.is_err() {
                    // Nobody is listening any more: the copy still
                    // finishes, its report goes nowhere.
                    debug!("relay: the client stopped reading");
                    reading = false;
                }
            }
            value = &mut last => {
                if let Ok(value) = value
                    && reading
                {
                    let _ = line(writer, &value).await;
                }
                return;
            }
        }
    }
}

/// One session: the header, the endpoints, the copy. Every line for the
/// client goes to `lines`; the outcome — a `report` or an `error` line —
/// comes back with the exit code.
async fn session<R>(
    relay: &Relay,
    reader: R,
    lines: mpsc::UnboundedSender<Value>,
    agent: Option<Arc<dyn AgentSource>>,
) -> (u8, Value)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(reader);
    let cancel = relay.cancel.child_token();
    let header = match read_header(relay, &mut reader).await {
        Ok(h) => h,
        Err(e) => return refuse(e),
    };
    let broker = match header.credentials {
        Credentials::OnDemand => Some(RemoteBroker::new(lines.clone(), cancel.clone())),
        Credentials::Header => None,
    };
    if header.op != Op::Copy {
        return operation(relay, header, reader, lines, broker, cancel, agent).await;
    }
    let name = header.name.clone().unwrap_or_default();
    let size = header.size.unwrap_or(0);
    // In version 2 the frames are taken apart from here on, before a
    // target is opened: opening one may already ask the client for a
    // password, and the answer comes in a control frame.
    let fault = Arc::new(std::sync::Mutex::new(None));
    let (payload, intake): (Option<Box<dyn AsyncRead + Send + Unpin>>, _) = match header.v {
        1 => (Some(Box::new(reader)), None),
        _ => {
            let (data_tx, data_rx) = mpsc::unbounded_channel();
            let (consumed_tx, consumed_rx) = mpsc::unbounded_channel();
            // With a source the relay reads itself, the client's input
            // carries control frames only, and its end means the client
            // is gone. A data frame then has nowhere to go and ends the
            // session.
            let payload = match header.src {
                Some(_) => None,
                None => Some(Box::new(ChannelReader::new(data_rx, consumed_tx))
                    as Box<dyn AsyncRead + Send + Unpin>),
            };
            let intake = tokio::spawn(intake(
                reader,
                data_tx,
                consumed_rx,
                lines.clone(),
                broker.clone(),
                Ending {
                    cancel: cancel.clone(),
                    reads_source: header.src.is_some(),
                    fault: Arc::clone(&fault),
                },
            ));
            (payload, Some(intake))
        }
    };
    // The end of the session: the intake stopped, and what it found wrong
    // with the client's input, which is then the session's error.
    let stop = |intake: Option<tokio::task::JoinHandle<()>>| {
        if let Some(intake) = intake {
            intake.abort();
        }
        if let Some(broker) = &broker {
            broker.close();
        }
        fault.lock().unwrap_or_else(|e| e.into_inner()).take()
    };
    let Prepared {
        copy,
        source,
        targets,
    } = match prepare(relay, &header, &broker, &cancel, agent).await {
        Ok(p) => p,
        Err(e) => return refuse(stop(intake).unwrap_or(e)),
    };
    info!(
        what = %header.what(),
        size = header.size,
        targets = targets.len(),
        v = header.v,
        credentials = header.credentials.as_str(),
        "relay"
    );
    let src: Result<Box<dyn Endpoint>> = match (source, payload) {
        (Some(source), _) => Ok(source),
        (None, Some(payload)) => {
            ReaderEndpoint::new(&name, size, Idle::maybe(payload, copy.tee.send_timeout))
                .map(|r| Box::new(r) as Box<dyn Endpoint>)
        }
        (None, None) => Err(Error::invalid_option("src", "no source and no payload")),
    };
    let src = match src {
        Ok(s) => s,
        Err(e) => return refuse(stop(intake).unwrap_or(e)),
    };
    let progress = copy.progress.clone().unwrap_or_else(Progress::new);
    let refs: Vec<&dyn Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let copying = crate::transfer::copy_many(src.as_ref(), &refs, &copy);
    tokio::pin!(copying);
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = None;
    let outcome = loop {
        tokio::select! {
            r = &mut copying => break r,
            _ = tick.tick() => {
                let read = progress.read();
                if last != Some(read) {
                    last = Some(read);
                    let _ = lines.send(
                        json!({ "progress": { "read": read, "total": progress.total() } }),
                    );
                }
            }
        }
    };
    // A fault that cancelled the copy is its reason; one after every
    // target had the file changes nothing of that.
    if let Some(fault) = stop(intake)
        && !outcome.as_ref().is_ok_and(|r| r.all_ok())
    {
        return refuse(fault);
    }
    match outcome {
        Ok(report) => (
            exit_code(&report),
            json!({ "report": crate::report::fanout_json(&report) }),
        ),
        Err(e) => refuse(e),
    }
}

/// A session that is not a copy: a listing (an `entry` line per entry,
/// then `listed`), a size (`size`), or directories created (`made`). The
/// client's input carries control frames only, as with a source the relay
/// reads itself.
async fn operation<R>(
    relay: &Relay,
    header: Header,
    reader: BufReader<R>,
    lines: mpsc::UnboundedSender<Value>,
    broker: Option<Arc<RemoteBroker>>,
    cancel: CancellationToken,
    agent: Option<Arc<dyn AgentSource>>,
) -> (u8, Value)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let fault = Arc::new(std::sync::Mutex::new(None));
    // Nothing is credited: no payload is taken.
    let (data_tx, _data_rx) = mpsc::unbounded_channel();
    let (_consumed_tx, consumed_rx) = mpsc::unbounded_channel();
    let intake = tokio::spawn(intake(
        reader,
        data_tx,
        consumed_rx,
        lines.clone(),
        broker.clone(),
        Ending {
            cancel: cancel.clone(),
            reads_source: true,
            fault: Arc::clone(&fault),
        },
    ));
    let done = async {
        let agent = agent.filter(|_| header.agent);
        let open = |url: &str, who: Who| -> Result<Box<dyn Endpoint>> {
            let loc = (relay.locate)(url, &header.options)?;
            let loc = with_agent(with_broker(loc, &broker, who)?, &agent);
            info!(what = %loc, op = header.op.as_str(), credentials = header.credentials.as_str(), "relay operation");
            crate::protocols::open(loc)
        };
        let src = header.src.as_deref().unwrap_or_default();
        match header.op {
            Op::List => {
                let entries = open(src, Who::Src)?.receiver()?.list().await?;
                for e in &entries {
                    let _ = lines.send(json!({ "entry": crate::report::entry_json(e) }));
                }
                Ok(json!({ "listed": { "entries": entries.len() } }))
            }
            Op::Size => {
                let size = open(src, Who::Src)?.receiver()?.size().await?;
                Ok(json!({ "size": size }))
            }
            Op::Mkdir => {
                for (i, dst) in header.dst.iter().enumerate() {
                    let target = open(dst.url(), Who::Dst(i))?;
                    let sender = target.sender()?;
                    if !sender.supports_mkdir() {
                        return Err(sender.unsupported("create directories"));
                    }
                    sender.mkdir_all().await?;
                }
                Ok(json!({ "made": { "dirs": header.dst.len() } }))
            }
            Op::Copy => Err(Error::invalid_option("op", "a copy is not an operation")),
        }
    };
    let outcome = tokio::select! {
        r = done => r,
        () = cancel.cancelled() => Err(Error::Cancelled),
    };
    intake.abort();
    if let Some(broker) = &broker {
        broker.close();
    }
    let fault = fault.lock().unwrap_or_else(|e| e.into_inner()).take();
    match (outcome, fault) {
        (_, Some(fault)) => refuse(fault),
        (Ok(last), None) => (0, last),
        (Err(e), None) => refuse(e),
    }
}

/// The session's `error` line for `e`, with its exit code.
fn refuse(e: Error) -> (u8, Value) {
    debug!("relay: {e}");
    (
        e.exit_code(),
        json!({ "error": crate::report::error_json(&e) }),
    )
}

/// How the intake ends a session.
struct Ending {
    cancel: CancellationToken,
    /// The relay reads the source itself.
    reads_source: bool,
    /// Where what the client sent wrong is left.
    fault: Arc<std::sync::Mutex<Option<Error>>>,
}

/// Version 2: take the frames apart. Data goes to the copy through
/// `data`, an answer to the broker, and what the copy has consumed (told
/// on `consumed`) comes back to the client as credit. Ends when the
/// client's input does — which cancels the session when the relay reads
/// the source itself (`reads_source`), since only the input tells that the
/// client is still there — or when the client sends what it may not: a
/// malformed frame, data beyond its credit, data where the relay reads the
/// source. That ends the session too, with the error left for it.
async fn intake<R: AsyncRead + Unpin>(
    mut reader: R,
    data: mpsc::UnboundedSender<Vec<u8>>,
    mut consumed: mpsc::UnboundedReceiver<u64>,
    lines: mpsc::UnboundedSender<Value>,
    broker: Option<Arc<RemoteBroker>>,
    end: Ending,
) {
    let Ending {
        cancel,
        reads_source,
        fault,
    } = end;
    let granted = Arc::new(AtomicU64::new(protocol::INITIAL_CREDIT));
    // The copy drops its reader once it has the payload, which ends the
    // crediting; the control frames keep coming until the client is done.
    let crediting = {
        let granted = Arc::clone(&granted);
        let lines = lines.clone();
        tokio::spawn(async move {
            let mut pending = 0u64;
            while let Some(n) = consumed.recv().await {
                pending += n;
                if pending >= protocol::CREDIT_STEP {
                    granted.fetch_add(pending, Ordering::SeqCst);
                    let _ = lines.send(json!({ "credit": pending }));
                    pending = 0;
                }
            }
        })
    };
    let reading = async {
        let mut received = 0u64;
        loop {
            match protocol::read_frame(&mut reader).await {
                // An empty data frame carries nothing; handed on, it would
                // read as the end of the payload.
                Ok(Some(Frame::Data(bytes))) if bytes.is_empty() => {}
                Ok(Some(Frame::Data(_))) if reads_source => {
                    return Some(Error::invalid_option(
                        "frame",
                        "a payload frame, but the relay reads the source itself",
                    ));
                }
                Ok(Some(Frame::Data(bytes))) => {
                    received += bytes.len() as u64;
                    if received > granted.load(Ordering::SeqCst) {
                        return Some(Error::invalid_option(
                            "credit",
                            "the client sent more payload than it had credit for",
                        ));
                    }
                    // The copy has the whole payload and no use for more.
                    let _ = data.send(bytes);
                }
                Ok(Some(Frame::Control(value))) => match &broker {
                    Some(broker) => broker.answer(&value),
                    // Not shown: it may hold a password all the same.
                    None => debug!("relay: control frame in a header session, ignored"),
                },
                Ok(None) => {
                    debug!("relay: the client's input ended");
                    if reads_source {
                        cancel.cancel();
                    }
                    return None;
                }
                Err(e) => return Some(Error::invalid_option("frame", e)),
            }
        }
    };
    let found = reading.await;
    crediting.abort();
    if let Some(broker) = &broker {
        broker.close();
    }
    if let Some(e) = found {
        warn!("relay: {e}");
        // Left before the session is ended, so it is there to be found.
        *fault.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
        cancel.cancel();
    }
}

/// Read and check the header. Nothing of the payload is read.
async fn read_header<R: AsyncRead + Unpin>(
    relay: &Relay,
    reader: &mut BufReader<R>,
) -> Result<Header> {
    let mut raw = Vec::new();
    let mut limited = reader.take(MAX_HEADER as u64 + 1);
    let reading = limited.read_until(b'\n', &mut raw);
    match tokio::time::timeout(HEADER_TIMEOUT, reading).await {
        Ok(read) => read?,
        Err(_) => {
            return Err(Error::invalid_option(
                "header",
                format!("no header line within {}s", HEADER_TIMEOUT.as_secs()),
            ));
        }
    };
    if raw.last() != Some(&b'\n') {
        return Err(Error::invalid_option(
            "header",
            if raw.len() > MAX_HEADER {
                format!("longer than {MAX_HEADER} bytes")
            } else {
                "no line before the input ended".to_string()
            },
        ));
    }
    let header: Header =
        serde_json::from_slice(&raw).map_err(|e| Error::invalid_option("header", e))?;
    if !(1..=VERSION).contains(&header.v) {
        return Err(Error::invalid_option(
            "v",
            format!(
                "this relay speaks versions 1 to {VERSION}, not {}",
                header.v
            ),
        ));
    }
    if header.op != Op::Copy && header.v < 3 {
        return Err(Error::invalid_option(
            "op",
            format!(
                "{} is not in version {} of the protocol",
                header.op.as_str(),
                header.v
            ),
        ));
    }
    if header.v == 1 {
        for (what, wrong) in [
            ("src", header.src.is_some()),
            ("credentials", header.credentials != Credentials::Header),
            ("agent", header.agent),
            ("agent_onward", header.agent_onward),
            (
                "via",
                header.dst.iter().any(|d| matches!(d, Dst::Via { .. })),
            ),
        ] {
            if wrong {
                return Err(Error::invalid_option(
                    what,
                    "not in version 1 of the protocol",
                ));
            }
        }
    }
    if header.op != Op::Copy {
        // What the operation works on, and nothing that belongs to a copy:
        // a source for a listing or a size, plain targets for mkdir.
        let op = header.op.as_str();
        let on_targets = header.op == Op::Mkdir;
        if on_targets && header.dst.is_empty() {
            return Err(Error::invalid_option("dst", "mkdir needs the directories"));
        }
        if !on_targets && header.src.is_none() {
            return Err(Error::invalid_option(
                "src",
                format!("{op} needs the location"),
            ));
        }
        for (what, wrong) in [
            ("name", header.name.is_some()),
            ("size", header.size.is_some()),
            ("src", on_targets && header.src.is_some()),
            ("dst", !on_targets && !header.dst.is_empty()),
            (
                "via",
                header.dst.iter().any(|d| matches!(d, Dst::Via { .. })),
            ),
            ("agent_onward", header.agent_onward),
        ] {
            if wrong {
                return Err(Error::invalid_option(what, format!("not in {op}")));
            }
        }
        let only_timeout = JobOptions {
            timeout: header.options.timeout,
            ..JobOptions::default()
        };
        if header.options != only_timeout {
            return Err(Error::invalid_option(
                "options",
                format!("{op} takes a timeout and nothing else"),
            ));
        }
        relay.credentials.allows(header.credentials)?;
        return Ok(header);
    }
    match (&header.src, &header.name, &header.size) {
        (None, Some(_), Some(_)) | (Some(_), None, None) => {}
        (Some(_), _, _) => {
            return Err(Error::invalid_option(
                "src",
                "either a source or a name and size, not both",
            ));
        }
        (None, _, _) => {
            return Err(Error::invalid_option(
                "header",
                "a name and a size, or a source",
            ));
        }
    }
    if header.dst.is_empty() {
        return Err(Error::invalid_option("dst", "no target given"));
    }
    relay.credentials.allows(header.credentials)?;
    if let Some(size) = header.size
        && relay.max_size > 0
        && size > relay.max_size
    {
        return Err(Error::invalid_option(
            "size",
            format!(
                "{size} bytes is more than this relay takes ({})",
                relay.max_size
            ),
        ));
    }
    Ok(header)
}

/// Lay the header's options over the relay's and open the endpoints.
/// A login here may already ask the client for its password.
async fn prepare(
    relay: &Relay,
    header: &Header,
    broker: &Option<Arc<RemoteBroker>>,
    cancel: &CancellationToken,
    agent: Option<Arc<dyn AgentSource>>,
) -> Result<Prepared> {
    let o = &header.options;
    for (name, set) in [
        ("check", o.check == Some(true)),
        (
            "delete_source",
            o.delete_source == Some(true) && header.src.is_none(),
        ),
        ("resume", o.resume == Some(true)),
        ("recursive", o.recursive == Some(true)),
        ("allow_empty", o.allow_empty == Some(true)),
        ("parallel", o.parallel.is_some()),
        ("fail_fast", o.fail_fast.is_some()),
    ] {
        if set {
            return Err(Error::invalid_option(name, "not over a relay"));
        }
    }
    // Only a source the relay opened itself can be deleted by it, and only
    // when the relay was started to allow that.
    let delete_source = header.src.is_some() && o.delete_source == Some(true);
    if delete_source && !relay.allow_delete {
        return Err(Error::invalid_option(
            "delete_source",
            "this relay deletes no source; start it with --allow-delete \
             (or [relay] allow_delete) if that is meant",
        ));
    }
    let mut copy = header.options.apply(&relay.copy, relay.cache_limit)?;
    copy.check = false;
    copy.verify = None;
    copy.delete_source = delete_source;
    copy.cancel = Some(cancel.clone());
    copy.progress = Some(Progress::new());
    let agent = match (header.agent, agent) {
        (true, Some(agent)) => Some(agent),
        (true, None) => {
            debug!("relay: the header asks for the client's agent, but none was forwarded");
            None
        }
        (false, _) => None,
    };
    let mut targets = Vec::with_capacity(header.dst.len());
    for (i, dst) in header.dst.iter().enumerate() {
        let loc = (relay.locate)(dst.url(), &header.options)?;
        match dst {
            Dst::Url(_) => {
                let loc = with_broker(loc, broker, Who::Dst(i))?;
                targets.push(crate::protocols::open(with_agent(loc, &agent))?);
            }
            // The far relay opens the target; here it is only named, and
            // its password — if one is asked for — is the client's to give.
            Dst::Via { url, via } => {
                no_password_on_demand(&loc, broker)?;
                let hop = (relay.locate)(via, &header.options)?;
                if hop.scheme() != crate::Scheme::Ssh {
                    return Err(Error::invalid_option(
                        "via",
                        format!("{hop}: a relay needs an ssh:// URL"),
                    ));
                }
                let hop = with_agent(with_broker(hop, broker, Who::Via(i))?, &agent);
                let answer: Arc<dyn broker::PasswordAnswerer> = match broker {
                    Some(broker) => Arc::new(endpoint::ChainAnswerer {
                        broker: Arc::clone(broker),
                        index: i,
                        target: loc.clone(),
                    }),
                    None => Arc::new(broker::NoAnswer),
                };
                // The far relay does the same copy, but it reads no
                // source: it cannot delete one either.
                let mut options = header.options.clone();
                options.delete_source = None;
                targets.push(Box::new(endpoint::RelayEndpoint {
                    target: loc,
                    relay: hop,
                    max_size: relay.max_size,
                    header_url: url.clone(),
                    credentials: header.credentials,
                    options,
                    // The relay logs in to the far relay with the agent
                    // (`hop`); the far relay gets it only when asked for.
                    agent: agent.clone().filter(|_| header.agent_onward),
                    answerer: answer,
                    cancel: cancel.clone(),
                }));
            }
        }
    }
    let source = match &header.src {
        None => None,
        Some(url) => {
            let loc = (relay.locate)(url, &header.options)?;
            if delete_source && loc.scheme() == crate::Scheme::File {
                return Err(Error::invalid_option(
                    "delete_source",
                    format!("{loc}: a file on the relay host is never deleted by a relay"),
                ));
            }
            let loc = with_broker(loc, broker, Who::Src)?;
            let source = crate::protocols::open(with_agent(loc, &agent))?;
            if relay.max_size == 0 {
                Some(source)
            } else {
                // Refused before the copy when the size is known; and
                // counted as it is read, for a size that is not known or
                // not true.
                if let Some(size) = source.receiver()?.size().await?
                    && size > relay.max_size
                {
                    return Err(Error::invalid_option(
                        "src",
                        format!(
                            "{size} bytes is more than this relay takes ({})",
                            relay.max_size
                        ),
                    ));
                }
                Some(Box::new(LimitedSource {
                    inner: source,
                    limit: relay.max_size,
                }) as Box<dyn Endpoint>)
            }
        }
    };
    Ok(Prepared {
        copy,
        source,
        targets,
    })
}

/// A source the relay reads, cut off with an error past `--max-size`.
struct LimitedSource {
    inner: Box<dyn Endpoint>,
    limit: u64,
}

impl Endpoint for LimitedSource {
    fn location(&self) -> &Location {
        self.inner.location()
    }
    fn as_receiver(&self) -> Option<&dyn crate::Receiver> {
        Some(self)
    }
    // Deleting the source goes to the source itself.
    fn as_sender(&self) -> Option<&dyn crate::Sender> {
        self.inner.as_sender()
    }
}

#[async_trait::async_trait]
impl crate::Receiver for LimitedSource {
    async fn receive(&self) -> Result<crate::ByteStream> {
        let body = self.inner.receiver()?.receive().await?;
        Ok(crate::stream::boxed(crate::stream::Limited::new(
            body,
            self.limit,
            format!(
                "the source is larger than this relay takes ({} bytes)",
                self.limit
            ),
        )))
    }

    async fn list(&self) -> Result<Vec<crate::Entry>> {
        self.inner.receiver()?.list().await
    }

    async fn size(&self) -> Result<Option<u64>> {
        self.inner.receiver()?.size().await
    }
}

/// An SSH target authenticates with the agent the client forwarded.
fn with_agent(mut loc: Location, agent: &Option<Arc<dyn AgentSource>>) -> Location {
    if let Some(agent) = agent
        && loc.scheme().is_ssh()
    {
        let mut brokers = loc.brokers().clone();
        brokers.agent = Some(Arc::clone(agent));
        loc.set_brokers(brokers);
    }
    loc
}

/// An on-demand session takes no password with an endpoint: that is the
/// whole point of it. Not in a URL, and not from a profile of the relay's
/// own, which would win over the question and leave the client unasked.
fn no_password_on_demand(loc: &Location, broker: &Option<Arc<RemoteBroker>>) -> Result<()> {
    if broker.is_some() && loc.has_password() {
        return Err(Error::invalid_option(
            "credentials",
            format!("{loc}: carries a password, but the passwords are to be asked for on demand"),
        ));
    }
    Ok(())
}

/// An on-demand session's target asks the client for its password, and
/// must not have brought one along.
fn with_broker(
    mut loc: Location,
    broker: &Option<Arc<RemoteBroker>>,
    who: Who,
) -> Result<Location> {
    no_password_on_demand(&loc, broker)?;
    let Some(broker) = broker else {
        return Ok(loc);
    };
    if loc.scheme() != crate::Scheme::File {
        let mut brokers = loc.brokers().clone();
        brokers.password = Some(match who {
            Who::Src => broker.for_src(),
            Who::Dst(i) => broker.for_dst(i),
            Who::Via(i) => broker.for_via(i),
        });
        loc.set_brokers(brokers);
    }
    Ok(loc)
}

/// The exit code of a fan-out, as `cp` decides it: 0 when every target
/// has the file, 130 when one was cancelled, else what the failed
/// targets agree on and 1 when they do not.
pub fn exit_code(report: &FanoutReport) -> u8 {
    let codes: Vec<u8> = report
        .failures()
        .map(|t| t.result.as_ref().err().map_or(1, Error::exit_code))
        .collect();
    match codes.as_slice() {
        [] => 0,
        codes if codes.contains(&130) => 130,
        [first, rest @ ..] if rest.iter().all(|c| c == first) => *first,
        _ => 1,
    }
}

async fn line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    let mut text = serde_json::to_string(value).unwrap_or_default();
    text.push('\n');
    writer.write_all(text.as_bytes()).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashAlgo;
    use tokio::io::{AsyncReadExt, duplex};

    fn relay(max_size: u64) -> Relay {
        Relay {
            copy: CopyOptions::default(),
            cache_limit: 1 << 20,
            locate: Arc::new(|url, _| crate::Location::parse(url)),
            max_size,
            credentials: RelayCredentials::Header,
            allow_delete: false,
            cancel: CancellationToken::new(),
        }
    }

    /// Feed a header and a payload through a pipe, collect the lines and
    /// the exit code.
    async fn relay_run(
        relay: &Relay,
        header: &str,
        payload: &[u8],
    ) -> (u8, Vec<serde_json::Value>) {
        let (mut client_in, server_in) = duplex(64 << 10);
        let (server_out, mut client_out) = duplex(64 << 10);
        let mut input = header.as_bytes().to_vec();
        input.push(b'\n');
        input.extend_from_slice(payload);
        let feed = tokio::spawn(async move {
            let _ = client_in.write_all(&input).await;
            // Dropping the writer ends the input.
        });
        let read = tokio::spawn(async move {
            let mut text = String::new();
            client_out.read_to_string(&mut text).await.unwrap();
            text
        });
        let code = run(relay, server_in, server_out).await;
        feed.await.unwrap();
        let text = read.await.unwrap();
        let lines = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (code, lines)
    }

    #[tokio::test]
    async fn copies_the_payload_to_every_target_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        let header = json!({
            "v": 1, "name": "data.bin", "size": payload.len(),
            "dst": [format!("{}/", a.display()), format!("{}/", b.display())],
            "options": { "hash": "blake3" }
        });
        let (code, lines) = relay_run(&relay(0), &header.to_string(), &payload).await;
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(std::fs::read(a.join("data.bin")).unwrap(), payload);
        assert_eq!(std::fs::read(b.join("data.bin")).unwrap(), payload);
        assert!(a.join("data.bin.b3").exists());
        let report = &lines.last().unwrap()["report"];
        assert_eq!(report["ok"], true);
        assert_eq!(report["bytes_read"], payload.len());
        assert_eq!(report["source"], "data.bin");
        assert_eq!(report["targets"].as_array().unwrap().len(), 2);
        let expected = HashAlgo::Blake3;
        assert!(report["digests"][expected.name()].is_string());
        assert!(
            lines.iter().any(|l| l.get("progress").is_some()),
            "progress lines: {lines:?}"
        );
    }

    /// Version 2 over a pipe: the payload in frames, more than the initial
    /// credit allows, so the relay has to grant more for the copy to
    /// finish; a control frame nobody asked for is let through.
    #[tokio::test]
    async fn a_framed_payload_is_taken_apart_and_credited() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let payload: Vec<u8> = (0..(protocol::INITIAL_CREDIT as usize * 2 + 12_345))
            .map(|i| (i % 239) as u8)
            .collect();
        let header = json!({
            "name": "big.bin", "size": payload.len(),
            "dst": [format!("{}/", dir.path().display())],
            "credentials": "on-demand"
        });
        let (mut client_in, server_in) = duplex(64 << 10);
        let (server_out, client_out) = duplex(64 << 10);
        let credit = Arc::new(protocol::Credit::new(protocol::INITIAL_CREDIT));
        let credits_seen = Arc::new(AtomicU64::new(0));
        let feed = {
            let credit = Arc::clone(&credit);
            let payload = payload.clone();
            tokio::spawn(async move {
                let mut line = header.to_string();
                line.push('\n');
                client_in.write_all(line.as_bytes()).await.unwrap();
                client_in
                    .write_all(&protocol::control(&json!({ "password": { "id": 99 } })))
                    .await
                    .unwrap();
                for chunk in payload.chunks(protocol::CHUNK) {
                    credit.take(chunk.len() as u64).await;
                    client_in
                        .write_all(&protocol::frame(protocol::DATA, chunk))
                        .await
                        .unwrap();
                }
                // Stay open: a version 2 client closes after the outcome.
                std::future::pending::<()>().await;
            })
        };
        let read = {
            let credit = Arc::clone(&credit);
            let seen = Arc::clone(&credits_seen);
            tokio::spawn(async move {
                let mut lines = BufReader::new(client_out).lines();
                let mut out = Vec::new();
                while let Ok(Some(text)) = lines.next_line().await {
                    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if let Some(n) = value.get("credit").and_then(|v| v.as_u64()) {
                        seen.fetch_add(n, Ordering::Relaxed);
                        credit.grant(n);
                        continue;
                    }
                    out.push(value);
                }
                out
            })
        };
        let mut relay = relay(0);
        relay.credentials = RelayCredentials::Any;
        let code = run(&relay, server_in, server_out).await;
        feed.abort();
        let lines = read.await.unwrap();
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(std::fs::read(dir.path().join("big.bin")).unwrap(), payload);
        assert!(
            credits_seen.load(Ordering::Relaxed) >= protocol::INITIAL_CREDIT,
            "credit granted: {}",
            credits_seen.load(Ordering::Relaxed)
        );
        assert_eq!(lines.last().unwrap()["report"]["ok"], true);
    }

    /// A source named in the header is read by the relay; nothing of the
    /// file comes over the pipe. The client's input stays open until the
    /// relay is done.
    #[tokio::test]
    async fn a_source_the_relay_reads_itself() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in").join("x.bin");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 229) as u8).collect();
        std::fs::write(&src, &payload).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let session = |relay: Relay, options: serde_json::Value| {
            let header = json!({
                "src": src.display().to_string(),
                "dst": [format!("{}/", out.display())],
                "options": options
            });
            async move {
                let (mut client_in, server_in) = duplex(64 << 10);
                let (server_out, mut client_out) = duplex(64 << 10);
                let feed = tokio::spawn(async move {
                    let mut line = header.to_string();
                    line.push('\n');
                    client_in.write_all(line.as_bytes()).await.unwrap();
                    std::future::pending::<()>().await;
                });
                let read = tokio::spawn(async move {
                    let mut text = String::new();
                    client_out.read_to_string(&mut text).await.unwrap();
                    text
                });
                let code = run(&relay, server_in, server_out).await;
                feed.abort();
                let text = read.await.unwrap();
                let lines: Vec<serde_json::Value> = text
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                (code, lines)
            }
        };
        let (code, lines) = session(relay(0), json!({ "hash": "sha256" })).await;
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(std::fs::read(out.join("x.bin")).unwrap(), payload);
        assert!(out.join("x.bin.sha256").exists());
        let report = &lines.last().unwrap()["report"];
        assert_eq!(report["bytes_read"], payload.len());
        assert!(src.exists());

        // Deleting it takes --allow-delete, and even then a file on the
        // relay host stays.
        let (code, lines) = session(relay(0), json!({ "delete_source": true })).await;
        assert_eq!(code, 2, "{lines:?}");
        let message = lines[0]["error"]["message"].as_str().unwrap();
        assert!(message.contains("--allow-delete"), "{message}");
        let mut allowing = relay(0);
        allowing.allow_delete = true;
        let (code, lines) = session(allowing, json!({ "delete_source": true })).await;
        assert_eq!(code, 2, "{lines:?}");
        let message = lines[0]["error"]["message"].as_str().unwrap();
        assert!(message.contains("never deleted"), "{message}");
        assert!(src.exists());

        // Too large for this relay: refused before anything is read.
        let header =
            json!({ "src": src.display().to_string(), "dst": [format!("{}/", out.display())] });
        let (mut client_in, server_in) = duplex(64 << 10);
        let (server_out, mut client_out) = duplex(64 << 10);
        let feed = tokio::spawn(async move {
            let mut line = header.to_string();
            line.push('\n');
            client_in.write_all(line.as_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        });
        let read = tokio::spawn(async move {
            let mut text = String::new();
            client_out.read_to_string(&mut text).await.unwrap();
            text
        });
        let code = run(&relay(4_096), server_in, server_out).await;
        feed.abort();
        let text = read.await.unwrap();
        assert_eq!(code, 2, "{text}");
        assert!(text.contains("more than this relay takes"), "{text}");
    }

    /// Send `header` and keep the input open, as a client that waits for
    /// the outcome does; the lines and the exit code.
    async fn held_open(relay: &Relay, header: serde_json::Value) -> (u8, Vec<serde_json::Value>) {
        let (mut client_in, server_in) = duplex(64 << 10);
        let (server_out, mut client_out) = duplex(64 << 10);
        let feed = tokio::spawn(async move {
            let mut line = header.to_string();
            line.push('\n');
            client_in.write_all(line.as_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        });
        let read = tokio::spawn(async move {
            let mut text = String::new();
            client_out.read_to_string(&mut text).await.unwrap();
            text
        });
        let code = run(relay, server_in, server_out).await;
        feed.abort();
        let text = read.await.unwrap();
        let lines = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (code, lines)
    }

    #[tokio::test]
    async fn a_directory_is_listed_entry_by_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.csv"), b"12345").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let src = format!("{}/", dir.path().display());
        let (code, lines) = held_open(
            &relay(0),
            json!({ "v": 3, "op": "list", "src": src, "options": { "timeout": 5 } }),
        )
        .await;
        assert_eq!(code, 0, "{lines:?}");
        let mut entries: Vec<crate::Entry> = lines
            .iter()
            .filter_map(|l| l.get("entry"))
            .map(|e| crate::report::entry_from_json(e).unwrap())
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2, "{lines:?}");
        assert_eq!(
            (entries[0].name.as_str(), entries[0].size, entries[0].is_dir),
            ("a.csv", Some(5), false)
        );
        assert!(entries[0].modified.is_some());
        assert!(entries[1].is_dir);
        assert_eq!(lines.last().unwrap()["listed"]["entries"], 2);

        // A directory that is not there fails as a missing file does.
        let (code, lines) = held_open(
            &relay(0),
            json!({ "op": "list", "src": format!("{}/nope/", dir.path().display()) }),
        )
        .await;
        assert_eq!(code, 1, "{lines:?}");
        let err = crate::report::error_from_json(&lines.last().unwrap()["error"]);
        assert!(err.is_not_found(), "{err}");
    }

    #[tokio::test]
    async fn a_size_and_directories_are_the_relays_to_find_and_make() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.csv"), b"12345").unwrap();
        let (code, lines) = held_open(
            &relay(0),
            json!({ "op": "size", "src": dir.path().join("a.csv").display().to_string() }),
        )
        .await;
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(lines.last().unwrap()["size"], 5);
        let (code, lines) = held_open(
            &relay(0),
            json!({ "op": "size", "src": dir.path().display().to_string() }),
        )
        .await;
        assert_eq!(code, 0, "{lines:?}");
        assert!(lines.last().unwrap()["size"].is_null(), "{lines:?}");

        let made = [dir.path().join("x/y/"), dir.path().join("z/")];
        let (code, lines) = held_open(
            &relay(0),
            json!({ "op": "mkdir", "dst": made.iter().map(|d| format!("{}/", d.display())).collect::<Vec<_>>() }),
        )
        .await;
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(lines.last().unwrap()["made"]["dirs"], 2);
        assert!(made.iter().all(|d| d.is_dir()));

        // A target without directories says so, as it would from here.
        let (code, lines) = held_open(
            &relay(0),
            json!({ "op": "mkdir", "dst": ["http://127.0.0.1:9/in/"] }),
        )
        .await;
        assert_eq!(code, 2, "{lines:?}");
        assert_eq!(
            lines.last().unwrap()["error"]["kind"],
            "unsupported_operation"
        );
    }

    #[tokio::test]
    async fn a_listing_header_is_checked_like_any_other() {
        for (header, what) in [
            (
                json!({ "v": 2, "op": "list", "src": "/tmp/" }),
                "not in version 2",
            ),
            (json!({ "v": 3, "op": "list" }), "list needs the location"),
            (
                json!({ "op": "list", "src": "/tmp/", "dst": ["/tmp/x/"] }),
                "'dst': not in list",
            ),
            (
                json!({ "op": "size", "src": "/tmp/", "name": "x", "size": 1 }),
                "'name': not in size",
            ),
            (json!({ "op": "mkdir" }), "mkdir needs the directories"),
            (
                json!({ "op": "mkdir", "src": "/tmp/", "dst": ["/tmp/x/"] }),
                "'src': not in mkdir",
            ),
            (
                json!({ "op": "mkdir", "dst": [{ "url": "/tmp/x/", "via": "ssh://r/" }] }),
                "'via': not in mkdir",
            ),
            (
                json!({ "op": "list", "src": "/tmp/", "options": { "delete_source": true } }),
                "a timeout and nothing else",
            ),
            (json!({ "op": "move", "src": "/tmp/" }), "unknown variant"),
        ] {
            let (code, lines) = held_open(&relay(0), header).await;
            assert_eq!(code, 2, "{lines:?}");
            let message = lines[0]["error"]["message"].as_str().unwrap();
            assert!(message.contains(what), "{what}: {message}");
        }
    }

    /// An HTTP server on a free port that answers every request with
    /// `body` — its length announced when `announce` — and hands back the
    /// requests it saw.
    async fn http_server(
        body: &'static [u8],
        announce: bool,
    ) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await
            {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let length = match announce {
                    true => format!("Content-Length: {}\r\n", body.len()),
                    false => String::new(),
                };
                let mut answer =
                    format!("HTTP/1.1 200 OK\r\n{length}Connection: close\r\n\r\n").into_bytes();
                if request.starts_with("GET") {
                    answer.extend_from_slice(body);
                }
                let _ = socket.write_all(&answer).await;
                seen.push(request);
            }
            seen
        });
        (port, task)
    }

    /// With `--max-size`, the relay asks a source it reads for its size
    /// before the copy starts. In an on-demand session that login already
    /// asks the client for the password, and the answer has to get through.
    #[tokio::test]
    async fn a_password_asked_for_before_the_copy_is_answered() {
        let dir = tempfile::tempdir().unwrap();
        let (port, server) = http_server(b"0123456789", true).await;
        let header = json!({
            "src": format!("http://u@127.0.0.1:{port}/f.bin?timeout=5"),
            "dst": [format!("{}/", dir.path().display())],
            "credentials": "on-demand"
        });
        let (mut client_in, server_in) = duplex(64 << 10);
        let (server_out, client_out) = duplex(64 << 10);
        let (answers_tx, mut answers_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let feed = tokio::spawn(async move {
            let mut line = header.to_string();
            line.push('\n');
            client_in.write_all(line.as_bytes()).await.unwrap();
            while let Some(frame) = answers_rx.recv().await {
                client_in.write_all(&frame).await.unwrap();
            }
            std::future::pending::<()>().await;
        });
        let read = tokio::spawn(async move {
            let mut lines = BufReader::new(client_out).lines();
            let mut out = Vec::new();
            while let Ok(Some(text)) = lines.next_line().await {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if let Some(need) = broker::Need::parse(&value) {
                    let answer = Ok(Some(secrecy::SecretString::from("s3cret")));
                    let _ =
                        answers_tx.send(protocol::control(&broker::answer_line(need.id, &answer)));
                }
                out.push(value);
            }
            out
        });
        let mut relay = relay(4);
        relay.credentials = RelayCredentials::Any;
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            run(&relay, server_in, server_out),
        )
        .await
        .expect("the relay does not wait for an answer that cannot come");
        feed.abort();
        let lines = read.await.unwrap();
        assert!(
            lines.iter().any(|l| l.get("need").is_some()),
            "no question: {lines:?}"
        );
        assert_eq!(code, 2, "{lines:?}");
        let message = lines.last().unwrap()["error"]["message"].to_string();
        assert!(message.contains("more than this relay takes"), "{message}");
        let seen = server.await.unwrap();
        assert!(
            seen.iter().any(|r| r
                .to_ascii_lowercase()
                .contains("authorization: basic dtpzm2nyzxq=")),
            "{seen:?}"
        );
    }

    /// A source that does not say how large it is is held to --max-size
    /// as it is read.
    #[tokio::test]
    async fn max_size_holds_for_a_source_of_unknown_size() {
        let dir = tempfile::tempdir().unwrap();
        let (port, _server) = http_server(b"0123456789", false).await;
        let header = json!({
            "src": format!("http://127.0.0.1:{port}/f.bin?timeout=5"),
            "dst": [format!("{}/", dir.path().display())],
        });
        let (mut client_in, server_in) = duplex(64 << 10);
        let (server_out, mut client_out) = duplex(64 << 10);
        let feed = tokio::spawn(async move {
            let mut line = header.to_string();
            line.push('\n');
            client_in.write_all(line.as_bytes()).await.unwrap();
            std::future::pending::<()>().await;
        });
        let read = tokio::spawn(async move {
            let mut text = String::new();
            client_out.read_to_string(&mut text).await.unwrap();
            text
        });
        let code = run(&relay(4), server_in, server_out).await;
        feed.abort();
        let text = read.await.unwrap();
        assert_eq!(code, 1, "{text}");
        assert!(text.contains("larger than this relay takes"), "{text}");
        assert!(!dir.path().join("f.bin").exists());
    }

    /// A client that does not read the relay's lines for a while holds up
    /// none of the copy: the lines wait, the payload keeps flowing.
    #[tokio::test]
    async fn a_client_that_does_not_read_does_not_stall_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 241) as u8).collect();
        let header = json!({
            "v": 1, "name": "slow.bin", "size": payload.len(),
            "dst": [format!("{}/", dir.path().display())]
        });
        let (mut client_in, server_in) = duplex(64 << 10);
        // Room for one progress line, not for two.
        let (server_out, mut client_out) = duplex(64);
        let feed = {
            let payload = payload.clone();
            tokio::spawn(async move {
                let mut line = header.to_string();
                line.push('\n');
                client_in.write_all(line.as_bytes()).await.unwrap();
                for chunk in payload.chunks(20_000) {
                    client_in.write_all(chunk).await.unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            })
        };
        let relay = relay(0);
        let running = run(&relay, server_in, server_out);
        tokio::pin!(running);
        let done = dir.path().join("slow.bin");
        let arrived = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    code = &mut running => panic!("the relay ended unread: {code}"),
                    () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                        if std::fs::read(&done).is_ok_and(|d| d == payload) {
                            break;
                        }
                    }
                }
            }
        })
        .await;
        assert!(arrived.is_ok(), "the copy stalled behind the unread lines");
        let read = tokio::spawn(async move {
            let mut text = String::new();
            client_out.read_to_string(&mut text).await.unwrap();
            text
        });
        assert_eq!(running.await, 0);
        feed.await.unwrap();
        let text = read.await.unwrap();
        assert!(text.contains("\"report\""), "{text}");
    }

    /// A version 2 client that stops before the size is reached fails the
    /// targets like a short version 1 payload does.
    #[tokio::test]
    async fn a_framed_payload_that_ends_early_fails_every_target() {
        let dir = tempfile::tempdir().unwrap();
        let header =
            json!({ "name": "x.bin", "size": 100, "dst": [format!("{}/", dir.path().display())] });
        let mut payload = protocol::frame(protocol::DATA, &[1u8; 40]);
        payload.extend(protocol::frame(protocol::DATA, &[2u8; 20]));
        let (code, lines) = relay_run(&relay(0), &header.to_string(), &payload).await;
        assert_eq!(code, 1, "{lines:?}");
        let err = lines.last().unwrap()["report"]["targets"][0]["error"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(err.contains("60 of 100"), "{err}");
        assert!(!dir.path().join("x.bin").exists());
    }

    /// An empty data frame is no end of the payload.
    #[tokio::test]
    async fn an_empty_data_frame_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let header =
            json!({ "name": "x.bin", "size": 6, "dst": [format!("{}/", dir.path().display())] });
        let mut payload = protocol::frame(protocol::DATA, b"abc");
        payload.extend(protocol::frame(protocol::DATA, b""));
        payload.extend(protocol::frame(protocol::DATA, b"def"));
        let (code, lines) = relay_run(&relay(0), &header.to_string(), &payload).await;
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(std::fs::read(dir.path().join("x.bin")).unwrap(), b"abcdef");
    }

    /// A frame the relay cannot take ends the session with that error,
    /// and no target keeps what arrived before it.
    #[tokio::test]
    async fn a_malformed_frame_ends_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let header =
            json!({ "name": "x.bin", "size": 100, "dst": [format!("{}/", dir.path().display())] });
        let mut payload = protocol::frame(protocol::DATA, &[1u8; 40]);
        payload.extend([9u8, 0, 0, 0, 1, 0]);
        payload.extend(protocol::frame(protocol::DATA, &[2u8; 60]));
        let (code, lines) = relay_run(&relay(0), &header.to_string(), &payload).await;
        assert_eq!(code, 2, "{lines:?}");
        let error = &lines.last().unwrap()["error"];
        assert_eq!(error["kind"], "invalid_option", "{lines:?}");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("unknown frame kind 9"),
            "{error}"
        );
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn a_payload_that_ends_early_fails_every_target() {
        let dir = tempfile::tempdir().unwrap();
        let header = json!({ "v": 1, "name": "x.bin", "size": 100, "dst": [format!("{}/", dir.path().display())] });
        let (code, lines) = relay_run(&relay(0), &header.to_string(), &[1u8; 40]).await;
        assert_eq!(code, 1, "{lines:?}");
        let report = &lines.last().unwrap()["report"];
        assert_eq!(report["ok"], false);
        let err = report["targets"][0]["error"].as_str().unwrap();
        assert!(err.contains("40 of 100"), "{err}");
        assert!(!dir.path().join("x.bin").exists());
        assert!(!dir.path().join("x.bin.mpt-part").exists());
    }

    #[tokio::test]
    async fn bad_headers_are_refused_before_anything_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = format!("{}/", dir.path().display());
        for (header, what) in [
            ("not json".to_string(), "header"),
            (json!({ "name": "x", "size": 1, "dst": [] }).to_string(), "dst"),
            (json!({ "v": 4, "name": "x", "size": 1, "dst": [target.clone()] }).to_string(), "v"),
            (json!({ "name": "x", "size": 1 }).to_string(), "dst"),
            (json!({ "v": 1, "name": "x", "size": 1, "dst": [target.clone()], "credentials": "on-demand" }).to_string(), "credentials"),
            (json!({ "name": "x", "dst": [target.clone()] }).to_string(), "header"),
            (json!({ "src": "/x", "name": "x", "size": 1, "dst": [target.clone()] }).to_string(), "src"),
            (json!({ "v": 1, "src": "/x", "dst": [target.clone()] }).to_string(), "src"),
            (json!({ "name": "x", "size": 1, "dst": [target.clone()], "credentials": "on-demand" }).to_string(), "credentials"),
            (json!({ "name": "x", "size": 1, "dst": ["ftp://u:pw@h/"], "credentials": "on-demand" }).to_string(), "credentials"),
            (json!({ "name": "x", "size": 1, "dst": [target.clone()], "options": { "check": true } }).to_string(), "check"),
            (json!({ "name": "x", "size": 1, "dst": [target.clone()], "options": { "retries": 2 } }).to_string(), "retries"),
            (json!({ "name": "x", "size": 1, "dst": [target.clone()], "nope": 1 }).to_string(), "header"),
            (json!({ "name": "x", "size": 5_000, "dst": [target.clone()] }).to_string(), "size"),
            (json!({ "name": "x", "size": 1, "dst": [{ "url": target.clone(), "via": "ssh://r/", "hop": 2 }] }).to_string(), "header"),
            (json!({ "name": "x", "size": 1, "dsts": [] }).to_string(), "dst"),
        ] {
            let (code, lines) = relay_run(&relay(4_096), &header, b"x").await;
            assert_eq!(code, 2, "{header}: {lines:?}");
            assert_eq!(lines.len(), 1, "{lines:?}");
            let error = &lines[0]["error"];
            assert_eq!(error["kind"], "invalid_option", "{header}");
            assert!(
                error["message"].as_str().unwrap().contains(what),
                "{header}: {}",
                error["message"]
            );
        }
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    /// A password the relay would add itself (a profile of its own) is
    /// refused in an on-demand session like one in the URL: it would win
    /// over the question, and the client would never be asked.
    #[tokio::test]
    async fn an_on_demand_session_takes_no_password_from_the_relay_either() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = relay(0);
        r.credentials = RelayCredentials::Any;
        r.locate = Arc::new(|url, _| {
            let mut loc = crate::Location::parse(url)?;
            if loc.scheme() == crate::Scheme::Ftp {
                loc.set_password("the-relays-own");
            }
            Ok(loc)
        });
        let header = json!({
            "name": "x", "size": 1, "credentials": "on-demand",
            "dst": [format!("{}/", dir.path().display()), "ftp://u@h/"]
        });
        let (code, lines) = relay_run(&r, &header.to_string(), b"").await;
        assert_eq!(code, 2, "{lines:?}");
        let message = lines[0]["error"]["message"].as_str().unwrap();
        assert!(message.contains("asked for on demand"), "{message}");
        assert!(!message.contains("the-relays-own"), "{message}");
    }

    #[tokio::test]
    async fn a_header_without_newline_is_refused() {
        // Straight from a cursor: no newline is ever appended here.
        for (input, what) in [
            (b"{\"name\": \"x\"".to_vec(), "no line"),
            (vec![b'x'; MAX_HEADER + 10], "longer than"),
        ] {
            let mut out = Vec::new();
            let code = run(&relay(0), std::io::Cursor::new(input), &mut out).await;
            assert_eq!(code, 2);
            let line: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let message = line["error"]["message"].as_str().unwrap();
            assert!(message.contains(what), "{message}");
        }
    }

    /// A client that sends nothing is refused after a while, and gives
    /// its slot back.
    #[tokio::test(start_paused = true)]
    async fn a_header_that_never_comes_is_refused() {
        let (_client_in, server_in) = duplex(1024);
        let mut out = Vec::new();
        let code = run(&relay(0), server_in, &mut out).await;
        assert_eq!(code, 2);
        let line: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let message = line["error"]["message"].as_str().unwrap();
        assert!(message.contains("no header line within 30s"), "{message}");
    }

    #[tokio::test]
    async fn the_relay_options_are_the_base() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = relay(0);
        r.copy.hash = Some(HashAlgo::Sha256);
        let header = json!({ "v": 1, "name": "x.bin", "size": 3, "dst": [format!("{}/", dir.path().display())] });
        let (code, _) = relay_run(&r, &header.to_string(), b"abc").await;
        assert_eq!(code, 0);
        assert!(dir.path().join("x.bin.sha256").exists());
    }

    #[test]
    fn exit_codes_follow_the_failed_targets() {
        use crate::transfer::TargetReport;
        let target = |result: Result<()>| TargetReport {
            target: String::new(),
            bytes: 0,
            elapsed: std::time::Duration::ZERO,
            attempts: 1,
            result,
            sidecar: None,
            signature: None,
            skipped: false,
        };
        let report = |targets| FanoutReport {
            source: String::new(),
            bytes_read: 0,
            elapsed: std::time::Duration::ZERO,
            targets,
            digests: Vec::new(),
            checked: None,
            source_removed: None,
        };
        assert_eq!(exit_code(&report(vec![target(Ok(()))])), 0);
        assert_eq!(
            exit_code(&report(vec![
                target(Ok(())),
                target(Err(Error::Auth("x".into())))
            ])),
            4
        );
        assert_eq!(
            exit_code(&report(vec![
                target(Err(Error::Auth("x".into()))),
                target(Err(Error::Remote("y".into())))
            ])),
            1
        );
        assert_eq!(
            exit_code(&report(vec![
                target(Err(Error::Cancelled)),
                target(Err(Error::Remote("y".into())))
            ])),
            130
        );
    }
}
