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
//! A target of the header may name a relay of its own. The relay then
//! writes it through that one ([`endpoint`]), with the same protocol and
//! the same questions — which it passes on to the client — so a file goes
//! from one relay's reach to another's without coming through the client.
//!
//! Nothing is spooled: the targets read the payload as it arrives, so the
//! slowest of them sets the pace, and the source ending early (the client
//! going away) fails them all. Everything `cp` does — checksums, atomic
//! finishing, the memory cache with retries, timeouts — applies unchanged.

pub mod agent;
pub mod broker;
pub mod client;
pub mod endpoint;
pub mod plan;
pub mod protocol;
pub mod sshd;

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

/// The protocol version a client sends.
pub const VERSION: u32 = 2;

/// The longest header line a relay reads.
pub const MAX_HEADER: usize = 64 * 1024;

/// The first line on stdin: what to call the file, how many bytes follow,
/// where they go and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    #[serde(default = "version")]
    pub v: u32,
    /// The source the relay reads itself, instead of a payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// The file's name, when a payload follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// How many bytes the payload has, when one follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(alias = "dsts")]
    pub dst: Vec<Dst>,
    /// Where the targets' passwords come from.
    #[serde(default, skip_serializing_if = "Credentials::is_header")]
    pub credentials: Credentials,
    /// The client forwards its ssh-agent for the SSH targets.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub agent: bool,
    #[serde(default, skip_serializing_if = "is_default")]
    pub options: JobOptions,
}

impl Header {
    /// A header for a payload of `size` bytes called `name`.
    pub fn stream(name: impl Into<String>, size: u64, dst: Vec<String>) -> Header {
        Header {
            v: VERSION,
            src: None,
            name: Some(name.into()),
            size: Some(size),
            dst: dst.into_iter().map(Dst::Url).collect(),
            credentials: Credentials::Header,
            agent: false,
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

/// One target of a header: a URL, or a URL behind a relay of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
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
    let mut reader = BufReader::new(reader);
    // Lines for the client from wherever they arise: progress here, credit
    // from the intake, `need` from the broker.
    let (lines, mut lines_rx) = mpsc::unbounded_channel::<Value>();
    let cancel = relay.cancel.child_token();
    let header = match read_header(relay, &mut reader).await {
        Ok(h) => h,
        Err(e) => return refuse(&mut writer, e).await,
    };
    let broker = match header.credentials {
        Credentials::OnDemand => Some(RemoteBroker::new(lines.clone(), cancel.clone())),
        Credentials::Header => None,
    };
    let name = header.name.clone().unwrap_or_default();
    let size = header.size.unwrap_or(0);
    // In version 2 the frames are taken apart from here on, before a
    // target is opened: opening one may already ask the client for a
    // password, and the answer comes in a control frame.
    let (payload, intake): (Option<Box<dyn AsyncRead + Send + Unpin>>, _) = match header.v {
        1 => (Some(Box::new(reader)), None),
        _ => {
            let (data_tx, data_rx) = mpsc::unbounded_channel();
            let (consumed_tx, consumed_rx) = mpsc::unbounded_channel();
            // With a source the relay reads itself, the client's input
            // carries control frames only, and its end means the client
            // is gone. A data frame then has nowhere to go and ends the
            // session.
            let (payload, on_end) = match header.src {
                Some(_) => (None, Some(cancel.clone())),
                None => (
                    Some(Box::new(ChannelReader::new(data_rx, consumed_tx))
                        as Box<dyn AsyncRead + Send + Unpin>),
                    None,
                ),
            };
            let intake = tokio::spawn(intake(
                reader,
                data_tx,
                consumed_rx,
                lines.clone(),
                broker.clone(),
                on_end,
            ));
            (payload, Some(intake))
        }
    };
    // The `need` lines of the logins in `prepare` go out while it runs.
    let preparing = prepare(relay, &header, &broker, &cancel, agent);
    tokio::pin!(preparing);
    let prepared = loop {
        tokio::select! {
            r = &mut preparing => break r,
            Some(msg) = lines_rx.recv() => {
                if line(&mut writer, &msg).await.is_err() {
                    debug!("relay: the client stopped reading");
                }
            }
        }
    };
    let stop = |intake: Option<tokio::task::JoinHandle<()>>| {
        if let Some(intake) = intake {
            intake.abort();
        }
        if let Some(broker) = &broker {
            broker.close();
        }
    };
    let Prepared {
        copy,
        source,
        targets,
    } = match prepared {
        Ok(p) => p,
        Err(e) => {
            stop(intake);
            return refuse(&mut writer, e).await;
        }
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
        Err(e) => {
            stop(intake);
            return refuse(&mut writer, e).await;
        }
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
            Some(msg) = lines_rx.recv() => {
                if line(&mut writer, &msg).await.is_err() {
                    debug!("relay: the client stopped reading");
                }
            }
            _ = tick.tick() => {
                let read = progress.read();
                if last != Some(read) {
                    last = Some(read);
                    let msg = json!({ "progress": { "read": read, "total": progress.total() } });
                    if line(&mut writer, &msg).await.is_err() {
                        // Nobody is listening any more: the copy still
                        // finishes, its report goes nowhere.
                        debug!("relay: the client stopped reading");
                    }
                }
            }
        }
    };
    stop(intake);
    match outcome {
        Ok(report) => {
            let _ = line(
                &mut writer,
                &json!({ "report": crate::report::fanout_json(&report) }),
            )
            .await;
            exit_code(&report)
        }
        Err(e) => refuse(&mut writer, e).await,
    }
}

/// Write `e` as the session's `error` line and give its exit code.
async fn refuse<W: AsyncWrite + Unpin>(writer: &mut W, e: Error) -> u8 {
    debug!("relay: {e}");
    let _ = line(writer, &json!({ "error": crate::report::error_json(&e) })).await;
    e.exit_code()
}

/// Version 2: take the frames apart. Data goes to the copy through
/// `data`, an answer to the broker, and what the copy has consumed (told
/// on `consumed`) comes back to the client as credit. Ends when the
/// client's input does, or when it sends what it may not; `on_end` is
/// cancelled then, for a copy whose source is not that input.
async fn intake<R: AsyncRead + Unpin>(
    mut reader: R,
    data: mpsc::UnboundedSender<Vec<u8>>,
    mut consumed: mpsc::UnboundedReceiver<u64>,
    lines: mpsc::UnboundedSender<Value>,
    broker: Option<Arc<RemoteBroker>>,
    on_end: Option<CancellationToken>,
) {
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
                Ok(Some(Frame::Data(bytes))) => {
                    received += bytes.len() as u64;
                    if received > granted.load(Ordering::SeqCst) {
                        warn!("relay: the client sent more data than it had credit for");
                        break;
                    }
                    if data.send(bytes).is_err() {
                        break;
                    }
                }
                Ok(Some(Frame::Control(value))) => match &broker {
                    Some(broker) => broker.answer(&value),
                    None => debug!("relay: control frame in a header session: {value}"),
                },
                Ok(None) => {
                    debug!("relay: the client's input ended");
                    break;
                }
                Err(e) => {
                    warn!("relay: {e}");
                    break;
                }
            }
        }
    };
    reading.await;
    crediting.abort();
    if let Some(broker) = &broker {
        broker.close();
    }
    if let Some(cancel) = on_end {
        cancel.cancel();
    }
}

/// Read and check the header. Nothing of the payload is read.
async fn read_header<R: AsyncRead + Unpin>(
    relay: &Relay,
    reader: &mut BufReader<R>,
) -> Result<Header> {
    let mut raw = Vec::new();
    reader
        .take(MAX_HEADER as u64 + 1)
        .read_until(b'\n', &mut raw)
        .await?;
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
                "this relay speaks versions 1 and {VERSION}, not {}",
                header.v
            ),
        ));
    }
    if header.v == 1 {
        for (what, wrong) in [
            ("src", header.src.is_some()),
            ("credentials", header.credentials != Credentials::Header),
            ("agent", header.agent),
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
    let mut copy = header.options.apply(&relay.copy, relay.cache_limit)?;
    copy.check = false;
    copy.verify = None;
    // Only a source the relay opened itself can be deleted by it.
    copy.delete_source = header.src.is_some() && o.delete_source == Some(true);
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
                    header_url: url.clone(),
                    credentials: header.credentials,
                    options,
                    agent: agent.clone(),
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
            let loc = with_broker(loc, broker, Who::Src)?;
            let source = crate::protocols::open(with_agent(loc, &agent))?;
            if relay.max_size > 0
                && let Some(size) = source.receiver()?.size().await?
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
            Some(source)
        }
    };
    Ok(Prepared {
        copy,
        source,
        targets,
    })
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

    /// A source named in the header is read by the relay, and deleted by
    /// it when asked; nothing of the file comes over the pipe. The
    /// client's input stays open until the relay is done.
    #[tokio::test]
    async fn a_source_the_relay_reads_itself() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in").join("x.bin");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 229) as u8).collect();
        std::fs::write(&src, &payload).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let header = json!({
            "src": src.display().to_string(),
            "dst": [format!("{}/", out.display())],
            "options": { "delete_source": true, "hash": "sha256" }
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
        let code = run(&relay(0), server_in, server_out).await;
        feed.abort();
        let text = read.await.unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(std::fs::read(out.join("x.bin")).unwrap(), payload);
        assert!(out.join("x.bin.sha256").exists());
        assert!(!src.exists(), "the relay deletes the source it read");
        let report = &lines.last().unwrap()["report"];
        assert_eq!(report["source_removed"], true, "{report}");
        assert_eq!(report["bytes_read"], payload.len());

        // Too large for this relay: refused before anything is read.
        std::fs::write(&src, &payload).unwrap();
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

    /// An HTTP server on a free port that answers every request with
    /// `body` and hands back the requests it saw.
    async fn http_server(body: &'static [u8]) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
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
                let mut answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
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
        let (port, server) = http_server(b"0123456789").await;
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
            (json!({ "v": 3, "name": "x", "size": 1, "dst": [target.clone()] }).to_string(), "v"),
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
