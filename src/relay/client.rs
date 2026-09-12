//! The client side of a relay: open an SSH session, run `mpt relay`, feed
//! it the header and the payload, and read what it says back.
//!
//! Three tasks share the channel. The writer owns its writing half and
//! takes what the other two hand it, a control frame before a data frame
//! every time. The feeder cuts the body into data frames as long as it has
//! credit for them. The reader — this function's own loop — turns the
//! relay's lines into credit, into questions for the [`PasswordAnswerer`]
//! (answered in a task of their own, so a slow answer stalls nothing) and
//! into the outcome.

use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::broker::{Need, PasswordAnswerer, answer_line};
use super::protocol::{self, Credit};
use super::{Credentials, Header};
use crate::protocols::ssh::{SshConfig, disconnect, ssh_err};
use crate::{ByteStream, Error, Location, Result};

/// What the relay said at the end.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The relay's exit status: what `cp` would have given.
    pub exit: u8,
    /// The `report` line, the shape of `--json`.
    pub report: Option<Value>,
    /// The `error` line, when the relay refused or could not read.
    pub error: Option<Value>,
    /// Whatever the relay wrote to stderr (its log, when it was asked for one).
    pub stderr: String,
}

/// One session with a relay: where, what, and who answers its questions.
pub struct Session<'a> {
    /// The relay, an `ssh://` location.
    pub via: &'a Location,
    pub header: &'a Header,
    /// The payload; `None` when the header names a source the relay reads
    /// itself.
    pub body: Option<ByteStream>,
    /// Closes the channel, which makes the relay fail its targets and
    /// clean up.
    pub cancel: &'a CancellationToken,
    /// Answers the relay's `need` lines.
    pub answer: Arc<dyn PasswordAnswerer>,
}

/// Run a relay for `session`, hand every line the relay writes to
/// `on_line` and return the outcome.
pub async fn send(session: Session<'_>, mut on_line: impl FnMut(&Value)) -> Result<Outcome> {
    let Session {
        via,
        header,
        body,
        cancel,
        answer,
    } = session;
    if header.credentials == Credentials::OnDemand {
        for dst in &header.dst {
            if Location::parse(dst.url()).is_ok_and(|l| l.password_in_url()) {
                return Err(Error::invalid_option(
                    "credentials",
                    format!(
                        "{}: a password in the header of an on-demand session",
                        dst.url()
                    ),
                ));
            }
        }
    }
    let cfg = SshConfig::from_location(via)?;
    let handle = cfg.connect().await?;
    let result = async {
        let mut channel = handle.channel_open_session().await.map_err(ssh_err)?;
        channel.exec(true, "mpt relay").await.map_err(ssh_err)?;
        let mut line =
            serde_json::to_string(header).map_err(|e| Error::invalid_option("header", e))?;
        line.push('\n');

        // The writer: control frames first, then data, until both senders
        // are gone.
        let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(4);
        let mut writer = channel.make_writer();
        let writing = tokio::spawn(async move {
            writer.write_all(line.as_bytes()).await?;
            let (mut ctl_open, mut data_open) = (true, true);
            while ctl_open || data_open {
                tokio::select! {
                    biased;
                    c = ctl_rx.recv(), if ctl_open => match c {
                        Some(bytes) => writer.write_all(&bytes).await?,
                        None => ctl_open = false,
                    },
                    d = data_rx.recv(), if data_open => match d {
                        Some(bytes) => writer.write_all(&bytes).await?,
                        None => data_open = false,
                    },
                }
            }
            writer.flush().await
        });

        // The feeder: the body in frames, as the credit allows.
        let credit = Arc::new(Credit::new(protocol::INITIAL_CREDIT));
        let feeding = body.map(|mut body| {
            let credit = Arc::clone(&credit);
            let data_tx = data_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; protocol::CHUNK];
                loop {
                    let n = body.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    credit.take(n as u64).await;
                    if data_tx
                        .send(protocol::frame(protocol::DATA, &buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok::<(), std::io::Error>(())
            })
        });
        drop(data_tx);

        let mut outcome = Outcome::default();
        let mut exit = None;
        let mut pending = Vec::new();
        let mut accepted = false;
        loop {
            let msg = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    let _ = channel.close().await;
                    return Err(Error::Cancelled);
                }
                msg = channel.wait() => msg,
            };
            let Some(msg) = msg else { break };
            match msg {
                russh::ChannelMsg::Success => accepted = true,
                russh::ChannelMsg::Failure => {
                    return Err(Error::Remote(
                        "the server does not run `mpt relay` (not a relay, or not in its PATH)"
                            .into(),
                    ));
                }
                russh::ChannelMsg::Data { data } => {
                    pending.extend_from_slice(&data);
                    while let Some(nl) = pending.iter().position(|b| *b == b'\n') {
                        let raw: Vec<u8> = pending.drain(..=nl).collect();
                        match serde_json::from_slice::<Value>(&raw[..nl]) {
                            Ok(value) => {
                                if let Some(n) = value.get("credit").and_then(Value::as_u64) {
                                    credit.grant(n);
                                    continue;
                                }
                                if let Some(need) = Need::parse(&value) {
                                    let answer = Arc::clone(&answer);
                                    let ctl = ctl_tx.clone();
                                    tokio::spawn(async move {
                                        let reply = answer.answer(&need).await;
                                        if let Err(e) = &reply {
                                            debug!(target = %need.target, "no password for the relay: {e}");
                                        }
                                        let _ = ctl.send(protocol::control(&answer_line(
                                            need.id, &reply,
                                        )));
                                    });
                                    continue;
                                }
                                if let Some(r) = value.get("report") {
                                    outcome.report = Some(r.clone());
                                }
                                if let Some(e) = value.get("error") {
                                    outcome.error = Some(e.clone());
                                }
                                on_line(&value);
                            }
                            Err(e) => debug!("relay wrote a line that is not JSON: {e}"),
                        }
                    }
                }
                russh::ChannelMsg::ExtendedData { data, .. } => {
                    outcome.stderr.push_str(&String::from_utf8_lossy(&data));
                }
                russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close if exit.is_some() => break,
                _ => {}
            }
        }
        // The feeder may still be waiting for credit when the relay is
        // done: its error is the relay's line, not the pipe's.
        if let Some(feeding) = feeding {
            feeding.abort();
        }
        drop(ctl_tx);
        writing.abort();
        match exit {
            Some(code) => outcome.exit = u8::try_from(code).unwrap_or(1),
            None if accepted => {
                return Err(Error::Remote(
                    "the relay ended without an exit status".into(),
                ));
            }
            None => {
                return Err(Error::Remote(
                    "the relay never started (the server closed the channel)".into(),
                ));
            }
        }
        Ok(outcome)
    }
    .await;
    disconnect(&handle).await;
    result
}
