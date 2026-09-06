//! The client side of a relay: open an SSH session, run `mpt relay`, feed
//! it the header and the payload, and read what it says back.

use futures::future::FutureExt;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::Header;
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

/// Run a relay on `via` (an `ssh://` location) with `header`, send `body`
/// after it, hand every line the relay writes to `on_line` and return the
/// outcome. `cancel` closes the channel, which makes the relay fail its
/// targets and clean up.
pub async fn send(
    via: &Location,
    header: &Header,
    body: ByteStream,
    cancel: &CancellationToken,
    mut on_line: impl FnMut(&Value),
) -> Result<Outcome> {
    let cfg = SshConfig::from_location(via)?;
    let handle = cfg.connect().await?;
    let result = async {
        let mut channel = handle.channel_open_session().await.map_err(ssh_err)?;
        channel.exec(true, "mpt relay").await.map_err(ssh_err)?;
        let mut line =
            serde_json::to_string(header).map_err(|e| Error::invalid_option("header", e))?;
        line.push('\n');
        let mut writer = channel.make_writer();
        let feed = tokio::spawn(async move {
            let mut body = body;
            writer.write_all(line.as_bytes()).await?;
            tokio::io::copy(&mut body, &mut writer).await?;
            writer.shutdown().await
        });
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
        // The feeder may still be writing when the relay refused the
        // header: its error is the relay's line, not the pipe's.
        feed.abort();
        if let Some(Ok(Err(e))) = feed.now_or_never() {
            debug!("relay input: {e}");
        }
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
