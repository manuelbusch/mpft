//! `mpt relay`: one upload, fanned out by the relay.
//!
//! A relay is `cp` with its stdin as the source. The first line on stdin
//! is a JSON [`Header`] — the file's name and size, the targets, the
//! options — and exactly `size` bytes follow. While the copy runs the
//! relay writes JSON lines to stdout: `{"progress": …}` four times a
//! second, then `{"report": …}` (the shape of `--json`) or `{"error": …}`,
//! and it exits the way `cp` would. A relay listens on stdin because that
//! is what an SSH channel looks like from inside: [`sshd`] runs it on a
//! channel of its own server, and a plain sshd runs the binary.
//!
//! Nothing is spooled: the targets read the payload as it arrives, so the
//! slowest of them sets the pace, and the source ending early (the client
//! going away) fails them all. Everything `cp` does — checksums, atomic
//! finishing, the memory cache with retries, timeouts — applies unchanged.

pub mod client;
pub mod sshd;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::options::{JobOptions, LocateFn};
use crate::stream::{Idle, ReaderEndpoint};
use crate::transfer::{CopyOptions, FanoutReport, Progress};
use crate::{Endpoint, Error, Result};

/// The protocol version a relay speaks.
pub const VERSION: u32 = 1;

/// The longest header line a relay reads.
pub const MAX_HEADER: usize = 64 * 1024;

/// The first line on stdin: what to call the file, how many bytes follow,
/// where they go and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    #[serde(default = "version")]
    pub v: u32,
    pub name: String,
    pub size: u64,
    #[serde(alias = "dsts")]
    pub dst: Vec<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub options: JobOptions,
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
    /// Stops the running copy: Ctrl-C on the relay.
    pub cancel: CancellationToken,
}

/// Run one relay: read the header and the payload from `reader`, write
/// progress and the outcome to `writer`, and return the exit code `cp`
/// would give — 0 when every target has the file.
pub async fn run<R, W>(relay: &Relay, reader: R, mut writer: W) -> u8
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let (header, copy, targets) = match prepare(relay, &mut reader).await {
        Ok(p) => p,
        Err(e) => {
            debug!("relay refused: {e}");
            let _ = line(
                &mut writer,
                &json!({ "error": crate::report::error_json(&e) }),
            )
            .await;
            return e.exit_code();
        }
    };
    info!(name = %header.name, size = header.size, targets = targets.len(), "relay");
    let src = match ReaderEndpoint::new(
        &header.name,
        header.size,
        Idle::maybe(reader, copy.tee.send_timeout),
    ) {
        Ok(s) => s,
        Err(e) => {
            let _ = line(
                &mut writer,
                &json!({ "error": crate::report::error_json(&e) }),
            )
            .await;
            return e.exit_code();
        }
    };
    let progress = copy.progress.clone().unwrap_or_else(Progress::new);
    let refs: Vec<&dyn Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let copying = crate::transfer::copy_many(&src, &refs, &copy);
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
    match outcome {
        Ok(report) => {
            let _ = line(
                &mut writer,
                &json!({ "report": crate::report::fanout_json(&report) }),
            )
            .await;
            exit_code(&report)
        }
        Err(e) => {
            let _ = line(
                &mut writer,
                &json!({ "error": crate::report::error_json(&e) }),
            )
            .await;
            e.exit_code()
        }
    }
}

/// Read and check the header, lay its options over the relay's, open the
/// targets. Nothing of the payload is read.
async fn prepare<R: AsyncRead + Unpin>(
    relay: &Relay,
    reader: &mut BufReader<R>,
) -> Result<(Header, CopyOptions, Vec<Box<dyn Endpoint>>)> {
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
    if header.v != VERSION {
        return Err(Error::invalid_option(
            "v",
            format!("this relay speaks version {VERSION}, not {}", header.v),
        ));
    }
    if header.dst.is_empty() {
        return Err(Error::invalid_option("dst", "no target given"));
    }
    if relay.max_size > 0 && header.size > relay.max_size {
        return Err(Error::invalid_option(
            "size",
            format!(
                "{} bytes is more than this relay takes ({})",
                header.size, relay.max_size
            ),
        ));
    }
    let o = &header.options;
    for (name, set) in [
        ("check", o.check == Some(true)),
        ("delete_source", o.delete_source == Some(true)),
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
    copy.delete_source = false;
    copy.cancel = Some(relay.cancel.child_token());
    copy.progress = Some(Progress::new());
    let targets = header
        .dst
        .iter()
        .map(|url| crate::protocols::open((relay.locate)(url, &header.options)?))
        .collect::<Result<Vec<_>>>()?;
    Ok((header, copy, targets))
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
            "name": "data.bin", "size": payload.len(),
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

    #[tokio::test]
    async fn a_payload_that_ends_early_fails_every_target() {
        let dir = tempfile::tempdir().unwrap();
        let header =
            json!({ "name": "x.bin", "size": 100, "dst": [format!("{}/", dir.path().display())] });
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
            (json!({ "v": 2, "name": "x", "size": 1, "dst": [target.clone()] }).to_string(), "v"),
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
        let header =
            json!({ "name": "x.bin", "size": 3, "dst": [format!("{}/", dir.path().display())] });
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
