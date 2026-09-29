//! The outcome of a copy as JSON, for scripts and the API.
//!
//! The shape is what `mpft --json` prints (documented in the README under
//! "Machine-readable output"), so a script reads the same fields whether
//! it ran the command or asked the server.

use std::time::Duration;

use serde_json::{Value, json};

use crate::transfer::{CheckReport, FanoutReport, TargetReport};
use crate::{Error, HashAlgo, Result};

/// One entry of a listing, the shape `ls --json` prints: `name`, `size`,
/// `is_dir` and `modified` (RFC 3339, or `null`).
pub fn entry_json(e: &crate::Entry) -> Value {
    json!({
        "name": e.name,
        "size": e.size,
        "is_dir": e.is_dir,
        "modified": e.modified.map(crate::sign::format_time),
    })
}

/// [`entry_json`] read back.
pub fn entry_from_json(v: &Value) -> Result<crate::Entry> {
    let bad = |what: &str| Error::Remote(format!("a listed entry without {what}: {v}"));
    Ok(crate::Entry {
        name: v["name"].as_str().ok_or_else(|| bad("a name"))?.to_string(),
        size: v["size"].as_u64(),
        is_dir: v["is_dir"].as_bool().ok_or_else(|| bad("is_dir"))?,
        modified: match v["modified"].as_str() {
            Some(t) => Some(crate::sign::parse_time(t).map_err(|_| bad("a valid time"))?),
            None => None,
        },
    })
}

/// The whole outcome of one copy: what was read, what each target did, the
/// digests and the `check` verdict.
pub fn fanout_json(report: &FanoutReport) -> Value {
    let targets: Vec<Value> = report
        .targets
        .iter()
        .map(|t| {
            json!({
                "target": t.target,
                "bytes": t.bytes,
                "elapsed_ms": t.elapsed.as_millis() as u64,
                "attempts": t.attempts,
                "ok": t.result.is_ok(),
                "error": t.result.as_ref().err().map(|e| e.to_string()),
                "kind": t.result.as_ref().err().map(Error::kind),
                "cancelled": matches!(t.result, Err(Error::Cancelled)),
                "sidecar": t.sidecar,
                "signature": t.signature,
                "skipped": t.skipped,
            })
        })
        .collect();
    let digests: serde_json::Map<String, Value> = report
        .digests
        .iter()
        .map(|(algo, hex)| (algo.name().to_string(), hex.as_str().into()))
        .collect();
    let check = report.checked.as_ref().map(|c| {
        json!({
            "algo": c.algo.name(),
            "ok": c.ok(),
            "expected": c.expected,
            "actual": c.actual,
            "signer": c.signer,
        })
    });
    json!({
        "source": report.source,
        "bytes_read": report.bytes_read,
        "elapsed_ms": report.elapsed.as_millis() as u64,
        "ok": report.ok(),
        "targets": targets,
        "digests": digests,
        "check": check,
        "source_removed": report.source_removed.as_ref().map(|r| r.is_ok()),
        "remove_error": report.source_removed.as_ref().and_then(|r| r.as_ref().err().map(|e| e.to_string())),
    })
}

/// A report back from its JSON, as a relay hands it over. A target's
/// failure comes back as an error of its kind (see [`error_from_json`]).
pub fn fanout_from_json(v: &Value) -> Result<FanoutReport> {
    let bad = |what: &str| Error::Remote(format!("report: {what}"));
    let str_of = |v: &Value| v.as_str().map(String::from);
    let ms = |v: &Value| Duration::from_millis(v.as_u64().unwrap_or(0));
    let targets = v["targets"]
        .as_array()
        .ok_or_else(|| bad("no targets"))?
        .iter()
        .map(|t| {
            let result = if t["ok"] == true {
                Ok(())
            } else if t["cancelled"] == true {
                Err(Error::Cancelled)
            } else {
                Err(error_from_json(&json!({
                    "kind": t["kind"],
                    "message": t["error"].as_str().unwrap_or("failed"),
                })))
            };
            TargetReport {
                target: str_of(&t["target"]).unwrap_or_default(),
                bytes: t["bytes"].as_u64().unwrap_or(0),
                elapsed: ms(&t["elapsed_ms"]),
                attempts: t["attempts"].as_u64().unwrap_or(1) as u32,
                result,
                sidecar: str_of(&t["sidecar"]),
                signature: str_of(&t["signature"]),
                skipped: t["skipped"] == true,
            }
        })
        .collect();
    let digests = v["digests"]
        .as_object()
        .map(|d| {
            d.iter()
                .filter_map(|(algo, hex)| {
                    Some((HashAlgo::parse(algo).ok()?, hex.as_str()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let checked = v["check"].as_object().and_then(|c| {
        Some(CheckReport {
            algo: HashAlgo::parse(c.get("algo")?.as_str()?).ok()?,
            expected: str_of(c.get("expected")?)?,
            actual: str_of(c.get("actual")?)?,
            signer: c.get("signer").and_then(str_of),
        })
    });
    let source_removed = match (&v["source_removed"], &v["remove_error"]) {
        (Value::Bool(true), _) => Some(Ok(())),
        (Value::Bool(false), e) => Some(Err(Error::Remote(
            e.as_str().unwrap_or("not removed").to_string(),
        ))),
        _ => None,
    };
    Ok(FanoutReport {
        source: str_of(&v["source"]).unwrap_or_default(),
        bytes_read: v["bytes_read"].as_u64().unwrap_or(0),
        elapsed: ms(&v["elapsed_ms"]),
        targets,
        digests,
        checked,
        source_removed,
    })
}

/// An error as `{"kind": …, "message": …}`; `kind` is [`Error::kind`].
///
/// An I/O error of a kind a caller acts on (a file that is not there, one
/// that may not be touched) says which in `io` as well, so that it comes
/// back as that kind: `"not_found"` or `"permission_denied"`.
pub fn error_json(err: &Error) -> Value {
    let mut v = json!({ "kind": err.kind(), "message": err.to_string() });
    if let Error::Io(e) = err {
        let io = match e.kind() {
            std::io::ErrorKind::NotFound => Some("not_found"),
            std::io::ErrorKind::PermissionDenied => Some("permission_denied"),
            _ => None,
        };
        if let Some(io) = io {
            v["io"] = io.into();
        }
    }
    v
}

/// The error back from its JSON, of the same kind, so it keeps its exit
/// code and its `kind`: a relay's refusal is a usage error here too, its
/// authentication failure one of ours, a checksum that did not hold one as
/// well. What failed over there on the wire or on a disk says `relay:` in
/// its message, since it is not this side's.
pub fn error_from_json(v: &Value) -> Error {
    let message = v["message"].as_str().unwrap_or("refused");
    let after = |prefix: &str| message.strip_prefix(prefix).unwrap_or(message).to_string();
    match v["kind"].as_str().unwrap_or("") {
        "cancelled" => Error::Cancelled,
        "auth" => Error::Auth(after("authentication failed: ")),
        "invalid_option" => {
            // "invalid option 'name': reason"
            let rest = after("invalid option '");
            match rest.split_once("': ") {
                Some((name, reason)) => Error::InvalidOption {
                    name: name.to_string(),
                    reason: reason.to_string(),
                },
                None => Error::InvalidOption {
                    name: "header".into(),
                    reason: message.to_string(),
                },
            }
        }
        "invalid_url" => Error::InvalidUrl(after("invalid URL: ")),
        "config" => Error::Config(after("configuration: ")),
        "signature" => Error::Signature(after("signature: ")),
        "checksum_mismatch" => checksum_mismatch(message),
        "unsupported_scheme" => {
            let rest = after("unsupported scheme '");
            Error::UnsupportedScheme(rest.strip_suffix('\'').unwrap_or(&rest).to_string())
        }
        "unsupported_operation" => {
            // "scheme 'name' cannot op"
            let rest = after("scheme '");
            let (scheme, op) = rest.split_once("' cannot ").unwrap_or(("relay", &rest));
            Error::UnsupportedOperation {
                scheme: scheme.to_string(),
                op: KNOWN_OPS
                    .iter()
                    .find(|known| **known == op)
                    .copied()
                    .unwrap_or("do what was asked"),
            }
        }
        "io" => {
            let kind = match v["io"].as_str() {
                Some("not_found") => std::io::ErrorKind::NotFound,
                Some("permission_denied") => std::io::ErrorKind::PermissionDenied,
                _ => std::io::ErrorKind::Other,
            };
            Error::Io(std::io::Error::new(
                kind,
                format!("relay: {}", after("I/O error: ")),
            ))
        }
        "remote" => Error::Remote(format!("relay: {}", after("remote error: "))),
        _ => Error::Transport {
            protocol: "relay",
            source: message.into(),
        },
    }
}

/// What an unsupported operation may say it cannot do: the texts of this
/// crate, so a relay's comes back with its words.
const KNOWN_OPS: &[&str] = &[
    "receive",
    "send",
    "list",
    "append",
    "remove",
    "rename",
    "create directories",
    "delete its source after the copy",
    "address a sibling file",
    "have a parent directory",
    "have a path appended",
    "create directories (copy a tree elsewhere, or files one by one)",
    "hold files (it names a relay for `cp --via`; sftp:// or scp:// reach its files)",
    "list (use sftp:// instead)",
    "list (use webdav:// for PROPFIND)",
];

/// "`algo` checksum mismatch: expected `x`, got `y`" back as the error.
fn checksum_mismatch(message: &str) -> Error {
    let parsed = message
        .split_once(" checksum mismatch: expected ")
        .and_then(|(algo, rest)| {
            let (expected, actual) = rest.split_once(", got ")?;
            Some((HashAlgo::parse(algo).ok()?.name(), expected, actual))
        });
    match parsed {
        Some((algo, expected, actual)) => Error::ChecksumMismatch {
            algo,
            expected: expected.to_string(),
            actual: actual.to_string(),
        },
        None => Error::ChecksumMismatch {
            algo: "checksum",
            expected: String::new(),
            actual: message.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_entry_survives_the_round_trip() {
        let e = crate::Entry {
            name: "a b.csv".into(),
            size: Some(7),
            is_dir: false,
            modified: Some(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        };
        let back = entry_from_json(&entry_json(&e)).unwrap();
        assert_eq!(
            (back.name, back.size, back.is_dir, back.modified),
            (e.name, e.size, e.is_dir, e.modified)
        );
        let dir = entry_from_json(&json!({ "name": "d", "size": null, "is_dir": true })).unwrap();
        assert!(dir.is_dir && dir.size.is_none() && dir.modified.is_none());
        assert!(entry_from_json(&json!({ "size": 1, "is_dir": false })).is_err());
    }

    #[test]
    fn an_error_keeps_its_kind_on_the_way_back() {
        let back = |e: &Error| error_from_json(&error_json(e));
        let e = back(&Error::invalid_option("credentials", "no"));
        assert!(
            matches!(&e, Error::InvalidOption { name, reason } if name == "credentials" && reason == "no"),
            "{e}"
        );
        assert_eq!(e.exit_code(), 2);
        assert_eq!(
            back(&Error::Auth("x".into())).to_string(),
            "authentication failed: x"
        );
        assert!(matches!(back(&Error::Cancelled), Error::Cancelled));
        let e = back(&Error::Remote("gone".into()));
        assert_eq!(e.to_string(), "remote error: relay: gone");
        assert_eq!(e.exit_code(), 1);
    }

    /// Every kind of error comes back as that kind, with its exit code,
    /// and — where it has words of its own — with them.
    #[test]
    fn every_kind_survives_the_round_trip() {
        let every = [
            Error::InvalidUrl("no host".into()),
            Error::UnsupportedScheme("gopher".into()),
            Error::UnsupportedOperation {
                scheme: "http".into(),
                op: "rename",
            },
            Error::UnsupportedOperation {
                scheme: "mailto".into(),
                op: "hold files (it names a relay for `cp --via`; sftp:// or scp:// reach its files)",
            },
            Error::Config("bad".into()),
            Error::invalid_option("x", "y"),
            Error::Auth("no".into()),
            Error::Remote("gone".into()),
            Error::Signature("not trusted".into()),
            Error::ChecksumMismatch {
                algo: "blake3",
                expected: "aa".into(),
                actual: "bb".into(),
            },
            Error::Io(std::io::Error::other("disk full")),
            Error::not_found("/x/y"),
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "/x/z",
            )),
            Error::Cancelled,
            Error::transport("sftp", std::io::Error::other("reset")),
        ];
        for e in every {
            let back = error_from_json(&error_json(&e));
            assert_eq!(back.kind(), e.kind(), "{e}");
            assert_eq!(back.exit_code(), e.exit_code(), "{e}");
            assert_eq!(back.is_not_found(), e.is_not_found(), "{e}");
            if let (Error::Io(a), Error::Io(b)) = (&e, &back) {
                assert_eq!(a.kind(), b.kind(), "{e}");
            }
            match &e {
                Error::Io(_) | Error::Remote(_) => {
                    assert!(back.to_string().contains("relay: "), "{back}");
                }
                Error::Transport { .. } => {
                    assert_eq!(back.to_string(), format!("relay: {e}"));
                }
                _ => assert_eq!(back.to_string(), e.to_string()),
            }
        }
    }

    #[test]
    fn a_report_survives_the_round_trip() {
        let report = FanoutReport {
            source: "report.pdf".into(),
            bytes_read: 1234,
            elapsed: Duration::from_millis(50),
            targets: vec![
                TargetReport {
                    target: "sftp://u@h/in/".into(),
                    bytes: 1234,
                    elapsed: Duration::from_millis(40),
                    attempts: 1,
                    result: Ok(()),
                    sidecar: Some("sftp://u@h/in/report.pdf.b3".into()),
                    signature: None,
                    skipped: false,
                },
                TargetReport {
                    target: "ftp://x/".into(),
                    bytes: 0,
                    elapsed: Duration::ZERO,
                    attempts: 2,
                    result: Err(Error::Auth("wrong password".into())),
                    sidecar: None,
                    signature: None,
                    skipped: false,
                },
                TargetReport {
                    target: "/tmp/".into(),
                    bytes: 0,
                    elapsed: Duration::ZERO,
                    attempts: 0,
                    result: Err(Error::Cancelled),
                    sidecar: None,
                    signature: None,
                    skipped: false,
                },
            ],
            digests: vec![(HashAlgo::Blake3, "ab".repeat(32))],
            checked: None,
            source_removed: None,
        };
        let back = fanout_from_json(&fanout_json(&report)).unwrap();
        assert_eq!(back.source, "report.pdf");
        assert_eq!(back.bytes_read, 1234);
        assert_eq!(back.elapsed, Duration::from_millis(50));
        assert_eq!(back.targets.len(), 3);
        assert!(back.targets[0].result.is_ok());
        assert_eq!(
            back.targets[0].sidecar.as_deref(),
            Some("sftp://u@h/in/report.pdf.b3")
        );
        // An authentication failure is one here too: its exit code holds.
        let e = back.targets[1].result.as_ref().unwrap_err();
        assert!(matches!(e, Error::Auth(m) if m == "wrong password"), "{e}");
        assert_eq!(back.targets[1].attempts, 2);
        assert!(matches!(back.targets[2].result, Err(Error::Cancelled)));
        assert_eq!(back.digests, vec![(HashAlgo::Blake3, "ab".repeat(32))]);
        // The JSON of the round-tripped report is the JSON it came from.
        assert_eq!(fanout_json(&back), fanout_json(&report));
    }

    #[test]
    fn a_source_that_could_not_be_deleted_is_not_ok() {
        let mut report = FanoutReport {
            source: "report.pdf".into(),
            bytes_read: 0,
            elapsed: Duration::ZERO,
            targets: vec![TargetReport {
                target: "/tmp/".into(),
                bytes: 0,
                elapsed: Duration::ZERO,
                attempts: 0,
                result: Ok(()),
                sidecar: None,
                signature: None,
                skipped: true,
            }],
            digests: Vec::new(),
            checked: None,
            source_removed: Some(Ok(())),
        };
        assert_eq!(fanout_json(&report)["ok"], true);
        report.source_removed = Some(Err(Error::Remote("permission denied".into())));
        let v = fanout_json(&report);
        assert_eq!(v["ok"], false);
        assert_eq!(v["source_removed"], false);
    }
}
