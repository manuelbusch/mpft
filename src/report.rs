//! The outcome of a copy as JSON, for scripts and the API.
//!
//! The shape is what `mpt --json` prints (documented in the README under
//! "Machine-readable output"), so a script reads the same fields whether
//! it ran the command or asked the server.

use serde_json::{Value, json};

use crate::Error;
use crate::transfer::FanoutReport;

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
        "ok": report.all_ok() && report.checked.as_ref().is_none_or(|c| c.ok()),
        "targets": targets,
        "digests": digests,
        "check": check,
        "source_removed": report.source_removed.as_ref().map(|r| r.is_ok()),
        "remove_error": report.source_removed.as_ref().and_then(|r| r.as_ref().err().map(|e| e.to_string())),
    })
}

/// An error as `{"kind": …, "message": …}`; `kind` is [`Error::kind`].
pub fn error_json(err: &Error) -> Value {
    json!({ "kind": err.kind(), "message": err.to_string() })
}
