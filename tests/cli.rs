//! The command line on local files only: what `mpt` prints and how it exits
//! when no server is involved.

use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Run `mpt` in `dir` with an empty configuration, so the user's own does
/// not leak into the test.
fn mpt(dir: &Path, args: &[&str]) -> Output {
    mpt_with(dir, args, None)
}

/// [`mpt`] with `stdin` on standard input.
fn mpt_with(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let config = dir.join("empty-config.toml");
    if !config.exists() {
        std::fs::write(&config, "").unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_mpt"))
        .arg("--config")
        .arg(&config)
        .args(args)
        .current_dir(dir)
        .env_remove("MPT_CONFIG")
        .env_remove("MPT_PASSWORD")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("running mpt");
    if let Some(bytes) = stdin {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `--dry-run` on a plain copy prints the job and touches nothing, not
/// even with `--delete-source`; it once uploaded and deleted all the same.
#[test]
fn a_dry_run_of_a_plain_copy_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();

    let out = mpt(
        dir.path(),
        &["cp", "--dry-run", "--delete-source", "a.txt", "out/"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "[1/1] a.txt -> out/");
    assert!(dir.path().join("a.txt").exists(), "the source was deleted");
    assert!(
        !dir.path().join("out/a.txt").exists(),
        "the file was copied"
    );

    let out = mpt(dir.path(), &["--json", "cp", "--dry-run", "a.txt", "out/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(line["job"], 1);
    assert_eq!(line["src"], "a.txt");
    assert_eq!(line["dst"][0], "out/");
    assert!(
        !dir.path().join("out/a.txt").exists(),
        "the file was copied"
    );
}
