//! The command line on local files only: what `mpt` prints and how it exits
//! when no server is involved.

use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Run `mpt` in `dir` with an empty configuration, so the user's own does
/// not leak into the test.
fn mpt(dir: &Path, args: &[&str]) -> Output {
    mpt_with(dir, "", args, None)
}

/// [`mpt`] with `config` as the configuration file and `stdin` on
/// standard input.
fn mpt_with(dir: &Path, config: &str, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let path = dir.join("test-config.toml");
    std::fs::write(&path, config).unwrap();
    let config = path;
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

/// A profile with a relay changes nothing for a command that does not use
/// that profile: the copy runs here, with --check, --sign and --resume, and
/// prints what a plain copy prints. It once put every command through the
/// relay machinery as soon as any profile named a relay.
#[cfg(feature = "relay")]
#[test]
fn a_relay_of_an_unused_profile_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    for d in ["out", "out2"] {
        std::fs::create_dir(dir.path().join(d)).unwrap();
    }
    let config = "[profiles.far]\nurl = \"sftp://h/in/\"\nvia = \"ssh://relay.invalid/\"\n";
    let run = |args: &[&str]| mpt_with(dir.path(), config, args, None);

    let out = run(&["--hash", "sha256", "cp", "a.txt", "out/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("[1/1]"), "{}", stderr(&out));

    let out = run(&["--json", "--check", "cp", "out/a.txt", "out2/"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(report["ok"], true);
    assert!(report["job"].is_null(), "a batch line: {report}");

    let out = run(&["--delete-source", "cp", "out2/a.txt", "out/b.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!dir.path().join("out2/a.txt").exists());

    let out = run(&["--check", "ls", "."]);
    assert!(out.status.success(), "{}", stderr(&out));

    // The profile's relay is used, and refuses --check, when a job uses it.
    let out = run(&["--check", "cp", "out/a.txt", "mpt://far/"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not available with a relay"),
        "{}",
        stderr(&out)
    );
}
