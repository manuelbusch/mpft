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

/// Ctrl-C stops a copy whose source never ends and never gets to the next
/// read (a pipe nobody writes to): the process exits with 130 instead of
/// waiting for that read, where no further Ctrl-C reached it either.
#[cfg(unix)]
#[test]
fn an_interrupt_ends_a_copy_stuck_in_a_read() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();
    let fifo = dir.path().join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // Opening the pipe for writing returns once mpt opened it for reading,
    // and that is after it listens for signals.
    let mut writer = Command::new("sh")
        .arg("-c")
        .arg("exec 3>fifo; touch opened; sleep 60")
        .current_dir(dir.path())
        .spawn()
        .unwrap();
    let config = dir.path().join("test-config.toml");
    std::fs::write(&config, "").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_mpt"))
        .arg("--config")
        .arg(&config)
        .args(["cp", "fifo", "out/"])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !dir.path().join("opened").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "mpt never opened the pipe"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let kill = |sig: &str| {
        Command::new("kill")
            .args([sig, &child.id().to_string()])
            .status()
            .unwrap()
    };
    kill("-INT");
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = writer.kill();
            panic!("mpt did not stop after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = writer.kill();
    let _ = writer.wait();
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(err.contains("interrupted"), "{err}");
}

/// `--password-stdin` is refused with a command that reads standard input
/// itself; `mpt relay` once swallowed the upload as the password, and
/// `credentials set` stored an empty secret.
#[test]
fn the_password_cannot_share_stdin_with_a_command_that_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut refused = vec![vec!["--password-stdin", "batch", "-"]];
    if cfg!(feature = "relay") {
        refused.push(vec!["--password-stdin", "relay"]);
    }
    if cfg!(feature = "keyring") {
        refused.push(vec!["--password-stdin", "credentials", "set", "svc/user"]);
    }
    for args in refused {
        let out = mpt_with(dir.path(), "", &args, Some(b"pw\nmore\n"));
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("cannot both come from stdin"),
            "{args:?}: {}",
            stderr(&out)
        );
    }

    // Anywhere else only the first line is read.
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();
    let out = mpt_with(
        dir.path(),
        "",
        &["--password-stdin", "cp", "a.txt", "out/"],
        Some(b"pw\nmore\n"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

/// A dry run of `batch - --follow` numbers the jobs of one line one by one
/// and does not end by saying that none arrived; it once gave all of a
/// line's jobs the number of the last.
#[test]
fn a_following_dry_run_numbers_every_job() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a.csv", "b.csv", "c.txt"] {
        std::fs::write(dir.path().join(name), name).unwrap();
    }
    let out = mpt_with(
        dir.path(),
        "",
        &["batch", "-", "--follow", "--dry-run"],
        Some(b"*.csv out/\nc.txt out/\n"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let lines: Vec<String> = stdout(&out).lines().map(String::from).collect();
    assert_eq!(
        lines,
        [
            "[1] ./a.csv -> out/",
            "[2] ./b.csv -> out/",
            "[3] c.txt -> out/"
        ]
    );
    assert!(!stderr(&out).contains("nothing to do"), "{}", stderr(&out));
    assert!(!dir.path().join("out").exists(), "the dry run copied");

    // A line that is not a job still fails the run.
    let out = mpt_with(
        dir.path(),
        "",
        &["batch", "-", "--follow", "--dry-run"],
        Some(b"c.txt out/\n\"unbalanced\n"),
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("1 line rejected"), "{}", stderr(&out));
}

/// `config check` lists the profiles and masks the SMTP password; it once
/// printed `smtp://u:pw@…` as written and counted the profiles without
/// printing them.
#[test]
fn config_check_lists_profiles_and_hides_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let config = "[mail]\nsmtp = \"smtp://u:s3cret@mail.example.com:587\"\n\
                  password = \"hunter2\"\n\
                  [profiles.backup]\nurl = \"/tmp/backup/\"\n";
    let out = mpt_with(dir.path(), config, &["config", "check"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("[profiles]"), "{text}");
    assert!(text.contains("backup"), "{text}");
    assert!(text.contains("smtp://u:***@mail.example.com:587"), "{text}");
    assert!(
        !text.contains("s3cret") && !text.contains("hunter2"),
        "{text}"
    );
    assert!(text.contains("[mail] password"), "{text}");

    // Profiles alone are something set, not "nothing set".
    let out = mpt_with(
        dir.path(),
        "[profiles.backup]\nurl = \"/tmp/backup/\"\n",
        &["config", "check"],
        None,
    );
    assert!(stdout(&out).contains("[profiles]"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("nothing set"), "{}", stdout(&out));
}
