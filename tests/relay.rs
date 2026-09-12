//! `mpt relay --listen` and `cp --via` end to end: the binary is started
//! as a relay with its own SSH server, and the binary is the client that
//! sends a file through it. Only local directories are the targets, so
//! nothing here needs the test servers.

#![cfg(feature = "relay")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running relay, stopped when dropped.
struct Relay {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Relay {
    /// Start the binary on a free port with a fresh host key, one
    /// authorized client key (`keys/client`) and one that is not
    /// (`keys/stranger`), plus target directories `a` and `b`.
    fn start(extra: &[&str]) -> Relay {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for sub in ["a", "b", "keys"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
        }
        keygen(&d.join("keys").join("client"));
        keygen(&d.join("keys").join("stranger"));
        std::fs::copy(d.join("keys").join("client.pub"), d.join("authorized_keys")).unwrap();
        std::fs::write(
            d.join("client.toml"),
            format!(
                "[profiles.a]\nurl = \"{}/a/\"\n[profiles.b]\nurl = \"{}/b/\"\n",
                d.display(),
                d.display()
            ),
        )
        .unwrap();
        let port_file = d.join("port");
        let child = Command::new(env!("CARGO_BIN_EXE_mpt"))
            .env_remove("MPT_CONFIG")
            .arg("-vv")
            .arg("relay")
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--host-key")
            .arg(d.join("keys").join("host"))
            .arg("--authorized-keys")
            .arg(d.join("authorized_keys"))
            .arg("--port-file")
            .arg(&port_file)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(d.join("relay.log")).unwrap())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let port = loop {
            if let Ok(text) = std::fs::read_to_string(&port_file)
                && let Ok(p) = text.trim().parse::<u16>()
            {
                break p;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the relay wrote no port file"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        Relay { child, port, dir }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// `ssh://` to this relay with `key` from the `keys` directory.
    fn via(&self, key: &str) -> String {
        format!(
            "ssh://relay@127.0.0.1:{}/?key={}&known_hosts=off",
            self.port,
            self.path("keys").join(key).display()
        )
    }

    /// Run `mpt --config client.toml cp --via … <args>` and return the exit
    /// code, stdout and stderr.
    fn cp(&self, key: &str, args: &[&str]) -> (i32, String, String) {
        self.cp_with(key, &[], args)
    }

    /// The same with `global` flags in front of `cp`.
    fn cp_with(&self, key: &str, global: &[&str], args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_mpt"))
            .env_remove("MPT_CONFIG")
            .arg("--config")
            .arg(self.path("client.toml"))
            .arg("--color")
            .arg("never")
            .args(global)
            .args(["cp", "--via", &self.via(key)])
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("relay.log")).unwrap_or_default()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn keygen(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(path)
        .stdout(Stdio::null())
        .status()
        .expect("ssh-keygen is available");
    assert!(status.success(), "ssh-keygen failed");
}

#[test]
fn a_file_goes_through_the_relay_to_every_target() {
    let relay = Relay::start(&[]);
    let payload: Vec<u8> = (0..3_000_017u32).map(|i| (i % 241) as u8).collect();
    let src = relay.path("report.bin");
    std::fs::write(&src, &payload).unwrap();
    let (code, _, err) = relay.cp(
        "client",
        &[
            "--hash",
            "blake3",
            src.to_str().unwrap(),
            "mpt://a/",
            "mpt://b/",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(relay.path("a/report.bin")).unwrap(), payload);
    assert_eq!(std::fs::read(relay.path("b/report.bin")).unwrap(), payload);
    assert!(relay.path("a/report.bin.b3").exists());
    // Reported the way cp reports a copy of its own: the resolved targets,
    // the digests, the job count.
    assert!(
        err.contains(&format!("+ {}", relay.path("b/report.bin.b3").display())),
        "{err}"
    );
    assert!(err.contains("2/2 targets ok"), "{err}");
    assert!(err.contains("1/1 jobs ok"), "{err}");
    assert!(err.contains("blake3 "), "{err}");
    assert!(relay.log().contains("relay login"), "{}", relay.log());

    // The same with --json: one report line per job, as a batch prints it.
    let (code, out, _) = relay.cp("client", &["--json", src.to_str().unwrap(), "mpt://a/"]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["job"], 1);
    assert_eq!(report["bytes_read"], payload.len());
    assert_eq!(
        report["targets"][0]["target"],
        format!("{}/", relay.path("a").display())
    );
}

#[test]
fn a_batch_goes_through_the_relay_job_by_job() {
    let relay = Relay::start(&["--parallel", "2"]);
    let mut files = Vec::new();
    for i in 0..5u8 {
        let path = relay.path(&format!("in/f{i}.bin"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let payload: Vec<u8> = (0..200_000u32 + u32::from(i))
            .map(|n| (n % 199) as u8 ^ i)
            .collect();
        std::fs::write(&path, &payload).unwrap();
        files.push((path, payload));
    }
    // A job list: two files to both targets, the rest to one, and a
    // pattern that the client expands before anything is sent.
    let list = relay.path("jobs.txt");
    std::fs::write(
        &list,
        format!(
            "{} mpt://a/ mpt://b/\n{} mpt://a/ mpt://b/\n{}/in/f[2-4].bin mpt://b/\n",
            files[0].0.display(),
            files[1].0.display(),
            relay.dir.path().display()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mpt"))
        .env_remove("MPT_CONFIG")
        .arg("--config")
        .arg(relay.path("client.toml"))
        .args([
            "--color",
            "never",
            "--json",
            "batch",
            "--via",
            &relay.via("client"),
            "--parallel",
            "3",
        ])
        .arg(&list)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    for (i, (path, payload)) in files.iter().enumerate() {
        let name = path.file_name().unwrap();
        assert_eq!(
            &std::fs::read(relay.path("b").join(name)).unwrap(),
            payload,
            "f{i} in b"
        );
        assert_eq!(relay.path("a").join(name).exists(), i < 2, "f{i} in a");
    }
    assert!(err.contains("5/5 jobs ok"), "{err}");
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 5);
    assert!(lines.iter().all(|l| l["ok"] == true), "{lines:?}");
    let mut jobs: Vec<u64> = lines.iter().map(|l| l["job"].as_u64().unwrap()).collect();
    jobs.sort_unstable();
    assert_eq!(jobs, vec![1, 2, 3, 4, 5]);
    // Five sessions, one per job.
    assert_eq!(
        relay.log().matches("relay login").count(),
        5,
        "{}",
        relay.log()
    );

    // `cp -t` is a batch as well, and --fail-fast stops it at the first
    // failure: a target that cannot be written.
    std::fs::write(relay.path("b/wall"), b"").unwrap();
    let (code, _, err) = relay.cp(
        "client",
        &[
            "--fail-fast",
            "--parallel",
            "1",
            "-t",
            "mpt://b/wall/",
            files[0].0.to_str().unwrap(),
            files[1].0.to_str().unwrap(),
        ],
    );
    // The second job never started: the batch ends as interrupted, the
    // way a local batch does.
    assert_eq!(code, 130, "{err}");
    assert!(err.contains("stopped after the first failure"), "{err}");
    assert!(!relay.path("b/wall/f1.bin").exists());
}

#[test]
fn a_stranger_a_bad_target_and_a_refused_flag() {
    let relay = Relay::start(&[]);
    let src = relay.path("x.txt");
    std::fs::write(&src, b"hello").unwrap();

    let (code, _, err) = relay.cp("stranger", &[src.to_str().unwrap(), "mpt://a/"]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("authentication failed"), "{err}");
    assert!(!relay.path("a/x.txt").exists());

    // A target the relay cannot write: the failure comes back as cp's own.
    std::fs::write(relay.path("b/blocker"), b"").unwrap();
    let (code, _, err) = relay.cp("client", &[src.to_str().unwrap(), "mpt://b/blocker/"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("FAILED"), "{err}");
    assert!(err.contains("relay: I/O error"), "{err}");
    assert!(err.contains("1 of 1 jobs failed"), "{err}");

    // The relay from the configuration, and --no-via against it.
    std::fs::write(
        relay.path("via.toml"),
        format!(
            "{}[defaults]\nvia = \"{}\"\n",
            std::fs::read_to_string(relay.path("client.toml")).unwrap(),
            relay.via("client")
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_mpt"))
            .env_remove("MPT_CONFIG")
            .arg("--config")
            .arg(relay.path("via.toml"))
            .args(["--color", "never", "cp"])
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, err) = run(&[src.to_str().unwrap(), "mpt://a/"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("1/1 jobs ok"),
        "went through the relay:\n{err}"
    );
    let (code, err) = run(&["--no-via", src.to_str().unwrap(), "mpt://b/"]);
    assert_eq!(code, 0, "{err}");
    assert!(!err.contains("jobs ok"), "copied from here:\n{err}");
    // The blocked target above and the configured relay: two logins,
    // none for --no-via.
    assert_eq!(
        relay.log().matches("relay login").count(),
        2,
        "{}",
        relay.log()
    );

    let (code, _, err) = relay.cp("client", &["--check", src.to_str().unwrap(), "mpt://a/"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--check is not available with --via"), "{err}");

    // A key file of a target stays on this side; the relay cannot use it.
    let (code, _, err) = relay.cp(
        "client",
        &[
            src.to_str().unwrap(),
            "sftp://someone@nowhere/in/?key=/etc/hostname",
        ],
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("?key="), "{err}");
}

/// Both sides have to agree on where the passwords come from; a mismatch
/// is refused with a message that names both settings.
#[test]
fn the_credential_modes_have_to_match() {
    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("x.txt");
    std::fs::write(&src, b"hello").unwrap();

    let header_relay = Relay::start(&[]);
    let (code, _, err) = header_relay.cp(
        "client",
        &[
            "--via-credentials",
            "on-demand",
            src.to_str().unwrap(),
            "mpt://a/",
        ],
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("credentials = \"header\""), "{err}");
    assert!(err.contains("--credentials on-demand"), "{err}");
    assert!(!header_relay.path("a/x.txt").exists());

    let demand_relay = Relay::start(&["--credentials", "on-demand"]);
    let (code, _, err) = demand_relay.cp("client", &[src.to_str().unwrap(), "mpt://a/"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--via-credentials on-demand"), "{err}");
    assert!(!demand_relay.path("a/x.txt").exists());

    // Matching, with local targets that never ask: the copy goes through.
    let (code, _, err) = demand_relay.cp(
        "client",
        &[
            "--via-credentials",
            "on-demand",
            src.to_str().unwrap(),
            "mpt://a/",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::read(demand_relay.path("a/x.txt")).unwrap(),
        b"hello"
    );

    // A relay set to `any` takes both.
    let any_relay = Relay::start(&["--credentials", "any"]);
    for mode in ["header", "on-demand"] {
        let (code, _, err) = any_relay.cp(
            "client",
            &["--via-credentials", mode, src.to_str().unwrap(), "mpt://a/"],
        );
        assert_eq!(code, 0, "{mode}: {err}");
    }
}

/// With on-demand credentials the relay never sees a password: the client
/// sends the target without it, the relay asks at every login (FTP logs
/// in more than once for one file) and the answer is not kept.
#[test]
fn passwords_are_asked_for_on_demand() {
    let Some(ftp) = std::env::var("MPT_IT_FTP").ok().filter(|s| !s.is_empty()) else {
        eprintln!("skipping: MPT_IT_FTP not set");
        return;
    };
    let (base, query) = ftp.split_once('?').unwrap_or((&ftp, ""));
    let name = format!("on_demand_{}.bin", std::process::id());
    let target = format!("{}/{name}?{query}", base.trim_end_matches('/'));
    let password = base
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .map(|(_, pw)| pw.to_string())
        .expect("MPT_IT_FTP carries a password");

    let relay = Relay::start(&["--credentials", "on-demand"]);
    let payload: Vec<u8> = (0..500_000u32).map(|i| (i % 233) as u8).collect();
    let src = relay.path("report.bin");
    std::fs::write(&src, &payload).unwrap();
    let (code, _, err) = relay.cp_with(
        "client",
        &["-vv"],
        &[
            "--via-credentials",
            "on-demand",
            src.to_str().unwrap(),
            &target,
        ],
    );
    assert_eq!(code, 0, "{err}");
    let asked = err.matches("password asked for by the relay").count();
    assert!(asked >= 2, "asked {asked} times:\n{err}");
    let log = relay.log();
    assert!(
        !log.contains(&password),
        "the relay logged the password:\n{log}"
    );
    assert!(
        log.matches("asking the client for the password").count() >= 2,
        "{log}"
    );

    // What arrived is the file, read back without the relay.
    let back = relay.path("back.bin");
    let out = Command::new(env!("CARGO_BIN_EXE_mpt"))
        .env_remove("MPT_CONFIG")
        .args(["--color", "never", "cp", &target])
        .arg(&back)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&back).unwrap(), payload);
}

#[test]
fn the_relay_reads_stdin_without_a_server() {
    let dir = tempfile::tempdir().unwrap();
    let target = format!("{}/", dir.path().display());
    let run = |header: serde_json::Value, body: &[u8]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mpt"))
            .env_remove("MPT_CONFIG")
            .arg("relay")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin, "{header}").unwrap();
            stdin.write_all(body).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["report"]["ok"], true, "{text}");
    };
    // Version 1: the bytes as they are.
    run(
        serde_json::json!({ "v": 1, "name": "piped.txt", "size": 6, "dst": [&target] }),
        b"hello\n",
    );
    assert_eq!(
        std::fs::read(dir.path().join("piped.txt")).unwrap(),
        b"hello\n"
    );
    // Version 2: in frames, a control frame among them.
    let mut body = Vec::new();
    for (kind, payload) in [
        (1u8, &b"hel"[..]),
        (2, br#"{"password": {"id": 1}}"#),
        (1, b"lo\n"),
    ] {
        body.push(kind);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(payload);
    }
    run(
        serde_json::json!({ "name": "framed.txt", "size": 6, "dst": [&target] }),
        &body,
    );
    assert_eq!(
        std::fs::read(dir.path().join("framed.txt")).unwrap(),
        b"hello\n"
    );
}
