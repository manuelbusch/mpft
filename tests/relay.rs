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
            .arg("-v")
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
        let out = Command::new(env!("CARGO_BIN_EXE_mpt"))
            .env_remove("MPT_CONFIG")
            .arg("--config")
            .arg(self.path("client.toml"))
            .arg("--color")
            .arg("never")
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
    assert!(
        err.contains("mpt://a/"),
        "targets are shown as given:\n{err}"
    );
    assert!(err.contains("+ mpt://b/report.bin.b3"), "{err}");
    assert!(err.contains("2/2 targets ok"), "{err}");
    assert!(err.contains("blake3 "), "{err}");
    assert!(
        !err.contains(relay.dir.path().to_str().unwrap()),
        "no resolved paths:\n{err}"
    );
    assert!(relay.log().contains("relay login"), "{}", relay.log());

    // The same with --json: the report on stdout, targets as given.
    let (code, out, _) = relay.cp("client", &["--json", src.to_str().unwrap(), "mpt://a/"]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["bytes_read"], payload.len());
    assert_eq!(report["targets"][0]["target"], "mpt://a/");
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
    assert!(err.contains("1 of 1 targets failed"), "{err}");

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

#[test]
fn the_relay_reads_stdin_without_a_server() {
    let dir = tempfile::tempdir().unwrap();
    let target = format!("{}/", dir.path().display());
    let header = serde_json::json!({ "name": "piped.txt", "size": 6, "dst": [target] });
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
        stdin.write_all(b"hello\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last["report"]["ok"], true, "{text}");
    assert_eq!(
        std::fs::read(dir.path().join("piped.txt")).unwrap(),
        b"hello\n"
    );
}
