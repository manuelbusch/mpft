//! `mpt serve` end to end: the binary is started with a temporary
//! configuration and talked to over HTTP and WebSocket. Only local files
//! are moved, so nothing here needs the test servers.

#![cfg(all(feature = "server", feature = "http"))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

const TOKEN: &str = "t0k3n-for-tests";

/// A running server, stopped when dropped.
struct Server {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
    log: PathBuf,
}

impl Server {
    /// Start the binary on a free port with profiles `src` and `dst` that
    /// point at directories under `dir`, plus whatever `extra` flags say.
    fn start(extra: &[&str]) -> Server {
        Server::start_with(tempfile::tempdir().unwrap(), extra)
    }

    fn start_with(dir: tempfile::TempDir, extra: &[&str]) -> Server {
        let d = dir.path();
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::create_dir_all(d.join("dst")).unwrap();
        let config = d.join("mpt.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ntoken = {{ env = \"MPT_TEST_TOKEN\" }}\n\
                 [profiles.src]\nurl = \"{}/src/\"\n\
                 [profiles.dst]\nurl = \"{}/dst/\"\n",
                d.display(),
                d.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let port_file = d.join("port");
        let log = d.join("server.log");
        let child = Command::new(env!("CARGO_BIN_EXE_mpt"))
            .env("MPT_TEST_TOKEN", TOKEN)
            .env_remove("MPT_CONFIG")
            .arg("--config")
            .arg(&config)
            .arg("-v")
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--port-file")
            .arg(&port_file)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
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
                "server did not start: {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        Server {
            child,
            port,
            dir,
            log,
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn url(&self, route: &str) -> String {
        format!("http://127.0.0.1:{}{route}", self.port)
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    async fn post(&self, route: &str, content_type: &str, body: String) -> (u16, Value) {
        let resp = self
            .client()
            .post(self.url(route))
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get(&self, route: &str) -> (u16, Value) {
        let resp = self
            .client()
            .get(self.url(route))
            .header("authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Poll the job until it is over.
    async fn wait(&self, url: &str) -> Value {
        let started = Instant::now();
        loop {
            let (status, job) = self.get(url).await;
            assert_eq!(status, 200, "{job}");
            if matches!(job["state"].as_str(), Some("done" | "failed" | "cancelled")) {
                return job;
            }
            assert!(started.elapsed() < Duration::from_secs(30), "{job}");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Ask the server to stop and wait for it; the exit status comes back.
    #[cfg(unix)]
    fn interrupt(&mut self) -> std::process::ExitStatus {
        Command::new("kill")
            .arg("-INT")
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        self.child.wait().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

#[tokio::test]
async fn a_job_is_run_and_can_be_polled() {
    let server = Server::start(&[]);
    std::fs::write(server.path().join("src/a.bin"), payload(100_000)).unwrap();
    let (status, body) = server.get("/v1/healthz").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["accepting"], true);

    let (status, body) = server
        .post(
            "/v1/jobs",
            "application/json",
            r#"{"src": "mpt://src/a.bin", "dst": "mpt://dst/", "options": {"hash": "sha256"}}"#
                .into(),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let url = body["url"].as_str().unwrap().to_string();
    let job = server.wait(&url).await;
    assert_eq!(job["state"], "done", "{job}\n{}", server.log());
    assert_eq!(job["progress"]["bytes"], 100_000);
    assert_eq!(job["transfers"][0]["report"]["ok"], true);
    assert!(
        job["transfers"][0]["report"]["digests"]["sha256"].is_string(),
        "{job}"
    );
    assert_eq!(
        std::fs::read(server.path().join("dst/a.bin")).unwrap(),
        payload(100_000)
    );
    assert!(server.path().join("dst/a.bin.sha256").exists());

    // The transfer is shown by the reference the client sent, not by the
    // path behind the profile.
    let (status, t) = server.get(&format!("{url}/transfers/0")).await;
    assert_eq!(status, 200);
    assert_eq!(t["state"], "done");
    assert_eq!(t["src"], "mpt://src/a.bin", "{t}");
    assert_eq!(t["dst"][0], "mpt://dst/", "{t}");
    assert_eq!(t["report"]["source"], "mpt://src/a.bin", "{t}");
    assert_eq!(t["report"]["targets"][0]["target"], "mpt://dst/", "{t}");
    assert_eq!(
        t["report"]["targets"][0]["sidecar"], "mpt://dst/a.bin.sha256",
        "{t}"
    );
}

#[tokio::test]
async fn a_batch_as_ndjson_reports_every_transfer() {
    let server = Server::start(&[]);
    std::fs::write(server.path().join("src/one"), b"1").unwrap();
    std::fs::write(server.path().join("src/two"), b"22").unwrap();
    let lines = "{\"src\": \"mpt://src/one\", \"dst\": \"mpt://dst/\"}\n\
                 {\"src\": \"mpt://src/two\", \"dst\": [\"mpt://dst/\"]}\n\
                 {\"src\": \"mpt://src/missing\", \"dst\": \"mpt://dst/\"}\n";
    let (status, body) = server
        .post(
            "/v1/batches?parallel=2",
            "application/x-ndjson",
            lines.into(),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["transfers"], 3);
    let url = body["url"].as_str().unwrap().to_string();
    let job = server.wait(&url).await;
    assert_eq!(job["state"], "failed", "{job}");
    assert_eq!(job["kind"], "batch");
    assert_eq!(job["progress"]["transfers"]["done"], 2);
    assert_eq!(job["progress"]["transfers"]["failed"], 1);
    let transfers = job["transfers"].as_array().unwrap();
    assert_eq!(transfers[2]["state"], "failed");
    assert_eq!(transfers[2]["error"]["kind"], "io");
    assert_eq!(std::fs::read(server.path().join("dst/two")).unwrap(), b"22");

    let (status, list) = server.get("/v1/jobs?state=failed").await;
    assert_eq!(status, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["id"], job["id"]);
}

#[tokio::test]
async fn the_websocket_sends_a_snapshot_first_and_done_last() {
    let server = Server::start(&[]);
    std::fs::write(server.path().join("src/big.bin"), payload(4_000_000)).unwrap();
    let (status, body) = server
        .post(
            "/v1/jobs",
            "application/json",
            r#"{"src": "mpt://src/big.bin", "dst": "mpt://dst/"}"#.into(),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    let id = body["id"].as_str().unwrap().to_string();

    let mut request = format!("ws://127.0.0.1:{}/v1/jobs/{id}/events", server.port)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let mut events: Vec<Value> = Vec::new();
    let mut closed = false;
    while let Some(msg) = tokio::time::timeout(Duration::from_secs(30), ws.next())
        .await
        .expect("the server stopped talking")
    {
        match msg.unwrap() {
            Message::Text(text) => events.push(serde_json::from_str(&text).unwrap()),
            Message::Close(_) => {
                closed = true;
                break;
            }
            _ => {}
        }
    }
    assert!(closed, "no close frame: {events:?}");
    assert_eq!(events[0]["event"], "snapshot", "{events:?}");
    assert_eq!(events[0]["job"]["id"], id.as_str());
    let last = events.last().unwrap();
    assert_eq!(last["event"], "done", "{events:?}");
    assert_eq!(last["state"], "done", "{}", server.log());
    assert!(
        events
            .iter()
            .all(|e| e["event"] == "snapshot" || e["id"] == id.as_str()),
        "{events:?}"
    );
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"transfer_done"), "{kinds:?}");
    let _ = ws.send(Message::Close(None)).await;

    // Without the token, no upgrade.
    let request = format!("ws://127.0.0.1:{}/v1/jobs/{id}/events", server.port)
        .into_client_request()
        .unwrap();
    assert!(tokio_tungstenite::connect_async(request).await.is_err());
}

#[tokio::test]
async fn raw_urls_need_allow_any_url() {
    let server = Server::start(&[]);
    let src = server.path().join("src/x");
    std::fs::write(&src, b"x").unwrap();
    let body = format!(
        r#"{{"src": "{}", "dst": "{}/dst/"}}"#,
        src.display(),
        server.path().display()
    );
    let (status, resp) = server
        .post("/v1/jobs", "application/json", body.clone())
        .await;
    assert_eq!(status, 400, "{resp}");
    assert_eq!(resp["error"]["kind"], "invalid_url");
    let (status, resp) = server
        .post(
            "/v1/jobs",
            "application/json",
            r#"{"src": "mpt://nowhere/x", "dst": "mpt://dst/"}"#.into(),
        )
        .await;
    assert_eq!(status, 400, "{resp}");
    drop(server);

    let server = Server::start(&["--allow-any-url"]);
    let src = server.path().join("src/x");
    std::fs::write(&src, b"x").unwrap();
    let body = format!(
        r#"{{"src": "{}", "dst": "{}/dst/"}}"#,
        src.display(),
        server.path().display()
    );
    let (status, resp) = server.post("/v1/jobs", "application/json", body).await;
    assert_eq!(status, 202, "{resp}");
    let job = server.wait(resp["url"].as_str().unwrap()).await;
    assert_eq!(job["state"], "done", "{job}");
}

#[tokio::test]
async fn a_job_left_in_the_journal_runs_again() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/j.bin"), payload(10)).unwrap();
    let journal = dir.path().join("jobs.jsonl");
    let id = "0123456789abcdef0123456789abcdef";
    std::fs::write(
        &journal,
        format!(
            "{{\"t\":\"submitted\",\"id\":\"{id}\",\"at\":\"2026-01-01T00:00:00Z\",\"attempt\":1,\
             \"submission\":{{\"kind\":\"single\",\"specs\":[{{\"src\":\"mpt://src/j.bin\",\"dsts\":[\"mpt://dst/\"]}}]}}}}\n"
        ),
    )
    .unwrap();
    let journal_arg = journal.display().to_string();
    let server = Server::start_with(dir, &["--journal", &journal_arg]);
    let job = server.wait(&format!("/v1/jobs/{id}")).await;
    assert_eq!(job["state"], "done", "{job}\n{}", server.log());
    assert_eq!(job["attempt"], 2);
    assert_eq!(
        std::fs::read(server.path().join("dst/j.bin")).unwrap(),
        payload(10)
    );
    // The journal now closes the job, and a new one is written to it.
    let (status, body) = server
        .post(
            "/v1/jobs",
            "application/json",
            r#"{"src": "mpt://src/j.bin", "dst": "mpt://dst/again/"}"#.into(),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    server.wait(body["url"].as_str().unwrap()).await;
    let text = std::fs::read_to_string(&journal).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 4, "{text}");
    assert_eq!(lines[0]["t"], "submitted");
    assert_eq!(lines[0]["attempt"], 2);
    assert_eq!(lines[1]["t"], "done");
    assert_eq!(lines[1]["id"], id);
    assert_eq!(lines[3]["t"], "done");
}

#[test]
fn no_token_means_loopback_only() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mpt"))
        .env_remove("MPT_CONFIG")
        .env("XDG_CONFIG_HOME", dir.path())
        .current_dir(dir.path())
        .args(["serve", "--bind", "0.0.0.0:0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("without a token"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn an_interrupt_stops_the_server_cleanly() {
    let mut server = Server::start(&[]);
    std::fs::write(server.path().join("src/s"), b"s").unwrap();
    let (status, body) = server
        .post(
            "/v1/jobs",
            "application/json",
            r#"{"src": "mpt://src/s", "dst": "mpt://dst/"}"#.into(),
        )
        .await;
    assert_eq!(status, 202, "{body}");
    server.wait(body["url"].as_str().unwrap()).await;
    let exit = tokio::task::spawn_blocking(move || {
        let exit = server.interrupt();
        (exit, server.log())
    })
    .await
    .unwrap();
    assert!(exit.0.success(), "{:?}\n{}", exit.0, exit.1);
    assert!(exit.1.contains("stopped"), "{}", exit.1);
}
