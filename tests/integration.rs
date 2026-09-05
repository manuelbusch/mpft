//! End-to-end tests against real servers. Each test is skipped unless its
//! `MPT_IT_<PROTO>` variable holds a *directory* URL to use.
//! See `tests/local/start_servers.sh` for a Docker-free local setup.

use std::time::Duration;

use mpt::{Location, SendMeta};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn random_payload(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ len as u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn dir_url(base: &str, name: &str) -> String {
    let (path, query) = base
        .split_once('?')
        .map(|(p, q)| (p, Some(q)))
        .unwrap_or((base, None));
    let mut url = format!("{}{}", path.trim_end_matches('/'), name);
    if let Some(q) = query {
        url.push('?');
        url.push_str(q);
    }
    url
}

/// Upload random bytes to `<base>/<name>`, download them again, compare, and
/// check that `ls <base>` shows the file.
async fn roundtrip(base: &str, name: &str, len: usize, check_list: bool) {
    mpt::init_crypto();
    let payload = random_payload(len);
    let file_url = dir_url(base, &format!("/{name}"));

    let dst = mpt::open(base).unwrap();
    let sender = dst.sender().unwrap();
    let meta = SendMeta::from_filename(name).with_size(len as u64);
    sender
        .send(Box::pin(std::io::Cursor::new(payload.clone())), &meta)
        .await
        .expect("upload");

    let src = mpt::open(&file_url).unwrap();
    let mut stream = src.receiver().unwrap().receive().await.expect("download");
    let mut got = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
        .await
        .expect("read");
    assert_eq!(got.len(), payload.len(), "length mismatch for {file_url}");
    assert!(got == payload, "content mismatch for {file_url}");

    if check_list {
        let entries = dst.receiver().unwrap().list().await.expect("list");
        let e = entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("{name} not in listing: {entries:?}"));
        assert!(!e.is_dir);
        if let Some(s) = e.size {
            assert_eq!(s, len as u64);
        }
    }

    // Also exercise the generic copy pipeline (file → remote → file).
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("copy.bin");
    let l = mpt::open(local.to_str().unwrap()).unwrap();
    let report = mpt::copy(src.as_ref(), l.as_ref())
        .await
        .expect("copy remote → local");
    assert_eq!(report.bytes, len as u64);
    assert_eq!(std::fs::read(&local).unwrap(), payload);
}

macro_rules! roundtrip_test {
    ($name:ident, $var:literal, $len:expr, $list:expr) => {
        #[tokio::test]
        async fn $name() {
            let Some(base) = env($var) else {
                eprintln!("skipping {}: {} not set", stringify!($name), $var);
                return;
            };
            let file = format!("{}_{}.bin", stringify!($name), std::process::id());
            tokio::time::timeout(
                Duration::from_secs(120),
                roundtrip(&base, &file, $len, $list),
            )
            .await
            .expect("timeout");
        }
    };
}

roundtrip_test!(sftp_roundtrip, "MPT_IT_SFTP", 3 * 1024 * 1024 + 17, true);
roundtrip_test!(scp_roundtrip, "MPT_IT_SCP", 2 * 1024 * 1024 + 5, false);
roundtrip_test!(ftp_roundtrip, "MPT_IT_FTP", 1024 * 1024 + 3, true);
roundtrip_test!(ftps_roundtrip, "MPT_IT_FTPS", 1024 * 1024 + 9, true);
roundtrip_test!(http_roundtrip, "MPT_IT_HTTP", 512 * 1024 + 1, false);
roundtrip_test!(webdav_roundtrip, "MPT_IT_WEBDAV", 700 * 1024 + 7, true);
roundtrip_test!(s3_roundtrip, "MPT_IT_S3", 6 * 1024 * 1024 + 11, true);

/// Sends an attachment via `mailto:` and, if `MPT_IT_MAILDIR` points at the
/// receiving maildir, verifies that a new message containing the file arrived.
#[tokio::test]
async fn mailto_send() {
    let Some(target) = env("MPT_IT_MAILTO") else {
        eprintln!("skipping mailto_send: MPT_IT_MAILTO not set");
        return;
    };
    mpt::init_crypto();
    let maildir = env("MPT_IT_MAILDIR");
    let count_before = maildir.as_deref().map(count_mails).unwrap_or(0);

    let name = format!("mail_{}.txt", std::process::id());
    let payload = b"hello from mpt integration test\n".to_vec();
    let ep = mpt::open(&target).unwrap();
    assert!(
        ep.as_receiver().is_none(),
        "mail endpoints must not receive"
    );
    let meta = SendMeta::from_filename(&name).with_size(payload.len() as u64);
    ep.sender()
        .unwrap()
        .send(Box::pin(std::io::Cursor::new(payload)), &meta)
        .await
        .expect("send mail");

    if let Some(dir) = maildir {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            count_mails(&dir),
            count_before + 1,
            "expected one new message in {dir}"
        );
        let found = walk(&dir).into_iter().any(|p| {
            std::fs::read_to_string(&p)
                .map(|s| s.contains(&name))
                .unwrap_or(false)
        });
        assert!(found, "no message mentions attachment {name}");
    }
}

fn walk(dir: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p)
                } else {
                    out.push(p)
                }
            }
        }
    }
    out
}

fn count_mails(dir: &str) -> usize {
    walk(dir).len()
}

#[test]
fn location_direction_rules() {
    let m = Location::parse("mailto:a@b.c").unwrap();
    assert!(!m.scheme().can_receive() && m.scheme().can_send());
    for u in [
        "sftp://u@h/p",
        "scp://u@h/p",
        "ftp://h/p",
        "ftps://h/p",
        "https://h/p",
        "webdav://h/p",
        "s3://b/k",
        "/tmp/x",
    ] {
        let l = Location::parse(u).unwrap();
        assert!(l.scheme().can_receive() && l.scheme().can_send(), "{u}");
    }
}
