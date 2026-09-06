//! End-to-end tests against real servers. Each test is skipped unless its
//! `MPT_IT_<PROTO>` variable holds a *directory* URL to use.
//! See `tests/local/start_servers.sh` for a Docker-free local setup.

use std::time::Duration;

use mpt::{Location, SendMeta};

/// Set `MPT_IT_LOG=debug` to see client-side tracing while the tests run.
fn init_log() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Ok(level) = std::env::var("MPT_IT_LOG") {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(level)
                .with_writer(std::io::stderr)
                .try_init();
        }
    });
}

fn env(name: &str) -> Option<String> {
    init_log();
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

/// The URL without one query option.
fn drop_option(url: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    url.split('&')
        .filter(|p| !p.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("&")
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
    let meta = SendMeta::from_filename(name).unwrap().with_size(len as u64);
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

/// A pinned host key is accepted, a wrong one is refused before any transfer.
#[tokio::test]
async fn sftp_host_key_pinning() {
    let (Some(base), Some(fp)) = (env("MPT_IT_SFTP"), env("MPT_IT_SSH_HOSTKEY")) else {
        eprintln!("skipping: MPT_IT_SFTP / MPT_IT_SSH_HOSTKEY not set");
        return;
    };
    mpt::init_crypto();
    let pinned = |f: &str| {
        base.replace(
            "known_hosts=off",
            &format!("known_hosts=strict&hostkey={f}"),
        )
    };

    let ok = mpt::open(&pinned(&fp)).unwrap();
    ok.receiver()
        .unwrap()
        .list()
        .await
        .expect("pinned host key must be accepted");

    let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let bad = mpt::open(&pinned(wrong)).unwrap();
    let err = bad
        .receiver()
        .unwrap()
        .list()
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("hostkey= pins"), "{err}");
    assert!(
        err.contains(&fp),
        "error should name the real fingerprint: {err}"
    );

    // A malformed fingerprint is rejected while parsing, not on connect.
    assert!(mpt::open(&pinned("nonsense")).is_err());
}

roundtrip_test!(sftp_roundtrip, "MPT_IT_SFTP", 3 * 1024 * 1024 + 17, true);
roundtrip_test!(scp_roundtrip, "MPT_IT_SCP", 2 * 1024 * 1024 + 5, false);
roundtrip_test!(ftp_roundtrip, "MPT_IT_FTP", 1024 * 1024 + 3, true);
roundtrip_test!(ftps_roundtrip, "MPT_IT_FTPS", 1024 * 1024 + 9, true);
roundtrip_test!(http_roundtrip, "MPT_IT_HTTP", 512 * 1024 + 1, false);
roundtrip_test!(webdav_roundtrip, "MPT_IT_WEBDAV", 700 * 1024 + 7, true);
roundtrip_test!(s3_roundtrip, "MPT_IT_S3", 6 * 1024 * 1024 + 11, true);

/// One source, several real targets at once (stream mode): every target must
/// receive identical bytes. Uses whichever of sftp/s3/webdav/ftp are configured.
#[tokio::test]
async fn fanout_stream_to_many_targets() {
    fanout_many(mpt::CacheMode::Stream, 0).await;
}

/// Same with the in-memory cache and retries enabled.
#[tokio::test]
async fn fanout_memory_cache_to_many_targets() {
    fanout_many(mpt::CacheMode::Memory { limit: 64 << 20 }, 1).await;
}

async fn fanout_many(cache: mpt::CacheMode, retries: u32) {
    let bases: Vec<String> = [
        "MPT_IT_SFTP",
        "MPT_IT_S3",
        "MPT_IT_WEBDAV",
        "MPT_IT_FTP",
        "MPT_IT_SCP",
    ]
    .iter()
    .filter_map(|v| env(v))
    .collect();
    if bases.len() < 2 {
        eprintln!("skipping fan-out test: fewer than two MPT_IT_* targets set");
        return;
    }
    mpt::init_crypto();
    let len = 2 * 1024 * 1024 + 13;
    let payload = random_payload(len);
    let name =
        format!("fanout_{:?}_{}.bin", cache, std::process::id()).replace([' ', '{', '}', ':'], "_");
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join(&name);
    std::fs::write(&local, &payload).unwrap();

    let src = mpt::open(local.to_str().unwrap()).unwrap();
    // one deliberately failing target: wrong FTP password (if ftp is configured) or an unreachable sftp host
    let bad_url = env("MPT_IT_FTP")
        .map(|u| u.replace("ftppass", "wrongpass"))
        .unwrap_or_else(|| {
            "sftp://nobody@127.0.0.1:1/nowhere/?known_hosts=off&timeout=2".to_string()
        });
    let mut targets: Vec<Box<dyn mpt::Endpoint>> =
        bases.iter().map(|b| mpt::open(b).unwrap()).collect();
    targets.push(mpt::open(&bad_url).unwrap());
    let refs: Vec<&dyn mpt::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();

    let opts = mpt::CopyOptions {
        cache,
        retries,
        tee: mpt::TeeOptions {
            chunk_size: 32 * 1024,
            capacity: 4,
            ..Default::default()
        },
        ..Default::default()
    };
    let report = tokio::time::timeout(
        Duration::from_secs(180),
        mpt::copy_many(src.as_ref(), &refs, &opts),
    )
    .await
    .expect("timeout")
    .expect("copy_many");

    assert_eq!(report.bytes_read, len as u64);
    assert_eq!(report.targets.len(), bases.len() + 1);
    let bad = report.targets.last().unwrap();
    assert!(
        bad.result.is_err(),
        "bad target unexpectedly succeeded: {}",
        bad.target
    );
    if retries > 0 {
        assert_eq!(bad.attempts, retries + 1);
    }
    for (t, base) in report.targets.iter().zip(&bases) {
        assert!(t.result.is_ok(), "{}: {:?}", t.target, t.result);
        assert_eq!(t.bytes, len as u64, "{}", t.target);
        let file_url = dir_url(base, &format!("/{name}"));
        let ep = mpt::open(&file_url).unwrap();
        let mut stream = ep.receiver().unwrap().receive().await.expect("download");
        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
            .await
            .unwrap();
        assert!(got == payload, "content mismatch at {file_url}");
    }
}

/// After a copy the target directory holds the finished file and no leftover
/// `.mpt-part`; every protocol that can rename goes through that detour.
#[tokio::test]
async fn atomic_finish_leaves_no_part_files() {
    let bases: Vec<String> = ["MPT_IT_SFTP", "MPT_IT_WEBDAV", "MPT_IT_FTPS"]
        .iter()
        .filter_map(|k| env(k))
        .collect();
    if bases.is_empty() {
        eprintln!("skipping: no targets configured");
        return;
    }
    mpt::init_crypto();
    let name = format!("atomic_{}.bin", std::process::id());
    let payload = random_payload(200_000);
    let dir = tempfile::tempdir().unwrap();
    let src_path = dir.path().join(&name);
    std::fs::write(&src_path, &payload).unwrap();
    let src = mpt::open(src_path.to_str().unwrap()).unwrap();

    let targets: Vec<Box<dyn mpt::Endpoint>> =
        bases.iter().map(|b| mpt::open(b).unwrap()).collect();
    let refs: Vec<&dyn mpt::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let report = mpt::copy_many(src.as_ref(), &refs, &mpt::CopyOptions::default())
        .await
        .expect("copy_many");
    assert!(report.all_ok(), "{:?}", report.targets);

    for base in &bases {
        let listing = mpt::open(base)
            .unwrap()
            .receiver()
            .unwrap()
            .list()
            .await
            .expect("list");
        let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&name.as_str()),
            "{base}: {name} is missing from {names:?}"
        );
        // Only our own leftovers: other tests may be mid-transfer in the same
        // directory, and their .mpt-part files are legitimate right now.
        let part = format!("{name}.mpt-part");
        assert!(
            !names.contains(&part.as_str()),
            "{base}: a partial file was left behind: {part}"
        );
    }
}

/// `--hash`: the sidecar next to every real target must contain the digest of
/// the source, in `sha256sum` format; `--check` must then accept that sidecar.
#[tokio::test]
async fn hash_sidecars_on_real_targets_and_check() {
    let bases: Vec<String> = ["MPT_IT_SFTP", "MPT_IT_S3", "MPT_IT_WEBDAV", "MPT_IT_FTPS"]
        .iter()
        .filter_map(|v| env(v))
        .collect();
    if bases.is_empty() {
        eprintln!("skipping hash test: no MPT_IT_* targets set");
        return;
    }
    mpt::init_crypto();
    let payload = random_payload(300_000 + 1);
    let name = format!("hashed_{}.bin", std::process::id());
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join(&name);
    std::fs::write(&local, &payload).unwrap();
    let expected = mpt::hash::digest_bytes(mpt::HashAlgo::Sha256, &payload);

    let src = mpt::open(local.to_str().unwrap()).unwrap();
    let targets: Vec<Box<dyn mpt::Endpoint>> =
        bases.iter().map(|b| mpt::open(b).unwrap()).collect();
    let refs: Vec<&dyn mpt::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let opts = mpt::CopyOptions {
        hash: Some(mpt::HashAlgo::Sha256),
        ..Default::default()
    };
    let report = tokio::time::timeout(
        Duration::from_secs(120),
        mpt::copy_many(src.as_ref(), &refs, &opts),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(report.all_ok(), "{:?}", report.targets);
    assert_eq!(
        report.digests,
        vec![(mpt::HashAlgo::Sha256, expected.clone())]
    );

    for (t, base) in report.targets.iter().zip(&bases) {
        let sidecar_url = t.sidecar.as_deref().expect("sidecar written");
        // Read the sidecar back through the protocol itself.
        let ep = mpt::open(&dir_url(base, &format!("/{name}.sha256"))).unwrap();
        let mut stream = ep
            .receiver()
            .unwrap()
            .receive()
            .await
            .unwrap_or_else(|e| panic!("{sidecar_url}: {e}"));
        let mut text = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut text)
            .await
            .unwrap();
        assert_eq!(
            text,
            format!("{expected}  {name}\n"),
            "sidecar content at {sidecar_url}"
        );

        // Now copy the remote file back with --check: the remote sidecar must verify it.
        let remote_file = mpt::open(&dir_url(base, &format!("/{name}"))).unwrap();
        let back = mpt::open(&format!("{}/", tmp.path().join("back").display())).unwrap();
        let check_opts = mpt::CopyOptions {
            check: true,
            ..Default::default()
        };
        let r = mpt::copy_many(remote_file.as_ref(), &[back.as_ref()], &check_opts)
            .await
            .unwrap();
        let c = r.checked.expect("checked");
        assert!(c.ok(), "{}: expected {} got {}", base, c.expected, c.actual);
        assert_eq!(
            std::fs::read(tmp.path().join("back").join(&name)).unwrap(),
            payload
        );
    }
}

/// `--sign ssh:<key>` on real targets: the signature next to the checksum file
/// must verify with the allowed_signers file, both through mpt and ssh-keygen.
#[tokio::test]
async fn signed_sidecars_on_real_targets() {
    let bases: Vec<String> = ["MPT_IT_SFTP", "MPT_IT_S3", "MPT_IT_WEBDAV"]
        .iter()
        .filter_map(|v| env(v))
        .collect();
    if bases.is_empty() {
        eprintln!("skipping signing test: no MPT_IT_* targets set");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("id_ed25519");
    let ok = std::process::Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "it@example.com",
            "-f",
        ])
        .arg(&key)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipping signing test: ssh-keygen not available");
        return;
    }
    let signers = tmp.path().join("allowed_signers");
    std::fs::write(
        &signers,
        format!(
            "it@example.com {}",
            std::fs::read_to_string(tmp.path().join("id_ed25519.pub")).unwrap()
        ),
    )
    .unwrap();
    mpt::init_crypto();

    let name = format!("signed_{}.bin", std::process::id());
    let payload = random_payload(123_457);
    let local = tmp.path().join(&name);
    std::fs::write(&local, &payload).unwrap();
    let src = mpt::open(local.to_str().unwrap()).unwrap();
    let targets: Vec<Box<dyn mpt::Endpoint>> =
        bases.iter().map(|b| mpt::open(b).unwrap()).collect();
    let refs: Vec<&dyn mpt::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let signer =
        mpt::sign::load_signer(&mpt::SignSpec::parse(&format!("ssh:{}", key.display())).unwrap())
            .await
            .unwrap();
    let opts = mpt::CopyOptions {
        hash: Some(mpt::HashAlgo::Blake3),
        sign: Some(signer),
        ..Default::default()
    };
    let report = tokio::time::timeout(
        Duration::from_secs(120),
        mpt::copy_many(src.as_ref(), &refs, &opts),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(report.all_ok(), "{:?}", report.targets);

    let verifier =
        mpt::sign::load_verifier(&mpt::VerifySpec::SshAllowedSigners(signers.clone())).unwrap();
    for (t, base) in report.targets.iter().zip(&bases) {
        assert!(
            t.signature
                .as_deref()
                .unwrap()
                .contains(&format!("{name}.b3.sig")),
            "{:?}",
            t.signature
        );
        // Fetch the remote file with check + verify.
        let remote = mpt::open(&dir_url(base, &format!("/{name}"))).unwrap();
        let back = mpt::open(&format!("{}/", tmp.path().join("back").display())).unwrap();
        let opts = mpt::CopyOptions {
            check: true,
            verify: Some(verifier.clone()),
            ..Default::default()
        };
        let r = mpt::copy_many(remote.as_ref(), &[back.as_ref()], &opts)
            .await
            .unwrap();
        let c = r.checked.unwrap();
        assert!(
            c.ok() && c.signer.as_deref().unwrap().starts_with("it@example.com"),
            "{base}: {c:?}"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("back").join(&name)).unwrap(),
            payload
        );
    }
}

/// Sends an attachment via `mailto:` with `--hash` and (when ssh-keygen is
/// available) `--sign`. If `MPT_IT_MAILDIR` points at the receiving maildir,
/// the message must carry the file, the checksum file and the signature.
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

    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join(&name);
    std::fs::write(&local, &payload).unwrap();
    let src = mpt::open(local.to_str().unwrap()).unwrap();

    let key = tmp.path().join("id_ed25519");
    let signer = if std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        Some(
            mpt::sign::load_signer(
                &mpt::SignSpec::parse(&format!("ssh:{}", key.display())).unwrap(),
            )
            .await
            .unwrap(),
        )
    } else {
        None
    };
    let signed = signer.is_some();
    let opts = mpt::CopyOptions {
        hash: Some(mpt::HashAlgo::Blake3),
        sign: signer,
        ..Default::default()
    };
    let report = mpt::copy_many(src.as_ref(), &[ep.as_ref()], &opts)
        .await
        .expect("copy_many");
    assert!(report.all_ok(), "{:?}", report.targets);
    assert!(
        report.targets[0].sidecar.is_none(),
        "mail gets the checksum inline, not as a sidecar"
    );
    let expected = mpt::hash::digest_bytes(mpt::HashAlgo::Blake3, &payload);

    if let Some(dir) = maildir {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            count_mails(&dir),
            count_before + 1,
            "expected one new message in {dir}"
        );
        let msg = walk(&dir)
            .into_iter()
            .filter_map(|p| std::fs::read_to_string(&p).ok())
            .find(|s| s.contains(&name))
            .expect("no message mentions the attachment");
        assert!(
            msg.contains(&format!("filename=\"{name}.b3\"")),
            "checksum attachment missing:\n{msg}"
        );
        assert!(
            msg.contains(&format!("BLAKE3: {expected}")),
            "digest line missing in body:\n{msg}"
        );
        if signed {
            assert!(
                msg.contains(&format!("filename=\"{name}.b3.sig\"")),
                "signature attachment missing:\n{msg}"
            );
        }
    }
    let _ = SendMeta::from_filename("unused").unwrap();
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

/// A `[profiles.…]` entry stands in for the URL, and `mpt://<name>/<path>`
/// resolves to it — including the options the profile carries.
#[tokio::test]
async fn profile_urls_resolve_against_the_configuration() {
    let Some(base) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    // The only test that installs a configuration; it defines nothing but
    // this profile, so the others are unaffected.
    let cfg = mpt::Config::parse(&format!("[profiles.it-sftp]\nurl = \"{base}\"\n")).unwrap();
    mpt::config::install(cfg);

    let loc = mpt::config::locate("mpt://it-sftp/sub/x.bin").unwrap();
    assert_eq!(loc.scheme(), mpt::Scheme::Sftp);
    assert!(loc.path().ends_with("/sub/x.bin"), "{}", loc.path());
    assert!(loc.opt("key").is_some(), "the profile keeps its options");

    let file = format!("profile_{}.bin", std::process::id());
    tokio::time::timeout(
        Duration::from_secs(120),
        roundtrip("mpt://it-sftp/", &file, 8192, true),
    )
    .await
    .expect("timeout");
}

/// With the `s3-aws-auth` feature, credentials come from the AWS chain — here
/// from a profile file, the same path `aws sso login` fills in.
#[cfg(feature = "s3-aws-auth")]
#[tokio::test]
async fn s3_credentials_come_from_an_aws_profile() {
    let Some(base) = env("MPT_IT_S3") else {
        eprintln!("skipping: MPT_IT_S3 not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let creds = dir.path().join("credentials");
    std::fs::write(
        &creds,
        "[it]\naws_access_key_id = testkey\naws_secret_access_key = testsecret\n",
    )
    .unwrap();
    let conf = dir.path().join("config");
    std::fs::write(&conf, "[profile it]\nregion = us-east-1\n").unwrap();
    let payload = dir.path().join("profile-auth.bin");
    std::fs::write(&payload, b"from the aws chain").unwrap();

    let name = format!("aws_profile_{}.bin", std::process::id());
    let target = dir_url(&base, &format!("/{name}"));
    let sep = if target.contains('?') { "&" } else { "?" };
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["cp", payload.to_str().unwrap()])
        .arg(format!("{target}{sep}profile=it"))
        // Only the profile files may provide credentials.
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .env_remove("AWS_PROFILE")
        .env("AWS_CONFIG_FILE", &conf)
        .env("AWS_SHARED_CREDENTIALS_FILE", &creds)
        .output()
        .expect("running mpt");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Read it back the ordinary way.
    mpt::init_crypto();
    let got = mpt::open(&target).unwrap();
    let mut stream = got.receiver().unwrap().receive().await.expect("download");
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
        .await
        .unwrap();
    assert_eq!(buf, b"from the aws chain");
}

/// A certificate signed by a CA the server trusts gets in where the key
/// alone does not: `cert_key` is deliberately absent from `authorized_keys`.
#[tokio::test]
async fn sftp_authenticates_with_a_certificate() {
    let Some(url) = env("MPT_IT_SFTP_CERT") else {
        eprintln!("skipping: MPT_IT_SFTP_CERT not set");
        return;
    };
    mpt::init_crypto();
    let name = format!("cert_{}.bin", std::process::id());
    let file = dir_url(&url, &format!("/{name}"));
    let payload = b"signed by the CA".to_vec();

    let dst = mpt::open(&url).unwrap();
    let meta = SendMeta::from_filename(&name)
        .unwrap()
        .with_size(payload.len() as u64);
    dst.sender()
        .unwrap()
        .send(Box::pin(std::io::Cursor::new(payload.clone())), &meta)
        .await
        .expect("upload with a certificate");

    let src = mpt::open(&file).unwrap();
    let mut stream = src.receiver().unwrap().receive().await.expect("download");
    let mut got = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
        .await
        .unwrap();
    assert_eq!(got, payload);

    // The certificate is found next to the key even when the URL is silent
    // about it, the way OpenSSH looks for <key>-cert.pub.
    let implied = drop_option(&url, "cert");
    mpt::open(&implied)
        .unwrap()
        .receiver()
        .unwrap()
        .list()
        .await
        .expect("the certificate beside the key is found");

    // Away from its certificate, the same key is turned away — which is what
    // proves the certificate did the work.
    let key_path = url
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("key="))
        .expect("key= in MPT_IT_SFTP_CERT");
    let dir = tempfile::tempdir().unwrap();
    let lonely = dir.path().join("cert_key");
    std::fs::copy(key_path, &lonely).unwrap();
    let bare = drop_option(&url, "cert").replace(key_path, &lonely.display().to_string());
    let err = mpt::open(&bare)
        .unwrap()
        .receiver()
        .unwrap()
        .list()
        .await
        .expect_err("the bare key is not in authorized_keys");
    assert!(
        err.to_string().contains("no accepted method"),
        "unexpected error: {err}"
    );
}

/// `?token=` travels as `Authorization: Bearer …`, which is what an OAuth2
/// endpoint (SharePoint, Nextcloud, Artifactory) wants instead of a password.
#[tokio::test]
async fn http_sends_a_bearer_token() {
    let Some(base) = env("MPT_IT_HTTP") else {
        eprintln!("skipping: MPT_IT_HTTP not set");
        return;
    };
    mpt::init_crypto();
    let name = format!("bearer_{}.bin", std::process::id());
    let file = dir_url(&base, &format!("/{name}"));
    let dst = mpt::open(&format!("{file}?token=s3cr3t")).unwrap();
    let meta = SendMeta::from_filename(&name).unwrap().with_size(2);
    dst.sender()
        .unwrap()
        .send(Box::pin(std::io::Cursor::new(b"hi".to_vec())), &meta)
        .await
        .expect("upload");

    // The test server writes the header it saw next to the file.
    let seen = mpt::open(&format!("{file}.auth")).unwrap();
    let mut stream = seen.receiver().unwrap().receive().await.expect("download");
    let mut got = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut got)
        .await
        .unwrap();
    assert_eq!(got, "Bearer s3cr3t");
}

/// An interrupted upload is continued rather than repeated: the part file on
/// the target keeps what it has, and only the rest travels.
async fn resume_roundtrip(base: &str, name: &str) {
    mpt::init_crypto();
    let payload = random_payload(60_000);
    let dst = mpt::open(base).unwrap();

    // What an interrupted transfer would have left behind.
    let part = format!("{name}.mpt-part");
    let meta = SendMeta::from_filename(&part).unwrap().with_size(20_000);
    dst.sender()
        .unwrap()
        .send(
            Box::pin(std::io::Cursor::new(payload[..20_000].to_vec())),
            &meta,
        )
        .await
        .expect("placing the partial file");

    let tmp = tempfile::tempdir().unwrap();
    let src_path = tmp.path().join(name);
    std::fs::write(&src_path, &payload).unwrap();
    let src = mpt::open(src_path.to_str().unwrap()).unwrap();
    let opts = mpt::CopyOptions {
        resume: true,
        ..Default::default()
    };
    let report = mpt::copy_many(src.as_ref(), &[dst.as_ref()], &opts)
        .await
        .expect("resumed copy");
    assert!(report.all_ok(), "{:?}", report.targets);
    assert_eq!(
        report.targets[0].bytes, 40_000,
        "only what was missing should travel"
    );

    // And the file is whole.
    let file = mpt::open(&dir_url(base, &format!("/{name}"))).unwrap();
    let mut stream = file.receiver().unwrap().receive().await.expect("download");
    let mut got = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
        .await
        .unwrap();
    assert_eq!(got.len(), payload.len());
    assert!(got == payload, "the resumed file differs from the source");
}

#[tokio::test]
async fn sftp_resumes_a_partial_upload() {
    let Some(base) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    resume_roundtrip(&base, &format!("resume_sftp_{}.bin", std::process::id())).await;
}

#[tokio::test]
async fn ftp_resumes_a_partial_upload() {
    let Some(base) = env("MPT_IT_FTP") else {
        eprintln!("skipping: MPT_IT_FTP not set");
        return;
    };
    resume_roundtrip(&base, &format!("resume_ftp_{}.bin", std::process::id())).await;
}
