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
    let Some((path, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let prefix = format!("{name}=");
    let kept: Vec<&str> = query
        .split('&')
        .filter(|p| !p.starts_with(&prefix))
        .collect();
    if kept.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
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

/// An agent that holds a certificate offers it as a certificate: the same
/// `cert_key` that `authorized_keys` does not list gets in through the agent
/// alone, with no key file anywhere in the URL. The agent is reached the way a
/// relay reaches the one its client forwarded: as a broker on the location.
#[cfg(unix)]
#[tokio::test]
async fn sftp_authenticates_with_a_certificate_from_an_agent() {
    let (Some(url), Some(sock)) = (env("MPT_IT_SFTP_CERT"), env("MPT_IT_SSH_AGENT")) else {
        eprintln!("skipping: MPT_IT_SFTP_CERT / MPT_IT_SSH_AGENT not set");
        return;
    };
    mpt::init_crypto();

    struct Socket(String);
    #[async_trait::async_trait]
    impl mpt::broker::AgentSource for Socket {
        async fn open(&self) -> mpt::Result<mpt::broker::AgentStream> {
            Ok(Box::new(tokio::net::UnixStream::connect(&self.0).await?))
        }
    }

    let bare = drop_option(&drop_option(&url, "cert"), "key");
    let mut loc = Location::parse(&bare).unwrap();
    loc.set_brokers(mpt::broker::Brokers {
        password: None,
        agent: Some(std::sync::Arc::new(Socket(sock))),
    });
    mpt::protocols::open(loc)
        .unwrap()
        .receiver()
        .unwrap()
        .list()
        .await
        .expect("the certificate in the agent lets the key in");
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

/// A retry after a failed attempt sends the rest again from the same offset;
/// it must replace what the failed attempt wrote, not add to it.
#[tokio::test]
async fn sftp_repeated_append_writes_at_the_offset() {
    let Some(base) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    mpt::init_crypto();
    let name = format!("reappend_sftp_{}.bin", std::process::id());
    let dst = mpt::open(&dir_url(&base, &format!("/{name}"))).unwrap();
    let sender = dst.sender().unwrap();
    let meta = SendMeta::from_filename(&name).unwrap();
    sender
        .send(
            Box::pin(std::io::Cursor::new(b"0123456789".to_vec())),
            &meta,
        )
        .await
        .expect("placing the partial file");
    // What a failed first attempt left behind the offset.
    sender
        .append(Box::pin(std::io::Cursor::new(b"xyz".to_vec())), &meta, 10)
        .await
        .expect("first append");
    sender
        .append(
            Box::pin(std::io::Cursor::new(b"abcdef".to_vec())),
            &meta,
            10,
        )
        .await
        .expect("second append");
    assert_eq!(fetch(&base, &name).await, b"0123456789abcdef");
}

/// Download `<base>/<name>` and return the bytes.
async fn fetch(base: &str, name: &str) -> Vec<u8> {
    let file = mpt::open(&dir_url(base, &format!("/{name}"))).unwrap();
    let mut stream = file.receiver().unwrap().receive().await.expect("download");
    let mut got = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut got)
        .await
        .unwrap();
    got
}

/// Twenty jobs, each a local file fanned out to sftp and ftp, four at a
/// time; every target ends up byte-identical to its source.
#[tokio::test]
async fn batch_runs_many_jobs_in_parallel() {
    let (Some(sftp), Some(ftp)) = (env("MPT_IT_SFTP"), env("MPT_IT_FTP")) else {
        eprintln!("skipping: MPT_IT_SFTP and MPT_IT_FTP not both set");
        return;
    };
    mpt::init_crypto();
    let dir = tempfile::tempdir().unwrap();
    let tag = std::process::id();
    let mut jobs = Vec::new();
    let mut payloads = Vec::new();
    for i in 0..20 {
        let name = format!("batch_{tag}_{i}.bin");
        let payload = random_payload(1000 + i * 137);
        let path = dir.path().join(&name);
        std::fs::write(&path, &payload).unwrap();
        payloads.push((name, payload));
        jobs.push(mpt::Job {
            src: Location::parse(path.to_str().unwrap()).unwrap(),
            dsts: vec![
                Location::parse(&sftp).unwrap(),
                Location::parse(&ftp).unwrap(),
            ],
        });
    }
    let open = |l: &Location| mpt::protocols::open(l.clone());
    let progress = mpt::batch::BatchProgress::new();
    let opts = mpt::BatchOptions {
        parallel: 4,
        fail_fast: false,
        progress: Some(progress.clone()),
    };
    let mut finished = Vec::new();
    let report = mpt::batch::run(jobs, &open, &mpt::CopyOptions::default(), &opts, |r| {
        finished.push(r.index)
    })
    .await;
    assert!(
        report.all_ok(),
        "{:?}",
        report
            .failures()
            .map(|j| format!("{}: {:?}", j.job.src, j.result))
            .collect::<Vec<_>>()
    );
    assert_eq!(finished.len(), 20);
    assert_eq!(progress.done(), 20);
    assert_eq!(progress.failed(), 0);
    let total: u64 = payloads.iter().map(|(_, p)| p.len() as u64).sum();
    assert_eq!(progress.bytes(), total);
    for (name, payload) in &payloads {
        assert!(fetch(&sftp, name).await == *payload, "{name} on sftp");
        assert!(fetch(&ftp, name).await == *payload, "{name} on ftp");
    }
}

/// The binary: a CSV list with a spare column, a JSON Lines list on stdin
/// with `--json` (one JSON object per job on stdout), and `--dry-run`, which
/// transfers nothing.
#[tokio::test]
async fn batch_binary_takes_csv_and_jsonl_lists() {
    let Some(sftp) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    mpt::init_crypto();
    let dir = tempfile::tempdir().unwrap();
    let tag = std::process::id();
    let mut names = Vec::new();
    for i in 0..4 {
        let name = format!("batchbin_{tag}_{i}.bin");
        std::fs::write(dir.path().join(&name), format!("job {i}")).unwrap();
        names.push(name);
    }
    let path = |n: &str| dir.path().join(n).display().to_string();

    // CSV: the `note` column is ignored, the second row has two targets.
    let csv = dir.path().join("jobs.csv");
    std::fs::write(
        &csv,
        format!(
            "note,src,dst,dst\nfirst,{},{sftp},\nsecond,{},{sftp},{}/\n",
            path(&names[0]),
            path(&names[1]),
            dir.path().join("copy").display()
        ),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("copy")).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["batch", csv.to_str().unwrap(), "--parallel", "2"])
        .output()
        .expect("running mpt");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("2/2 jobs ok"), "{stderr}");
    assert_eq!(fetch(&sftp, &names[0]).await, b"job 0");
    assert_eq!(fetch(&sftp, &names[1]).await, b"job 1");
    assert_eq!(
        std::fs::read(dir.path().join("copy").join(&names[1])).unwrap(),
        b"job 1"
    );

    // JSON Lines on stdin, JSON out: one object per job, in completion order.
    let jsonl = format!(
        "{{\"src\": \"{}\", \"dst\": \"{sftp}\"}}\n{{\"src\": \"{}\", \"dst\": [\"{sftp}\"]}}\n",
        path(&names[2]),
        path(&names[3])
    );
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["batch", "-", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("running mpt");
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), jsonl.as_bytes()).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON object per line"))
        .collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    let mut jobs: Vec<u64> = lines.iter().map(|l| l["job"].as_u64().unwrap()).collect();
    jobs.sort();
    assert_eq!(jobs, vec![1, 2]);
    assert!(lines.iter().all(|l| l["ok"] == true), "{stdout}");
    assert_eq!(fetch(&sftp, &names[2]).await, b"job 2");
    assert_eq!(fetch(&sftp, &names[3]).await, b"job 3");

    // Dry run: the jobs are listed, nothing is sent.
    let unsent = format!("batchbin_{tag}_dry.bin");
    std::fs::write(dir.path().join(&unsent), b"never").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["cp", "--dry-run", "-t", &sftp, &path(&unsent)])
        .output()
        .expect("running mpt");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("[1/1]") && stdout.contains(&unsent),
        "{stdout}"
    );
    let listing = mpt::open(&sftp)
        .unwrap()
        .receiver()
        .unwrap()
        .list()
        .await
        .unwrap();
    assert!(
        listing.iter().all(|e| e.name != unsent),
        "dry run sent a file"
    );
}

/// When every failure in a batch is an authentication failure, the exit
/// code says so (4); the other jobs still run. Two jobs writing the same
/// file are refused before anything is sent (2).
#[tokio::test]
async fn batch_binary_exit_codes() {
    let (Some(sftp), Some(ftp)) = (env("MPT_IT_SFTP"), env("MPT_IT_FTP")) else {
        eprintln!("skipping: MPT_IT_SFTP and MPT_IT_FTP not both set");
        return;
    };
    mpt::init_crypto();
    let dir = tempfile::tempdir().unwrap();
    let tag = std::process::id();
    let good = format!("batchcode_{tag}_good.bin");
    let bad = format!("batchcode_{tag}_bad.bin");
    std::fs::write(dir.path().join(&good), b"good").unwrap();
    std::fs::write(dir.path().join(&bad), b"bad").unwrap();
    let wrong_ftp = ftp.replace("ftppass@", "wrongpass@");
    assert_ne!(
        wrong_ftp, ftp,
        "the FTP test URL is expected to carry ftpuser:ftppass"
    );
    let list = dir.path().join("jobs.txt");
    std::fs::write(
        &list,
        format!(
            "'{}' '{sftp}'\n'{}' '{wrong_ftp}'\n",
            dir.path().join(&good).display(),
            dir.path().join(&bad).display()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["batch", list.to_str().unwrap()])
        .output()
        .expect("running mpt");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("1/2 jobs ok"), "{stderr}");
    assert_eq!(fetch(&sftp, &good).await, b"good");

    // The same target twice.
    std::fs::write(
        &list,
        format!(
            "'{}' '{sftp}'\n'{}' '{sftp}'\n",
            dir.path().join(&good).display(),
            dir.path().join(&good).display()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["batch", list.to_str().unwrap()])
        .output()
        .expect("running mpt");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("jobs 1 and 2 write the same target"),
        "{stderr}"
    );
}

/// A pattern in the source names every matching file of a remote
/// directory; through the binary, with the jobs it expands to.
#[tokio::test]
async fn a_source_pattern_expands_on_a_remote_directory() {
    let Some(sftp) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    mpt::init_crypto();
    let tag = std::process::id();
    let dir = tempfile::tempdir().unwrap();
    // Three files on the server, two of which match.
    let sender = mpt::open(&sftp).unwrap();
    for (name, body) in [
        (format!("glob_{tag}_1.csv"), "one"),
        (format!("glob_{tag}_2.csv"), "two"),
        (format!("glob_{tag}_3.txt"), "three"),
    ] {
        let meta = SendMeta::from_filename(&name)
            .unwrap()
            .with_size(body.len() as u64);
        sender
            .sender()
            .unwrap()
            .send(
                Box::pin(std::io::Cursor::new(body.as_bytes().to_vec())),
                &meta,
            )
            .await
            .unwrap();
    }
    let pattern = dir_url(&sftp, &format!("/glob_{tag}_*.csv"));
    let out = format!("{}/", dir.path().display());
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["cp", &pattern, &out])
        .output()
        .expect("running mpt");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{stderr}");
    assert!(stderr.contains("2/2 jobs ok"), "{stderr}");
    assert_eq!(
        std::fs::read(dir.path().join(format!("glob_{tag}_1.csv"))).unwrap(),
        b"one"
    );
    assert_eq!(
        std::fs::read(dir.path().join(format!("glob_{tag}_2.csv"))).unwrap(),
        b"two"
    );
    assert!(!dir.path().join(format!("glob_{tag}_3.txt")).exists());

    // Nothing matches: an error, unless allowed.
    let none = dir_url(&sftp, &format!("/glob_{tag}_*.nothing"));
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["cp", &none, &out])
        .output()
        .expect("running mpt");
    assert_eq!(
        run.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["cp", "--allow-empty", &none, &out])
        .output()
        .expect("running mpt");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// `-r` copies a tree: directories are created on the way, and every file
/// lands where it belongs, on each protocol that can hold directories.
#[tokio::test]
async fn recursive_copy_creates_directories_on_every_protocol() {
    let remotes: Vec<(&str, String)> = [
        "MPT_IT_SFTP",
        "MPT_IT_SCP",
        "MPT_IT_FTP",
        "MPT_IT_WEBDAV",
        "MPT_IT_S3",
    ]
    .iter()
    .filter_map(|v| env(v).map(|u| (*v, u)))
    .collect();
    if remotes.is_empty() {
        eprintln!("skipping: no MPT_IT_* directory URL set");
        return;
    }
    mpt::init_crypto();
    let tag = std::process::id();
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("tree");
    std::fs::create_dir_all(src.join("a/deep")).unwrap();
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("top.txt"), "top").unwrap();
    std::fs::write(src.join("a/one.txt"), "one").unwrap();
    std::fs::write(src.join("a/deep/two.txt"), "two").unwrap();

    for (var, base) in &remotes {
        // `tree` without a slash: the directory itself, under a unique name.
        let target = dir_url(base, &format!("/rtree_{tag}/"));
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
            .args(["cp", "-r", src.to_str().unwrap(), &target])
            .output()
            .expect("running mpt");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{var}: {stderr}");
        assert!(stderr.contains("3/3 jobs ok"), "{var}: {stderr}");
        let root = dir_url(base, &format!("/rtree_{tag}/tree"));
        assert_eq!(fetch(&root, "top.txt").await, b"top", "{var}");
        assert_eq!(fetch(&root, "a/one.txt").await, b"one", "{var}");
        assert_eq!(fetch(&root, "a/deep/two.txt").await, b"two", "{var}");
        if *var != "MPT_IT_S3" && *var != "MPT_IT_SCP" {
            // An empty directory travels too (S3 has no such thing, and
            // SCP cannot list to show it).
            let listing = mpt::open(&dir_url(&root, "/"))
                .unwrap()
                .receiver()
                .unwrap()
                .list()
                .await
                .unwrap();
            assert!(
                listing.iter().any(|e| e.name == "empty" && e.is_dir),
                "{var}: {listing:?}"
            );
        }
    }

    // And back: the sftp tree's contents (trailing slash) into a local dir.
    if let Some(sftp) = env("MPT_IT_SFTP") {
        let back = dir.path().join("back");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
            .args([
                "cp",
                "-r",
                &dir_url(&sftp, &format!("/rtree_{tag}/tree/")),
                &format!("{}/", back.display()),
            ])
            .output()
            .expect("running mpt");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(back.join("a/deep/two.txt")).unwrap(), b"two");
        assert!(back.join("empty").is_dir());
        assert!(!back.join("tree").exists());
    }

    // A dry run creates nothing.
    if let Some(sftp) = env("MPT_IT_SFTP") {
        let target = dir_url(&sftp, &format!("/rtree_dry_{tag}/"));
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
            .args(["cp", "-r", "--dry-run", src.to_str().unwrap(), &target])
            .output()
            .expect("running mpt");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let listing = mpt::open(&sftp)
            .unwrap()
            .receiver()
            .unwrap()
            .list()
            .await
            .unwrap();
        assert!(listing.iter().all(|e| e.name != format!("rtree_dry_{tag}")));
    }
}

/// A second `-r --skip-existing` run over the same tree sends nothing; a
/// file that grew in between is sent again.
#[tokio::test]
async fn skip_existing_makes_a_tree_copy_repeatable() {
    let Some(sftp) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    mpt::init_crypto();
    let tag = std::process::id();
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("tree");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("one.txt"), "one").unwrap();
    std::fs::write(src.join("sub/two.txt"), "two").unwrap();
    let target = dir_url(&sftp, &format!("/skip_{tag}/"));
    let run = |extra: &[&str]| {
        let mut args = vec!["cp", "-r", "--skip-existing", "--json"];
        args.extend_from_slice(extra);
        args.push(src.to_str().unwrap());
        args.push(&target);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
            .args(&args)
            .output()
            .expect("running mpt");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .collect::<Vec<_>>()
    };
    let skipped = |lines: &[serde_json::Value]| -> usize {
        lines
            .iter()
            .filter(|l| l["targets"][0]["skipped"] == true)
            .count()
    };

    let first = run(&[]);
    assert_eq!(first.len(), 2);
    assert_eq!(skipped(&first), 0);

    let second = run(&[]);
    assert_eq!(second.len(), 2);
    assert_eq!(skipped(&second), 2, "{second:?}");
    assert!(second.iter().all(|l| l["bytes_read"] == 0));

    std::fs::write(src.join("sub/two.txt"), "two, longer").unwrap();
    let third = run(&[]);
    assert_eq!(skipped(&third), 1, "{third:?}");
    let root = dir_url(&sftp, &format!("/skip_{tag}/tree"));
    assert_eq!(fetch(&root, "sub/two.txt").await, b"two, longer");
}

/// `--delete-source` on a remote source: the file is gone from the server
/// after a successful copy, and stays when a target fails. An HTTP source
/// is refused up front.
#[tokio::test]
async fn delete_source_drains_a_remote_directory() {
    let Some(sftp) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    mpt::init_crypto();
    let tag = std::process::id();
    let dir = tempfile::tempdir().unwrap();
    let remote_dir = dir_url(&sftp, &format!("/outbox_{tag}/"));
    // Put two files there, through the library.
    let ep = mpt::open(&remote_dir).unwrap();
    ep.sender().unwrap().mkdir_all().await.unwrap();
    for (name, body) in [("keep.txt", "keep"), ("go.txt", "go")] {
        let meta = SendMeta::from_filename(name)
            .unwrap()
            .with_size(body.len() as u64);
        ep.sender()
            .unwrap()
            .send(
                Box::pin(std::io::Cursor::new(body.as_bytes().to_vec())),
                &meta,
            )
            .await
            .unwrap();
    }
    let names =
        |entries: Vec<mpt::Entry>| -> Vec<String> { entries.into_iter().map(|e| e.name).collect() };

    // One target cannot be written: the source stays.
    std::fs::write(dir.path().join("blocker"), b"x").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args([
            "cp",
            "--delete-source",
            &dir_url(&remote_dir, "keep.txt"),
            &format!("{}/blocker/sub/", dir.path().display()),
        ])
        .output()
        .expect("running mpt");
    assert!(!out.status.success());
    let listing = names(ep.receiver().unwrap().list().await.unwrap());
    assert!(listing.contains(&"keep.txt".to_string()), "{listing:?}");

    // The whole directory into a local one: files go, the directory stays.
    let inbox = dir.path().join("inbox");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args([
            "cp",
            "-r",
            "--delete-source",
            "--json",
            &remote_dir,
            &format!("{}/", inbox.display()),
        ])
        .output()
        .expect("running mpt");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["source_removed"], true, "{line}");
    }
    assert_eq!(std::fs::read(inbox.join("go.txt")).unwrap(), b"go");
    assert_eq!(std::fs::read(inbox.join("keep.txt")).unwrap(), b"keep");
    let listing = names(ep.receiver().unwrap().list().await.unwrap());
    assert!(listing.is_empty(), "{listing:?}");

    // An HTTP source cannot be deleted: refused before anything moves.
    if let Some(http) = env("MPT_IT_HTTP") {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
            .args([
                "cp",
                "--delete-source",
                &dir_url(&http, "/whatever.txt"),
                &format!("{}/", inbox.display()),
            ])
            .output()
            .expect("running mpt");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// `batch - --follow` runs each line as it arrives: the first job is done
/// before the second line is even written. A bad line is reported and
/// skipped, and the run ends with the input.
#[tokio::test]
async fn follow_runs_jobs_as_their_lines_arrive() {
    let Some(sftp) = env("MPT_IT_SFTP") else {
        eprintln!("skipping: MPT_IT_SFTP not set");
        return;
    };
    mpt::init_crypto();
    let tag = std::process::id();
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..2).map(|i| format!("follow_{tag}_{i}.bin")).collect();
    for (i, n) in names.iter().enumerate() {
        std::fs::write(dir.path().join(n), format!("line {i}")).unwrap();
    }
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
        .args(["batch", "-", "--follow", "--json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("running mpt");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = std::io::BufRead::lines(std::io::BufReader::new(stdout));
    let mut next_json = || -> serde_json::Value {
        serde_json::from_str(&lines.next().expect("a JSON line").unwrap()).unwrap()
    };

    // Line one; its report must come back before line two is sent.
    std::io::Write::write_all(
        &mut stdin,
        format!("'{}' '{sftp}'\n", dir.path().join(&names[0]).display()).as_bytes(),
    )
    .unwrap();
    let first = next_json();
    assert_eq!(first["job"], 1, "{first}");
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(fetch(&sftp, &names[0]).await, b"line 0");

    // A line that is no job at all, then a good one.
    std::io::Write::write_all(&mut stdin, b"'unbalanced\n").unwrap();
    let bad = next_json();
    assert_eq!(bad["line"], 2, "{bad}");
    assert_eq!(bad["ok"], false, "{bad}");
    std::io::Write::write_all(
        &mut stdin,
        format!("'{}' '{sftp}'\n", dir.path().join(&names[1]).display()).as_bytes(),
    )
    .unwrap();
    let second = next_json();
    assert_eq!(second["job"], 2, "{second}");
    assert_eq!(second["ok"], true, "{second}");
    drop(stdin);
    let status = child.wait().unwrap();
    // One rejected line: the run failed, with the usage code that line had.
    assert_eq!(status.code(), Some(2));
    assert_eq!(fetch(&sftp, &names[1]).await, b"line 1");
}

/// A pattern with nothing in front of it expands in the working directory.
/// `mpt cp '*.csv' out/` is the way anyone would write it, and it once failed
/// with "No such file or directory" because the empty directory in front of
/// the name was passed to the file system as it stood.
#[test]
fn a_bare_pattern_expands_in_the_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();
    for name in ["one.csv", "two.csv", "notes.txt"] {
        std::fs::write(dir.path().join(name), name).unwrap();
    }
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_mpt"))
            .args(args)
            .current_dir(dir.path())
            .output()
            .expect("running mpt")
    };

    let out = run(&["cp", "*.csv", "out/"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("2/2 jobs ok"), "{stderr}");
    assert_eq!(
        std::fs::read(dir.path().join("out/one.csv")).unwrap(),
        b"one.csv"
    );
    assert_eq!(
        std::fs::read(dir.path().join("out/two.csv")).unwrap(),
        b"two.csv"
    );
    assert!(
        !dir.path().join("out/notes.txt").exists(),
        "the pattern took too much"
    );

    // A pattern with a directory in front behaves the same way.
    std::fs::create_dir(dir.path().join("out2")).unwrap();
    let out = run(&["cp", "./*.csv", "out2/"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("out2/one.csv").exists());

    // Nothing matches: an error, and 0 with --allow-empty rather than the
    // I/O error the empty directory used to produce.
    let out = run(&["cp", "*.nothing", "out/"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("matches no file"), "{stderr}");
    let out = run(&["cp", "--allow-empty", "*.nothing", "out/"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
