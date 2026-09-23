//! Checksums computed while data streams through, plus the `sha256sum`-style
//! sidecar file format (`<hex>  <name>`).

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::SystemTime;

use sha2::Digest;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgo {
    Sha256,
    Sha512,
    Blake3,
}

impl HashAlgo {
    pub const ALL: [HashAlgo; 3] = [HashAlgo::Blake3, HashAlgo::Sha256, HashAlgo::Sha512];

    pub fn parse(s: &str) -> Result<Self> {
        Ok(
            match s.trim().to_ascii_lowercase().replace('-', "").as_str() {
                "sha256" => HashAlgo::Sha256,
                "sha512" => HashAlgo::Sha512,
                "blake3" | "b3" => HashAlgo::Blake3,
                other => {
                    return Err(Error::invalid_option(
                        "hash",
                        format!("expected sha256|sha512|blake3, got '{other}'"),
                    ));
                }
            },
        )
    }

    /// File extension of the sidecar file (`name.sha256`, `name.b3`).
    pub fn extension(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha512 => "sha512",
            HashAlgo::Blake3 => "b3",
        }
    }

    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().as_str() {
            "sha256" => Some(HashAlgo::Sha256),
            "sha512" => Some(HashAlgo::Sha512),
            "b3" | "blake3" => Some(HashAlgo::Blake3),
            _ => None,
        }
    }

    pub fn sidecar_name(self, file: &str) -> String {
        format!("{file}.{}", self.extension())
    }

    pub fn label(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "SHA-256",
            HashAlgo::Sha512 => "SHA-512",
            HashAlgo::Blake3 => "BLAKE3",
        }
    }

    /// Name as used on the command line.
    pub fn name(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha512 => "sha512",
            HashAlgo::Blake3 => "blake3",
        }
    }
}

impl std::fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for HashAlgo {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        HashAlgo::parse(s)
    }
}

enum Hasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    fn new(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            HashAlgo::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
            HashAlgo::Blake3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
            Hasher::Blake3(h) => {
                h.update(data);
            }
        }
    }

    fn finalize(self) -> String {
        match self {
            Hasher::Sha256(h) => hex::encode(h.finalize()),
            Hasher::Sha512(h) => hex::encode(h.finalize()),
            Hasher::Blake3(h) => h.finalize().to_hex().to_string(),
        }
    }
}

/// Hash of a complete in-memory buffer.
pub fn digest_bytes(algo: HashAlgo, data: &[u8]) -> String {
    let mut h = Hasher::new(algo);
    h.update(data);
    h.finalize()
}

/// Handle to a digest that is filled in once the hashed stream reached EOF.
#[derive(Debug, Clone)]
pub struct DigestHandle {
    algo: HashAlgo,
    cell: Arc<OnceLock<String>>,
}

impl DigestHandle {
    /// A handle whose value is already known (memory-cache mode).
    pub fn ready(algo: HashAlgo, hex: String) -> Self {
        let cell = Arc::new(OnceLock::new());
        let _ = cell.set(hex);
        DigestHandle { algo, cell }
    }

    pub fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// `None` until the stream has been read to its end.
    pub fn get(&self) -> Option<String> {
        self.cell.get().cloned()
    }
}

/// Reader that feeds every byte into one or more hashers and publishes the
/// digests through [`DigestHandle`]s when the inner reader signals EOF.
pub struct Hashing<R> {
    inner: R,
    hashers: Vec<(Option<Hasher>, Arc<OnceLock<String>>)>,
}

/// Wrap `inner`; returns one handle per algorithm, in the given order.
pub fn hashing<R>(inner: R, algos: &[HashAlgo]) -> (Hashing<R>, Vec<DigestHandle>) {
    let mut hashers = Vec::with_capacity(algos.len());
    let mut handles = Vec::with_capacity(algos.len());
    for &algo in algos {
        let cell = Arc::new(OnceLock::new());
        hashers.push((Some(Hasher::new(algo)), cell.clone()));
        handles.push(DigestHandle { algo, cell });
    }
    (Hashing { inner, hashers }, handles)
}

impl<R: AsyncRead + Unpin> AsyncRead for Hashing<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len() - before;
            if n == 0 {
                for (h, cell) in &mut self.hashers {
                    if let Some(h) = h.take() {
                        let _ = cell.set(h.finalize());
                    }
                }
            } else {
                let chunk = &buf.filled()[before..];
                for (h, _) in &mut self.hashers {
                    if let Some(h) = h {
                        h.update(chunk);
                    }
                }
            }
        }
        res
    }
}

/// `<hex>  <name>\n` — the format of `sha256sum`, `sha512sum` and `b3sum`.
pub fn sidecar_content(hex: &str, filename: &str) -> String {
    format!("{hex}  {filename}\n")
}

/// Comment that records when a checksum file was signed. `sha256sum -c` and
/// `b3sum -c` ignore comment lines, so the file keeps their format.
pub const SIGNED_AT: &str = "# mpt-signed-at: ";

/// Sidecar file with the signing time, so a verifier can refuse a signature
/// that is too old (`policy.max_signature_age`).
pub fn sidecar_content_at(hex: &str, filename: &str, signed_at: Option<SystemTime>) -> String {
    match signed_at {
        None => sidecar_content(hex, filename),
        Some(t) => format!(
            "{hex}  {filename}\n{SIGNED_AT}{}\n",
            crate::sign::format_time(t)
        ),
    }
}

/// The signing time out of a checksum file, if it carries one.
pub fn parse_signed_at(text: &str) -> Option<SystemTime> {
    let line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix(SIGNED_AT.trim_end()))?;
    match crate::sign::parse_time(line) {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::warn!("ignoring an unreadable '{}' line: {e}", SIGNED_AT.trim());
            None
        }
    }
}

/// One `<hex>  <name>` line: digest and file name (the name may be prefixed
/// with `*` for binary mode, as coreutils does, and may be empty).
fn parse_entry(line: &str) -> Option<(String, String)> {
    let mut it = line.split_whitespace();
    let hex = it.next()?;
    if hex.len() < 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let name = it.collect::<Vec<_>>().join(" ");
    let name = name.trim_start_matches('*').to_string();
    Some((hex.to_ascii_lowercase(), name))
}

/// The digest a checksum file gives for the file `name`, or why it gives
/// none. The entry must name that file (`name`, `./name`): a checksum file
/// for another file, renamed to sit beside this one, does not count, and a
/// file with several entries (`SHA256SUMS`) is searched for the right one.
///
/// A file that holds nothing but a digest names no file; `allow_bare` takes
/// it for the file it sits beside. A signed checksum file must name the file,
/// or the signature would not say which file it vouches for.
pub fn sidecar_digest(
    text: &str,
    name: &str,
    allow_bare: bool,
) -> std::result::Result<String, String> {
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry =
            parse_entry(line).ok_or_else(|| format!("line {} is not '<hex>  <name>'", n + 1))?;
        entries.push(entry);
    }
    let mut found = entries
        .iter()
        .filter(|(_, n)| n == name || n.strip_prefix("./") == Some(name))
        .map(|(hex, _)| hex);
    if let Some(hex) = found.next() {
        if found.any(|other| other != hex) {
            return Err(format!("it lists '{name}' twice, with different digests"));
        }
        return Ok(hex.clone());
    }
    match entries.as_slice() {
        [] => Err("it holds no checksum".into()),
        [(hex, n)] if n.is_empty() => {
            if allow_bare {
                Ok(hex.clone())
            } else {
                Err(format!(
                    "its digest names no file, and a signed checksum file must name '{name}'"
                ))
            }
        }
        _ => {
            let names: Vec<String> = entries
                .iter()
                .take(3)
                .map(|(_, n)| format!("'{n}'"))
                .collect();
            let more = if entries.len() > 3 { ", …" } else { "" };
            Err(format!(
                "it has no entry for '{name}' (it lists {}{more})",
                names.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn known_vectors() {
        assert_eq!(digest_bytes(HashAlgo::Sha256, b""), SHA256_EMPTY);
        assert_eq!(digest_bytes(HashAlgo::Sha256, b"abc"), SHA256_ABC);
        assert_eq!(digest_bytes(HashAlgo::Blake3, b""), BLAKE3_EMPTY);
        assert_eq!(digest_bytes(HashAlgo::Sha512, b"abc"), SHA512_ABC);
    }

    #[tokio::test]
    async fn streaming_matches_direct_and_finalizes_at_eof() {
        let data: Vec<u8> = (0..100_003u32).map(|i| (i % 251) as u8).collect();
        let (mut r, handles) = hashing(
            std::io::Cursor::new(data.clone()),
            &[HashAlgo::Sha256, HashAlgo::Blake3],
        );
        let mut buf = [0u8; 7];
        let mut total = 0;
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            assert!(
                handles[0].get().is_none(),
                "digest must not be available before EOF"
            );
        }
        assert_eq!(total, data.len());
        assert_eq!(
            handles[0].get().unwrap(),
            digest_bytes(HashAlgo::Sha256, &data)
        );
        assert_eq!(
            handles[1].get().unwrap(),
            digest_bytes(HashAlgo::Blake3, &data)
        );
        assert_eq!(handles[0].algo(), HashAlgo::Sha256);
    }

    #[test]
    fn sidecar_roundtrip_and_parse() {
        let c = sidecar_content(SHA256_ABC, "report.pdf");
        assert_eq!(c, format!("{SHA256_ABC}  report.pdf\n"));
        assert_eq!(sidecar_digest(&c, "report.pdf", false).unwrap(), SHA256_ABC);
        // coreutils binary-mode marker, a leading "./" and a name with spaces
        let hex = sidecar_digest(
            &format!("{}  *my file.bin\n", SHA256_EMPTY.to_uppercase()),
            "my file.bin",
            false,
        )
        .unwrap();
        assert_eq!(hex, SHA256_EMPTY);
        assert_eq!(
            sidecar_digest(&format!("{SHA256_ABC}  ./x\n"), "x", false).unwrap(),
            SHA256_ABC
        );
        assert!(sidecar_digest("not a hash  x", "x", true).is_err());
        assert!(sidecar_digest("", "x", true).is_err());
        assert!(sidecar_digest("# only a comment\n", "x", true).is_err());
    }

    /// A checksum file is only good for the file it names, so a signed one
    /// for another file cannot be renamed to vouch for this one.
    #[test]
    fn the_entry_must_name_the_file() {
        let other = sidecar_content(SHA256_ABC, "other.bin");
        let e = sidecar_digest(&other, "report.pdf", true).unwrap_err();
        assert!(e.contains("no entry for 'report.pdf'"), "{e}");
        assert!(e.contains("'other.bin'"), "{e}");
        // A path to a file of the same name elsewhere is another file.
        assert!(
            sidecar_digest(
                &format!("{SHA256_ABC}  dir/report.pdf\n"),
                "report.pdf",
                true
            )
            .is_err()
        );

        // SHA256SUMS: the matching line, wherever it is.
        let sums =
            format!("{SHA256_EMPTY}  a.bin\n{SHA256_ABC}  report.pdf\n{SHA256_EMPTY}  z.bin\n");
        assert_eq!(
            sidecar_digest(&sums, "report.pdf", false).unwrap(),
            SHA256_ABC
        );
        assert_eq!(sidecar_digest(&sums, "z.bin", false).unwrap(), SHA256_EMPTY);
        // One name with two different digests is not a checksum file to trust.
        let twice = format!("{SHA256_EMPTY}  x\n{SHA256_ABC}  x\n");
        assert!(
            sidecar_digest(&twice, "x", true)
                .unwrap_err()
                .contains("twice")
        );
        // A malformed line spoils the file rather than being skipped.
        let e = sidecar_digest(&format!("{SHA256_ABC}  x\ngarbage\n"), "x", true).unwrap_err();
        assert!(e.contains("line 2"), "{e}");

        // A bare digest is taken for the file it sits beside, but only when
        // no signature has to say which file it covers.
        let bare = format!("{SHA256_ABC}\n");
        assert_eq!(sidecar_digest(&bare, "x", true).unwrap(), SHA256_ABC);
        let e = sidecar_digest(&bare, "x", false).unwrap_err();
        assert!(e.contains("names no file"), "{e}");
    }

    #[test]
    fn the_signing_time_travels_in_a_comment() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let c = sidecar_content_at(SHA256_ABC, "report.pdf", Some(t));
        assert_eq!(
            c,
            format!("{SHA256_ABC}  report.pdf\n# mpt-signed-at: 2023-11-14T22:13:20Z\n")
        );
        // The comment does not get in the way of the digest.
        assert_eq!(sidecar_digest(&c, "report.pdf", false).unwrap(), SHA256_ABC);
        assert_eq!(parse_signed_at(&c), Some(t));
        // Without the comment, and with an unreadable one.
        assert_eq!(parse_signed_at(&sidecar_content(SHA256_ABC, "x")), None);
        assert_eq!(parse_signed_at("# mpt-signed-at: yesterday\n"), None);
        // A file that leads with comments still parses.
        let hex = sidecar_digest(&format!("# a comment\n{SHA256_ABC}  x\n"), "x", false).unwrap();
        assert_eq!(hex, SHA256_ABC);
    }

    #[test]
    fn names_and_extensions() {
        assert_eq!(HashAlgo::parse("b3").unwrap(), HashAlgo::Blake3);
        assert_eq!(HashAlgo::parse("SHA-256").unwrap(), HashAlgo::Sha256);
        assert!(HashAlgo::parse("md5").is_err());
        assert_eq!(HashAlgo::Blake3.sidecar_name("a.bin"), "a.bin.b3");
        assert_eq!(HashAlgo::from_extension("sha512"), Some(HashAlgo::Sha512));
    }
}
