//! Detached signatures over checksum files.
//!
//! Two backends behind the same object-safe traits:
//! * **OpenSSH** (`--sign ssh[:<key>]`): SSHSIG format, verifiable with
//!   `ssh-keygen -Y verify -f allowed_signers -I <principal> -n file -s x.sha256.sig < x.sha256`.
//!   Keys come from a file or from the running ssh-agent.
//! * **OpenPGP** (`--sign pgp:<key>`): armored detached signature (`.asc`),
//!   verifiable with `gpg --verify x.sha256.asc x.sha256`.
//!
//! The backends wrap key types that implement the RustCrypto `signature`
//! traits (`ssh-key`) or rPGP's `SigningKey`/`VerifyingKey`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::{Error, Result};

/// The SSHSIG namespace used by `ssh-keygen -Y sign` for files.
pub const SSH_NAMESPACE: &str = "file";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignFormat {
    Ssh,
    Pgp,
}

impl SignFormat {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "ssh" | "openssh" => SignFormat::Ssh,
            "pgp" | "gpg" | "openpgp" => SignFormat::Pgp,
            other => {
                return Err(Error::invalid_option(
                    "sign",
                    format!("expected ssh[:<key>] or pgp:<key>, got '{other}'"),
                ));
            }
        })
    }

    /// Extension of the detached signature file (`x.sha256.sig` / `x.sha256.asc`).
    pub fn extension(self) -> &'static str {
        match self {
            SignFormat::Ssh => "sig",
            SignFormat::Pgp => "asc",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SignFormat::Ssh => "OpenSSH",
            SignFormat::Pgp => "OpenPGP",
        }
    }

    pub fn signature_name(self, sidecar: &str) -> String {
        format!("{sidecar}.{}", self.extension())
    }
}

/// What to sign with, parsed from `ssh`, `ssh:<keyfile>` or `pgp:<keyfile>`.
#[derive(Debug, Clone)]
pub struct SignSpec {
    pub format: SignFormat,
    pub key: Option<PathBuf>,
    /// Passphrase of the key file (`MPT_SIGN_KEY_PASSPHRASE`).
    pub passphrase: Option<SecretString>,
}

impl SignSpec {
    pub fn parse(s: &str) -> Result<Self> {
        let (fmt, key) = match s.split_once(':') {
            Some((f, k)) => (f, Some(k)),
            None => (s, None),
        };
        let format = SignFormat::parse(fmt)?;
        let key = key
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(|k| PathBuf::from(expand_tilde(k)));
        if format == SignFormat::Pgp && key.is_none() {
            return Err(Error::invalid_option(
                "sign",
                "pgp needs a key file: pgp:<secret-key.asc>",
            ));
        }
        let passphrase = std::env::var("MPT_SIGN_KEY_PASSPHRASE")
            .ok()
            .filter(|p| !p.is_empty())
            .map(SecretString::from)
            .or_else(|| crate::config::global().resolved.signing_passphrase.clone());
        Ok(SignSpec {
            format,
            key,
            passphrase,
        })
    }
}

impl std::str::FromStr for SignSpec {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        SignSpec::parse(s)
    }
}

/// Produces detached signatures.
#[async_trait]
pub trait Signer: Send + Sync {
    fn format(&self) -> SignFormat;
    /// Human-readable description of the signing key (fingerprint, user id).
    fn identity(&self) -> String;
    /// Detached signature over `message` in the backend's file format.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// Verifies detached signatures against a set of trusted keys.
pub trait Verifier: Send + Sync {
    fn format(&self) -> SignFormat;

    /// Returns the identity of the trusted key that produced `signature`.
    /// Validity windows are checked against the current time.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<String> {
        self.verify_at(message, signature, SystemTime::now())
    }

    /// Like [`Verifier::verify`], but checks key and signer validity against
    /// `at` instead of now (the signing time recorded in the checksum file).
    fn verify_at(&self, message: &[u8], signature: &[u8], at: SystemTime) -> Result<String>;
}

/// Parse an OpenSSH `allowed_signers` timestamp: `YYYYMMDD`, `YYYYMMDDHHMM`
/// or `YYYYMMDDHHMMSS`, with an optional `Z`. Always read as UTC.
fn parse_ssh_time(raw: &str) -> Result<SystemTime> {
    let v = raw.trim().trim_end_matches(['Z', 'z']);
    let bad = || {
        Error::InvalidUrl(format!(
            "'{raw}' is not an allowed_signers timestamp (YYYYMMDD[HHMM[SS]])"
        ))
    };
    if !matches!(v.len(), 8 | 12 | 14) || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let num = |a: usize, b: usize| v[a..b].parse::<i64>().map_err(|_| bad());
    let (y, m, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (hh, mm, ss) = match v.len() {
        8 => (0, 0, 0),
        12 => (num(8, 10)?, num(10, 12)?, 0),
        _ => (num(8, 10)?, num(10, 12)?, num(12, 14)?),
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return Err(bad());
    }
    let secs = days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss;
    if secs < 0 {
        return Err(bad());
    }
    Ok(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant\'s
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Human-readable UTC date for error messages, without pulling in a date crate.
fn fmt_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Inverse of days_from_civil.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Trusted keys for verification.
#[derive(Debug, Clone)]
pub enum VerifySpec {
    /// OpenSSH `allowed_signers` file (`principal[,principal] [options] keytype base64 [comment]`).
    SshAllowedSigners(PathBuf),
    /// Armored OpenPGP public keys (one or more, e.g. `gpg --export --armor`).
    PgpKeyring(PathBuf),
}

impl VerifySpec {
    pub fn format(&self) -> SignFormat {
        match self {
            VerifySpec::SshAllowedSigners(_) => SignFormat::Ssh,
            VerifySpec::PgpKeyring(_) => SignFormat::Pgp,
        }
    }
}

/// Build a signer for `spec`.
pub async fn load_signer(spec: &SignSpec) -> Result<Arc<dyn Signer>> {
    match spec.format {
        SignFormat::Ssh => ssh::load(spec).await,
        SignFormat::Pgp => pgp::load(spec),
    }
}

/// Build a verifier for `spec`.
pub fn load_verifier(spec: &VerifySpec) -> Result<Arc<dyn Verifier>> {
    match spec {
        VerifySpec::SshAllowedSigners(p) => ssh::load_verifier(p),
        VerifySpec::PgpKeyring(p) => pgp::load_verifier(p),
    }
}

fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

#[allow(dead_code)]
fn unsupported(what: &str, feature: &str) -> Error {
    Error::UnsupportedScheme(format!(
        "{what} signatures (compiled without the '{feature}' feature)"
    ))
}

// ---------------------------------------------------------------------------
// OpenSSH backend
// ---------------------------------------------------------------------------

#[cfg(feature = "sign-ssh")]
pub mod ssh {
    use super::*;
    use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

    /// Sign with a private key file (or a default key from `~/.ssh`).
    pub struct FileSigner {
        key: PrivateKey,
    }

    #[async_trait]
    impl Signer for FileSigner {
        fn format(&self) -> SignFormat {
            SignFormat::Ssh
        }
        fn identity(&self) -> String {
            describe(self.key.public_key())
        }
        async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let sig = self
                .key
                .sign(SSH_NAMESPACE, HashAlg::Sha512, message)
                .map_err(|e| Error::transport("sshsig", e))?;
            Ok(sig
                .to_pem(LineEnding::LF)
                .map_err(|e| Error::transport("sshsig", e))?
                .into_bytes())
        }
    }

    pub(super) fn describe(key: &PublicKey) -> String {
        let comment = key.comment().to_string();
        let fp = key.fingerprint(HashAlg::Sha256);
        if comment.is_empty() {
            fp.to_string()
        } else {
            format!("{fp} ({comment})")
        }
    }

    pub(super) async fn load(spec: &SignSpec) -> Result<Arc<dyn Signer>> {
        if let Some(path) = &spec.key {
            return Ok(Arc::new(FileSigner {
                key: read_key(path, spec.passphrase.as_ref().map(|p| p.expose_secret()))?,
            }));
        }
        // No key given: ssh-agent first, then MPT_SSH_KEY, then default key files.
        #[cfg(feature = "ssh")]
        if std::env::var_os("SSH_AUTH_SOCK").is_some() {
            match agent::AgentSigner::connect().await {
                Ok(s) => return Ok(Arc::new(s)),
                Err(e) => tracing::warn!("ssh-agent not usable for signing: {e}"),
            }
        }
        let mut candidates: Vec<PathBuf> = std::env::var("MPT_SSH_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(expand_tilde(&s)))
            .into_iter()
            .collect();
        if let Some(home) = std::env::home_dir() {
            for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                candidates.push(home.join(".ssh").join(name));
            }
        }
        for path in candidates {
            if path.exists() {
                return Ok(Arc::new(FileSigner {
                    key: read_key(&path, spec.passphrase.as_ref().map(|p| p.expose_secret()))?,
                }));
            }
        }
        Err(Error::Auth(
            "no signing key: give --sign ssh:<key>, set MPT_SSH_KEY or run an ssh-agent".into(),
        ))
    }

    fn read_key(path: &std::path::Path, passphrase: Option<&str>) -> Result<PrivateKey> {
        let key = PrivateKey::read_openssh_file(path)
            .map_err(|e| Error::Auth(format!("cannot read {}: {e}", path.display())))?;
        if key.is_encrypted() {
            let pw = passphrase.ok_or_else(|| {
                Error::Auth(format!(
                    "{} is encrypted; set MPT_SIGN_KEY_PASSPHRASE",
                    path.display()
                ))
            })?;
            return key
                .decrypt(pw)
                .map_err(|e| Error::Auth(format!("cannot decrypt {}: {e}", path.display())));
        }
        Ok(key)
    }

    /// One usable line of an `allowed_signers` file.
    pub struct SignerEntry {
        principals: String,
        key: PublicKey,
        /// `namespaces="a,b"`; `None` means every namespace is allowed.
        namespaces: Option<Vec<String>>,
        valid_after: Option<SystemTime>,
        valid_before: Option<SystemTime>,
    }

    /// Verifier backed by an OpenSSH `allowed_signers` file.
    pub struct AllowedSigners {
        entries: Vec<SignerEntry>,
    }

    impl AllowedSigners {
        pub fn parse(text: &str) -> Result<Self> {
            let mut entries = Vec::new();
            let mut skipped = 0usize;
            for (n, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let n = n + 1;
                let tokens: Vec<&str> = line.split_whitespace().collect();
                let principals = tokens[0].to_string();
                // Everything between the principals and the key type is options.
                let Some(idx) = tokens
                    .iter()
                    .skip(1)
                    .position(|t| is_key_type(t))
                    .map(|i| i + 1)
                else {
                    return Err(Error::InvalidUrl(format!(
                        "allowed_signers line {n}: no key found"
                    )));
                };
                if tokens.len() < idx + 2 {
                    return Err(Error::InvalidUrl(format!(
                        "allowed_signers line {n}: truncated key"
                    )));
                }
                let key_text = tokens[idx..].join(" ");
                let key = PublicKey::from_openssh(&key_text)
                    .map_err(|e| Error::InvalidUrl(format!("allowed_signers line {n}: {e}")))?;

                let mut entry = SignerEntry {
                    principals,
                    key,
                    namespaces: None,
                    valid_after: None,
                    valid_before: None,
                };
                let mut is_ca = false;
                for (name, value) in split_options(&tokens[1..idx].join(" ")) {
                    match name.as_str() {
                        // A CA line delegates trust to certificates, which this
                        // program cannot check — never treat it as a plain key.
                        "cert-authority" => is_ca = true,
                        "namespaces" => {
                            entry.namespaces = Some(
                                value
                                    .unwrap_or_default()
                                    .split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect(),
                            )
                        }
                        "valid-after" => {
                            entry.valid_after = Some(parse_ssh_time(&value.unwrap_or_default())?)
                        }
                        "valid-before" => {
                            entry.valid_before = Some(parse_ssh_time(&value.unwrap_or_default())?)
                        }
                        other => {
                            tracing::warn!("allowed_signers line {n}: ignoring option '{other}'")
                        }
                    }
                }
                if is_ca {
                    tracing::warn!(
                        "allowed_signers line {n}: skipping cert-authority entry \
                         (certificate signatures are not supported)"
                    );
                    skipped += 1;
                    continue;
                }
                entries.push(entry);
            }
            if entries.is_empty() {
                return Err(Error::InvalidUrl(if skipped > 0 {
                    format!(
                        "allowed_signers: only cert-authority entries ({skipped}), no usable keys"
                    )
                } else {
                    "allowed_signers: no keys".into()
                }));
            }
            Ok(AllowedSigners { entries })
        }
    }

    /// Split an `allowed_signers` option list on commas outside quotes and
    /// return `(name, value)` pairs with the quotes removed.
    fn split_options(blob: &str) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        for c in blob.chars() {
            match c {
                '"' => quoted = !quoted,
                ',' if !quoted => {
                    out.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
        out.push(cur);
        out.into_iter()
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .map(|o| match o.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim().to_string())),
                None => (o.to_ascii_lowercase(), None),
            })
            .collect()
    }

    fn is_key_type(t: &str) -> bool {
        t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-")
    }

    impl Verifier for AllowedSigners {
        fn format(&self) -> SignFormat {
            SignFormat::Ssh
        }

        fn verify_at(&self, message: &[u8], signature: &[u8], at: SystemTime) -> Result<String> {
            let sig = SshSig::from_pem(signature)
                .map_err(|e| Error::Remote(format!("invalid SSH signature: {e}")))?;
            if sig.namespace() != SSH_NAMESPACE {
                return Err(Error::Remote(format!(
                    "SSH signature has namespace '{}', expected '{SSH_NAMESPACE}'",
                    sig.namespace()
                )));
            }
            let matching: Vec<&SignerEntry> = self
                .entries
                .iter()
                .filter(|e| e.key.key_data() == sig.public_key())
                .collect();
            if matching.is_empty() {
                let fp = PublicKey::from(sig.public_key().clone()).fingerprint(HashAlg::Sha256);
                return Err(Error::Auth(format!(
                    "signature made by {fp}, which is not in allowed_signers"
                )));
            }
            let mut why = Vec::new();
            for entry in matching {
                if let Some(ns) = &entry.namespaces
                    && !ns.iter().any(|n| n == SSH_NAMESPACE)
                {
                    why.push(format!(
                        "{}: key is limited to namespaces {}",
                        entry.principals,
                        ns.join(",")
                    ));
                    continue;
                }
                if let Some(after) = entry.valid_after
                    && at < after
                {
                    why.push(format!(
                        "{}: key is only valid after {}",
                        entry.principals,
                        fmt_time(after)
                    ));
                    continue;
                }
                if let Some(before) = entry.valid_before
                    && at >= before
                {
                    why.push(format!(
                        "{}: key expired at {}",
                        entry.principals,
                        fmt_time(before)
                    ));
                    continue;
                }
                entry
                    .key
                    .verify(SSH_NAMESPACE, message, &sig)
                    .map_err(|e| Error::Auth(format!("SSH signature invalid: {e}")))?;
                return Ok(format!(
                    "{} ({})",
                    entry.principals,
                    entry.key.fingerprint(HashAlg::Sha256)
                ));
            }
            Err(Error::Auth(format!(
                "signature rejected at {}: {}",
                fmt_time(at),
                why.join("; ")
            )))
        }
    }

    pub(super) fn load_verifier(path: &std::path::Path) -> Result<Arc<dyn Verifier>> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Auth(format!("cannot read {}: {e}", path.display())))?;
        Ok(Arc::new(AllowedSigners::parse(&text)?))
    }

    /// Signing through a running ssh-agent (the private key never leaves the agent).
    #[cfg(feature = "ssh")]
    pub mod agent {
        use super::*;
        use russh::keys::agent::AgentIdentity;
        use russh::keys::agent::client::AgentClient;
        use ssh_key::Signature;
        use tokio::sync::Mutex;

        pub struct AgentSigner {
            client: Mutex<AgentClient<tokio::net::UnixStream>>,
            identity: AgentIdentity,
            public: PublicKey,
        }

        impl AgentSigner {
            pub async fn connect() -> Result<Self> {
                let mut client = AgentClient::connect_env()
                    .await
                    .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
                let ids = client
                    .request_identities()
                    .await
                    .map_err(|e| Error::Auth(format!("ssh-agent: {e}")))?;
                let wanted = std::env::var("MPT_SIGN_KEY_FINGERPRINT")
                    .ok()
                    .or_else(|| crate::config::global().signing.agent_fingerprint.clone());
                let identity = ids
                    .into_iter()
                    .find(|id| match &wanted {
                        Some(fp) => id.public_key().fingerprint(HashAlg::Sha256).to_string() == *fp,
                        None => true,
                    })
                    .ok_or_else(|| Error::Auth("ssh-agent holds no (matching) identity".into()))?;
                let public = identity.public_key().into_owned();
                Ok(AgentSigner {
                    client: Mutex::new(client),
                    identity,
                    public,
                })
            }
        }

        #[async_trait]
        impl Signer for AgentSigner {
            fn format(&self) -> SignFormat {
                SignFormat::Ssh
            }
            fn identity(&self) -> String {
                format!("{} via ssh-agent", describe(&self.public))
            }
            async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                let data = SshSig::signed_data(SSH_NAMESPACE, HashAlg::Sha512, message)
                    .map_err(|e| Error::transport("sshsig", e))?;
                let raw = self
                    .client
                    .lock()
                    .await
                    .sign_request(&self.identity, None, data)
                    .await
                    .map_err(|e| Error::Auth(format!("ssh-agent sign: {e}")))?;
                let signature = Signature::try_from(raw.as_slice())
                    .map_err(|e| Error::transport("sshsig", e))?;
                let sig = SshSig::new(
                    self.public.key_data().clone(),
                    SSH_NAMESPACE,
                    HashAlg::Sha512,
                    signature,
                )
                .map_err(|e| Error::transport("sshsig", e))?;
                Ok(sig
                    .to_pem(LineEnding::LF)
                    .map_err(|e| Error::transport("sshsig", e))?
                    .into_bytes())
            }
        }
    }
}

#[cfg(not(feature = "sign-ssh"))]
mod ssh {
    use super::*;
    pub(super) async fn load(_: &SignSpec) -> Result<Arc<dyn Signer>> {
        Err(unsupported("OpenSSH", "sign-ssh"))
    }
    pub(super) fn load_verifier(_: &std::path::Path) -> Result<Arc<dyn Verifier>> {
        Err(unsupported("OpenSSH", "sign-ssh"))
    }
}

// ---------------------------------------------------------------------------
// OpenPGP backend (rPGP)
// ---------------------------------------------------------------------------

#[cfg(feature = "sign-pgp")]
pub mod pgp {
    use super::*;
    use ::pgp::composed::{
        ArmorOptions, Deserializable, DetachedSignature, SignedPublicKey, SignedSecretKey,
    };
    use ::pgp::crypto::hash::HashAlgorithm;
    use ::pgp::packet::{Signature, SignatureType};
    use ::pgp::types::{KeyDetails, Password};

    pub struct PgpSigner {
        key: SignedSecretKey,
        password: Password,
    }

    #[async_trait]
    impl Signer for PgpSigner {
        fn format(&self) -> SignFormat {
            SignFormat::Pgp
        }
        fn identity(&self) -> String {
            describe_secret(&self.key)
        }
        async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let sig = DetachedSignature::sign_binary_data(
                rand::thread_rng(),
                &self.key.primary_key,
                &self.password,
                HashAlgorithm::Sha256,
                message,
            )
            .map_err(|e| Error::transport("pgp", e))?;
            Ok(sig
                .to_armored_bytes(ArmorOptions::default())
                .map_err(|e| Error::transport("pgp", e))?)
        }
    }

    fn user_id(details: &::pgp::composed::SignedKeyDetails) -> String {
        details
            .users
            .first()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .unwrap_or_default()
    }

    fn describe_secret(key: &SignedSecretKey) -> String {
        format!(
            "{} {}",
            user_id(&key.details),
            key.primary_key.fingerprint()
        )
    }

    pub(super) fn load(spec: &SignSpec) -> Result<Arc<dyn Signer>> {
        let path = spec
            .key
            .as_ref()
            .ok_or_else(|| Error::invalid_option("sign", "pgp needs a key file"))?;
        let file = std::fs::File::open(path)
            .map_err(|e| Error::Auth(format!("cannot read {}: {e}", path.display())))?;
        let (key, _) = SignedSecretKey::from_armor_single(file).map_err(|e| {
            Error::Auth(format!(
                "{} is not an armored OpenPGP secret key: {e}",
                path.display()
            ))
        })?;
        let password = spec
            .passphrase
            .as_ref()
            .map(|p| Password::from(p.expose_secret()))
            .unwrap_or_else(Password::empty);
        // Fail early if the passphrase is wrong.
        key.primary_key
            .unlock(&password, |_, _| Ok(()))
            .map_err(|e| {
                Error::Auth(format!(
                    "cannot unlock {}: {e} (set MPT_SIGN_KEY_PASSPHRASE)",
                    path.display()
                ))
            })?
            .map_err(|e| Error::Auth(format!("cannot unlock {}: {e}", path.display())))?;
        Ok(Arc::new(PgpSigner { key, password }))
    }

    /// Verifier backed by a set of armored public keys.
    pub struct Keyring {
        keys: Vec<SignedPublicKey>,
    }

    impl Keyring {
        pub fn parse(bytes: &[u8]) -> Result<Self> {
            let (iter, _) = SignedPublicKey::from_armor_many(std::io::Cursor::new(bytes))
                .map_err(|e| Error::InvalidUrl(format!("keyring: {e}")))?;
            let parsed = iter
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidUrl(format!("keyring: {e}")))?;
            if parsed.is_empty() {
                return Err(Error::InvalidUrl("keyring: no public keys".into()));
            }
            // Only keys whose own self-signatures check out, and which have not
            // been revoked, are trusted.
            let mut keys = Vec::new();
            let mut dropped = 0usize;
            for key in parsed {
                let fp = key.primary_key.fingerprint();
                if let Err(e) = key.verify_bindings() {
                    tracing::warn!(
                        "keyring: ignoring {fp}, its self-signatures do not verify: {e}"
                    );
                    dropped += 1;
                    continue;
                }
                if !key.details.revocation_signatures.is_empty() {
                    tracing::warn!("keyring: ignoring revoked key {fp}");
                    dropped += 1;
                    continue;
                }
                keys.push(key);
            }
            if keys.is_empty() {
                return Err(Error::InvalidUrl(format!(
                    "keyring: no usable public keys ({dropped} revoked or unverifiable)"
                )));
            }
            Ok(Keyring { keys })
        }
    }

    /// Expiry of a key component: creation time plus the expiration subpacket
    /// of its newest self-signature.
    fn expiry_of<'a>(
        created: SystemTime,
        sigs: impl Iterator<Item = &'a Signature>,
    ) -> Option<SystemTime> {
        let mut newest: Option<(SystemTime, Duration)> = None;
        for sig in sigs {
            let Some(exp) = sig.key_expiration_time() else {
                continue;
            };
            let exp: Duration = exp.into();
            if exp.is_zero() {
                continue;
            }
            let made = sig.created().map(SystemTime::from).unwrap_or(UNIX_EPOCH);
            if newest.as_ref().is_none_or(|(t, _)| made >= *t) {
                newest = Some((made, exp));
            }
        }
        newest.map(|(_, exp)| created + exp)
    }

    fn revoked(sigs: &[Signature]) -> bool {
        sigs.iter().any(|s| {
            matches!(
                s.typ(),
                Some(SignatureType::KeyRevocation)
                    | Some(SignatureType::SubkeyRevocation)
                    | Some(SignatureType::CertRevocation)
            )
        })
    }

    /// `None` when the component was usable at `at`, otherwise the reason.
    fn invalid_at(
        created: SystemTime,
        expiry: Option<SystemTime>,
        at: SystemTime,
    ) -> Option<String> {
        if at < created {
            return Some(format!("key was only created at {}", fmt_time(created)));
        }
        match expiry {
            Some(exp) if at >= exp => Some(format!("key expired at {}", fmt_time(exp))),
            _ => None,
        }
    }

    impl Verifier for Keyring {
        fn format(&self) -> SignFormat {
            SignFormat::Pgp
        }

        fn verify_at(&self, message: &[u8], signature: &[u8], at: SystemTime) -> Result<String> {
            let (sig, _) = DetachedSignature::from_armor_single(std::io::Cursor::new(signature))
                .map_err(|e| Error::Remote(format!("invalid OpenPGP signature: {e}")))?;
            // The key must have been valid when the signature was made; a
            // signature that claims a future date is judged at `at`.
            let made = sig
                .signature
                .created()
                .map(SystemTime::from)
                .filter(|t| *t <= at)
                .unwrap_or(at);
            let issuers: Vec<String> = sig
                .signature
                .issuer_fingerprint()
                .iter()
                .map(|f| f.to_string())
                .collect();
            let issuer_ids: Vec<String> = sig
                .signature
                .issuer_key_id()
                .iter()
                .map(|k| k.to_string())
                .collect();
            let mut why: Vec<String> = Vec::new();
            for key in &self.keys {
                let self_sigs = || {
                    key.details
                        .direct_signatures
                        .iter()
                        .chain(key.details.users.iter().flat_map(|u| u.signatures.iter()))
                };
                // Primary key or any subkey that matches the issuer.
                let primary_matches = issuers
                    .iter()
                    .any(|f| *f == key.primary_key.fingerprint().to_string())
                    || issuer_ids
                        .iter()
                        .any(|k| *k == key.primary_key.legacy_key_id().to_string());
                if primary_matches {
                    let created = SystemTime::from(key.primary_key.created_at());
                    match invalid_at(created, expiry_of(created, self_sigs()), made) {
                        Some(reason) => {
                            why.push(format!("{}: {reason}", key.primary_key.fingerprint()))
                        }
                        None if sig.verify(key, message).is_ok() => {
                            return Ok(format!(
                                "{} {}",
                                user_id(&key.details),
                                key.primary_key.fingerprint()
                            ));
                        }
                        None => {}
                    }
                }
                for sub in &key.public_subkeys {
                    let m = issuers.iter().any(|f| *f == sub.fingerprint().to_string())
                        || issuer_ids
                            .iter()
                            .any(|k| *k == sub.legacy_key_id().to_string());
                    if !m {
                        continue;
                    }
                    if revoked(&sub.signatures) {
                        why.push(format!("subkey {} is revoked", sub.fingerprint()));
                        continue;
                    }
                    let created = SystemTime::from(sub.created_at());
                    if let Some(reason) =
                        invalid_at(created, expiry_of(created, sub.signatures.iter()), made)
                    {
                        why.push(format!("subkey {}: {reason}", sub.fingerprint()));
                        continue;
                    }
                    if sig.verify(sub, message).is_ok() {
                        return Ok(format!(
                            "{} {} (subkey {})",
                            user_id(&key.details),
                            key.primary_key.fingerprint(),
                            sub.fingerprint()
                        ));
                    }
                }
            }
            let who = issuers
                .first()
                .or(issuer_ids.first())
                .cloned()
                .unwrap_or_else(|| "unknown key".into());
            if why.is_empty() {
                return Err(Error::Auth(format!(
                    "OpenPGP signature by {who} is not valid for any key in the keyring"
                )));
            }
            Err(Error::Auth(format!(
                "OpenPGP signature by {who} rejected (signed {}): {}",
                fmt_time(made),
                why.join("; ")
            )))
        }
    }

    pub(super) fn load_verifier(path: &std::path::Path) -> Result<Arc<dyn Verifier>> {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::Auth(format!("cannot read {}: {e}", path.display())))?;
        Ok(Arc::new(Keyring::parse(&bytes)?))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn validity_window() {
            let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            let day = Duration::from_secs(86_400);
            assert!(invalid_at(t0, None, t0).is_none());
            assert!(invalid_at(t0, None, t0 + day).is_none());
            assert!(
                invalid_at(t0, None, t0 - Duration::from_secs(1))
                    .unwrap()
                    .contains("only created at")
            );
            assert!(invalid_at(t0, Some(t0 + day), t0 + Duration::from_secs(60)).is_none());
            assert!(
                invalid_at(t0, Some(t0 + day), t0 + day)
                    .unwrap()
                    .contains("expired at")
            );
        }
    }
}

#[cfg(not(feature = "sign-pgp"))]
mod pgp {
    use super::*;
    pub(super) fn load(_: &SignSpec) -> Result<Arc<dyn Signer>> {
        Err(unsupported("OpenPGP", "sign-pgp"))
    }
    pub(super) fn load_verifier(_: &std::path::Path) -> Result<Arc<dyn Verifier>> {
        Err(unsupported("OpenPGP", "sign-pgp"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_specs() {
        let s = SignSpec::parse("ssh").unwrap();
        assert_eq!(s.format, SignFormat::Ssh);
        assert!(s.key.is_none());
        let s = SignSpec::parse("ssh:/k/id_ed25519").unwrap();
        assert_eq!(s.key.as_deref().unwrap().to_str().unwrap(), "/k/id_ed25519");
        let s = SignSpec::parse("pgp:/k/sec.asc").unwrap();
        assert_eq!(s.format, SignFormat::Pgp);
        assert!(SignSpec::parse("pgp").is_err());
        assert!(SignSpec::parse("x509:/k").is_err());
        assert_eq!(SignFormat::Ssh.signature_name("a.sha256"), "a.sha256.sig");
        assert_eq!(SignFormat::Pgp.signature_name("a.b3"), "a.b3.asc");
    }

    /// Generate an OpenSSH key pair with `ssh-keygen`; `None` if it is not installed.
    #[cfg(feature = "sign-ssh")]
    fn keygen(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
        let path = dir.join(name);
        let out = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "alice@example.com",
                "-f",
            ])
            .arg(&path)
            .output()
            .ok()?;
        out.status.success().then_some(path)
    }

    #[cfg(feature = "sign-ssh")]
    #[tokio::test]
    async fn ssh_sign_and_verify_roundtrip() {
        use ssh_key::{HashAlg, LineEnding, PrivateKey};
        let dir = tempfile::tempdir().unwrap();
        let Some(key_path) = keygen(dir.path(), "id_ed25519") else {
            eprintln!("skipping: ssh-keygen not available");
            return;
        };
        let other_path = keygen(dir.path(), "other").unwrap();
        let pub_line = std::fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap();
        let signers = dir.path().join("allowed_signers");
        std::fs::write(
            &signers,
            format!("alice@example.com namespaces=\"file\" {}", pub_line),
        )
        .unwrap();

        let spec = SignSpec {
            format: SignFormat::Ssh,
            key: Some(key_path.clone()),
            passphrase: None,
        };
        let signer = load_signer(&spec).await.unwrap();
        assert!(
            signer.identity().contains("alice@example.com"),
            "{}",
            signer.identity()
        );
        let msg = b"deadbeef  report.pdf\n";
        let sig = signer.sign(msg).await.unwrap();
        assert!(sig.starts_with(b"-----BEGIN SSH SIGNATURE-----"));

        let verifier = load_verifier(&VerifySpec::SshAllowedSigners(signers.clone())).unwrap();
        let who = verifier.verify(msg, &sig).unwrap();
        assert!(who.starts_with("alice@example.com"), "{who}");
        assert!(verifier.verify(b"tampered", &sig).is_err());

        // A signature from a key that is not listed must be rejected.
        let other = PrivateKey::read_openssh_file(&other_path).unwrap();
        let other_sig = other
            .sign(SSH_NAMESPACE, HashAlg::Sha512, msg)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        assert!(verifier.verify(msg, other_sig.as_bytes()).is_err());

        // Interoperability: OpenSSH must accept our signature, and we must accept OpenSSH's.
        let sig_path = dir.path().join("msg.sig");
        std::fs::write(&sig_path, &sig).unwrap();
        let msg_path = dir.path().join("msg");
        std::fs::write(&msg_path, msg).unwrap();
        let out = std::process::Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&signers)
            .args(["-I", "alice@example.com", "-n", SSH_NAMESPACE, "-s"])
            .arg(&sig_path)
            .stdin(std::fs::File::open(&msg_path).unwrap())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ssh-keygen -Y verify failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let out = std::process::Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&key_path)
            .args(["-n", SSH_NAMESPACE])
            .arg(&msg_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ssh-keygen -Y sign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let theirs = std::fs::read(dir.path().join("msg.sig")).unwrap();
        assert!(
            verifier
                .verify(msg, &theirs)
                .unwrap()
                .starts_with("alice@example.com")
        );
    }

    #[test]
    fn passphrases_stay_out_of_debug_output() {
        let spec = SignSpec {
            format: SignFormat::Pgp,
            key: Some(PathBuf::from("/k/sec.asc")),
            passphrase: Some("letmein".into()),
        };
        let debug = format!("{spec:?}");
        assert!(!debug.contains("letmein"), "{debug}");
        assert_eq!(
            spec.passphrase.as_ref().map(|p| p.expose_secret()),
            Some("letmein")
        );
    }

    #[test]
    fn ssh_timestamps() {
        // 2024-02-29T12:30:45Z — leap day, so the civil-date maths is exercised.
        let t = parse_ssh_time("20240229123045").unwrap();
        assert_eq!(fmt_time(t), "2024-02-29T12:30:45Z");
        assert_eq!(
            fmt_time(parse_ssh_time("19700101").unwrap()),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            fmt_time(parse_ssh_time("20991231Z").unwrap()),
            "2099-12-31T00:00:00Z"
        );
        assert_eq!(
            fmt_time(parse_ssh_time("202412311800").unwrap()),
            "2024-12-31T18:00:00Z"
        );
        assert!(parse_ssh_time("20240229123045").unwrap() > parse_ssh_time("20240229").unwrap());
        for bad in [
            "",
            "2024",
            "20241301",
            "20240100",
            "2024123118",
            "20240101246000",
            "abcdefgh",
        ] {
            assert!(parse_ssh_time(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[cfg(feature = "sign-ssh")]
    #[tokio::test]
    async fn allowed_signers_options_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let Some(key_path) = keygen(dir.path(), "id_ed25519") else {
            eprintln!("skipping: ssh-keygen not available");
            return;
        };
        let pub_line = std::fs::read_to_string(dir.path().join("id_ed25519.pub")).unwrap();
        let pub_line = pub_line.trim().to_string();
        let msg = b"deadbeef  report.pdf\n";
        let signer = load_signer(&SignSpec {
            format: SignFormat::Ssh,
            key: Some(key_path),
            passphrase: None,
        })
        .await
        .unwrap();
        let sig = signer.sign(msg).await.unwrap();

        let verify = |line: &str| -> Result<String> {
            let f = dir.path().join("signers");
            std::fs::write(&f, format!("{line}\n")).unwrap();
            load_verifier(&VerifySpec::SshAllowedSigners(f))?.verify(msg, &sig)
        };

        // A window that contains today, and no options at all, both work.
        assert!(verify(&format!("alice {pub_line}")).is_ok());
        assert!(
            verify(&format!(
                "alice valid-after=\"20200101\",valid-before=\"20990101\" {pub_line}"
            ))
            .is_ok()
        );
        // Windows in the past or the future are refused.
        let e = verify(&format!("alice valid-before=\"20200101\" {pub_line}")).unwrap_err();
        assert!(e.to_string().contains("expired at 2020-01-01"), "{e}");
        let e = verify(&format!("alice valid-after=\"20990101\" {pub_line}")).unwrap_err();
        assert!(e.to_string().contains("only valid after 2099-01-01"), "{e}");
        // The namespace must include the one we sign in.
        let e = verify(&format!("alice namespaces=\"git,shell\" {pub_line}")).unwrap_err();
        assert!(e.to_string().contains("limited to namespaces"), "{e}");
        assert!(verify(&format!("alice namespaces=\"git,file\" {pub_line}")).is_ok());
        // Certificate authorities are not honoured as plain signing keys.
        let e = verify(&format!("alice cert-authority {pub_line}")).unwrap_err();
        assert!(e.to_string().contains("cert-authority"), "{e}");
        // …but they do not invalidate the rest of the file.
        assert!(verify(&format!("ca cert-authority {pub_line}\nalice {pub_line}")).is_ok());
        // Unknown options are ignored, not fatal.
        assert!(verify(&format!("alice verify-time=\"20240101\" {pub_line}")).is_ok());
    }

    #[cfg(feature = "sign-pgp")]
    #[tokio::test]
    async fn pgp_key_outside_its_validity_is_rejected() {
        use ::pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedPublicKey};
        use ::pgp::types::Timestamp;
        let created = SystemTime::now() + Duration::from_secs(3 * 86_400);
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .created_at(Timestamp::try_from(created).unwrap())
            .primary_user_id("Future <future@example.com>".to_string())
            .build()
            .unwrap();
        let secret = params.generate(rand::thread_rng()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sec_path = dir.path().join("sec.asc");
        std::fs::write(
            &sec_path,
            secret.to_armored_string(ArmorOptions::default()).unwrap(),
        )
        .unwrap();
        let public: SignedPublicKey = secret.clone().into();
        let pub_path = dir.path().join("pub.asc");
        std::fs::write(
            &pub_path,
            public.to_armored_string(ArmorOptions::default()).unwrap(),
        )
        .unwrap();

        let signer = load_signer(&SignSpec {
            format: SignFormat::Pgp,
            key: Some(sec_path),
            passphrase: None,
        })
        .await
        .unwrap();
        let msg = b"deadbeef  report.pdf\n";
        let sig = signer.sign(msg).await.unwrap();
        let verifier = load_verifier(&VerifySpec::PgpKeyring(pub_path)).unwrap();

        // The key claims to be created in three days, so nothing it signs is
        // acceptable today.
        let e = verifier.verify(msg, &sig).unwrap_err();
        assert!(e.to_string().contains("only created at"), "{e}");
    }

    /// A signature is judged against the moment it claims to have been made,
    /// capped at the verification time; before the key existed it is refused.
    #[cfg(feature = "sign-pgp")]
    #[tokio::test]
    async fn pgp_signature_before_key_creation_is_rejected() {
        use ::pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedPublicKey};
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .primary_user_id("Carol <carol@example.com>".to_string())
            .build()
            .unwrap();
        let secret = params.generate(rand::thread_rng()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sec_path = dir.path().join("sec.asc");
        std::fs::write(
            &sec_path,
            secret.to_armored_string(ArmorOptions::default()).unwrap(),
        )
        .unwrap();
        let public: SignedPublicKey = secret.clone().into();
        let pub_path = dir.path().join("pub.asc");
        std::fs::write(
            &pub_path,
            public.to_armored_string(ArmorOptions::default()).unwrap(),
        )
        .unwrap();

        let signer = load_signer(&SignSpec {
            format: SignFormat::Pgp,
            key: Some(sec_path),
            passphrase: None,
        })
        .await
        .unwrap();
        let msg = b"deadbeef  report.pdf\n";
        let sig = signer.sign(msg).await.unwrap();
        let verifier = load_verifier(&VerifySpec::PgpKeyring(pub_path)).unwrap();
        assert!(verifier.verify(msg, &sig).is_ok());

        let long_ago = SystemTime::now() - Duration::from_secs(10 * 86_400);
        let e = verifier.verify_at(msg, &sig, long_ago).unwrap_err();
        assert!(e.to_string().contains("only created at"), "{e}");
    }

    #[cfg(feature = "sign-pgp")]
    #[tokio::test]
    async fn pgp_sign_and_verify_roundtrip() {
        use ::pgp::composed::{ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedPublicKey};
        use ::pgp::types::Password;
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .primary_user_id("Bob <bob@example.com>".to_string())
            .build()
            .unwrap();
        let secret = params.generate(rand::thread_rng()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sec_path = dir.path().join("sec.asc");
        std::fs::write(
            &sec_path,
            secret.to_armored_string(ArmorOptions::default()).unwrap(),
        )
        .unwrap();
        let public: SignedPublicKey = secret.clone().into();
        let pub_path = dir.path().join("pub.asc");
        std::fs::write(
            &pub_path,
            public.to_armored_string(ArmorOptions::default()).unwrap(),
        )
        .unwrap();
        let _ = Password::empty();

        let spec = SignSpec {
            format: SignFormat::Pgp,
            key: Some(sec_path),
            passphrase: None,
        };
        let signer = load_signer(&spec).await.unwrap();
        assert!(signer.identity().contains("bob@example.com"));
        let msg = b"deadbeef  report.pdf\n";
        let sig = signer.sign(msg).await.unwrap();
        assert!(sig.starts_with(b"-----BEGIN PGP SIGNATURE-----"));

        let verifier = load_verifier(&VerifySpec::PgpKeyring(pub_path)).unwrap();
        let who = verifier.verify(msg, &sig).unwrap();
        assert!(who.contains("bob@example.com"), "{who}");
        assert!(verifier.verify(b"tampered", &sig).is_err());

        if std::process::Command::new("gpg")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            let home = dir.path().join("gnupg");
            std::fs::create_dir_all(&home).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let run = |args: &[&str]| {
                std::process::Command::new("gpg")
                    .arg("--homedir")
                    .arg(&home)
                    .args(["--batch", "--quiet"])
                    .args(args)
                    .output()
                    .unwrap()
            };
            let import = run(&["--import", dir.path().join("pub.asc").to_str().unwrap()]);
            assert!(
                import.status.success(),
                "gpg import: {}",
                String::from_utf8_lossy(&import.stderr)
            );
            std::fs::write(dir.path().join("msg"), msg).unwrap();
            std::fs::write(dir.path().join("msg.asc"), &sig).unwrap();
            let verify = run(&[
                "--verify",
                dir.path().join("msg.asc").to_str().unwrap(),
                dir.path().join("msg").to_str().unwrap(),
            ]);
            assert!(
                verify.status.success(),
                "gpg --verify failed: {}",
                String::from_utf8_lossy(&verify.stderr)
            );
        }
    }
}
