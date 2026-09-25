//! The client's ssh-agent for a relay session.
//!
//! The relay authenticates against the SSH targets, but the keys are on
//! the client, and they stay there: the client forwards an agent over the
//! session, and this is that agent. It answers `REQUEST_IDENTITIES` with
//! the keys the client would have used for the targets — the target's own
//! `?key=` (with its certificate), `[ssh] key`, `MPT_SSH_KEY`, the default
//! files in `~/.ssh` — plus whatever the client's real agent holds, and it
//! signs with the former and hands signing for the latter on. It signs
//! SSH logins only: data that is not a public-key authentication request
//! (an SSHSIG file signature, a git commit) is refused, so the relay can
//! log in with the keys while the session runs but sign nothing else with
//! them. Nothing else is served: a relay that asks to add, remove or lock
//! a key gets a failure.
//!
//! The bundled agent server of russh cannot be given keys up front and
//! ignores the RSA hash flags, so this is written out.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use russh::keys::ssh_encoding::{Decode, Encode};
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::{Certificate, HashAlg, Signature};
use russh::keys::{PrivateKey, load_secret_key, signature::Signer};
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tracing::{debug, warn};

use crate::broker::{AgentSource, AgentStream};
use crate::protocols::ssh::{SshConfig, agent};
use crate::{Error, Location, Result, Scheme};

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
/// `SSH_MSG_USERAUTH_REQUEST`, which the data of a login's signature
/// starts with (after the session id).
const USERAUTH_REQUEST: u8 = 50;
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;
/// The longest agent message taken in.
const MAX_MESSAGE: usize = 256 * 1024;

/// One key the responder signs with, under the blob the relay names it by:
/// the public key's, or the certificate's.
struct Identity {
    blob: Vec<u8>,
    key: Arc<PrivateKey>,
    comment: String,
}

/// The agent as an [`AgentSource`]: every `open` is a fresh in-memory
/// connection served by a task of its own.
pub struct Responder {
    identities: Vec<Identity>,
    /// Forward what is not ours to the local agent, when there is one.
    upstream: bool,
}

impl Responder {
    /// The keys the client would use for the SSH targets among `dsts`,
    /// each one's certificate beside it, and the default key files when
    /// a target names none. Keys that cannot be read (a passphrase the
    /// client does not have) are left out with a note in the log.
    pub fn for_targets(dsts: &[Location]) -> Responder {
        let mut responder = Responder {
            identities: Vec::new(),
            upstream: agent::available(),
        };
        let mut seen = std::collections::HashSet::new();
        for loc in dsts.iter().filter(|l| l.scheme().is_ssh()) {
            let Ok(cfg) = SshConfig::from_location(loc) else {
                continue;
            };
            let passphrase = cfg
                .key_passphrase
                .as_ref()
                .map(|p| p.expose_secret().to_string());
            match &cfg.key_file {
                Some(path) => {
                    if seen.insert(path.clone()) {
                        responder.add_file(path, cfg.cert_file.as_ref(), passphrase.as_deref());
                    }
                }
                None => {
                    if let Some(home) = dirs::home_dir() {
                        for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                            let path = home.join(".ssh").join(name);
                            if path.exists() && seen.insert(path.clone()) {
                                let cert = PathBuf::from(format!("{}-cert.pub", path.display()));
                                responder.add_file(
                                    &path,
                                    cert.exists().then_some(&cert),
                                    passphrase.as_deref(),
                                );
                            }
                        }
                    }
                }
            }
        }
        responder
    }

    /// How many identities of the client's own the responder serves.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    fn add_file(&mut self, path: &PathBuf, cert: Option<&PathBuf>, passphrase: Option<&str>) {
        let key = match load_secret_key(path, passphrase) {
            Ok(key) => Arc::new(key),
            Err(e) => {
                debug!(key = %path.display(), "not offered to the relay: {e}");
                return;
            }
        };
        let comment = path.display().to_string();
        if let Some(cert_path) = cert {
            match Certificate::read_file(cert_path) {
                Ok(cert) if cert.public_key() == key.public_key().key_data() => {
                    if let Ok(blob) = cert.to_bytes() {
                        self.identities.push(Identity {
                            blob,
                            key: Arc::clone(&key),
                            comment: format!("{comment} (certificate)"),
                        });
                    }
                }
                Ok(_) => warn!(
                    cert = %cert_path.display(),
                    "the certificate is not for {}; not offered to the relay",
                    path.display()
                ),
                Err(e) => warn!(cert = %cert_path.display(), "not offered to the relay: {e}"),
            }
        }
        if let Ok(blob) = key.public_key().to_bytes() {
            self.identities.push(Identity { blob, key, comment });
        }
    }

    /// The reply to one message; a `FAILURE` for anything not served.
    async fn reply(&self, message: &[u8]) -> Vec<u8> {
        match message.first() {
            Some(&REQUEST_IDENTITIES) => self.identities_answer().await,
            Some(&SIGN_REQUEST) if !is_login(&message[1..]) => {
                debug!("ssh-agent: refused to sign what is not an SSH login");
                vec![FAILURE]
            }
            Some(&SIGN_REQUEST) => match self.sign(&message[1..]).await {
                Ok(Some(response)) => response,
                Ok(None) if self.upstream => forward(message).await.unwrap_or_else(|e| {
                    debug!("ssh-agent upstream: {e}");
                    vec![FAILURE]
                }),
                Ok(None) => vec![FAILURE],
                Err(e) => {
                    debug!("ssh-agent sign: {e}");
                    vec![FAILURE]
                }
            },
            other => {
                debug!(kind = ?other, "ssh-agent request not served to a relay");
                vec![FAILURE]
            }
        }
    }

    async fn identities_answer(&self) -> Vec<u8> {
        let mut entries: Vec<(Vec<u8>, String)> = self
            .identities
            .iter()
            .map(|i| (i.blob.clone(), i.comment.clone()))
            .collect();
        if self.upstream {
            match forward(&[REQUEST_IDENTITIES]).await {
                Ok(answer) => match parse_identities(&answer) {
                    Ok(theirs) => entries.extend(theirs),
                    Err(e) => debug!("ssh-agent upstream identities: {e}"),
                },
                Err(e) => debug!("ssh-agent upstream: {e}"),
            }
        }
        let mut out = vec![IDENTITIES_ANSWER];
        let _ = (entries.len() as u32).encode(&mut out);
        for (blob, comment) in entries {
            let _ = blob.encode(&mut out);
            let _ = comment.encode(&mut out);
        }
        out
    }

    /// Sign with one of our own keys; `Ok(None)` when the blob is not ours.
    async fn sign(&self, body: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut r = body;
        let blob = Vec::<u8>::decode(&mut r).map_err(agent_err)?;
        let data = Vec::<u8>::decode(&mut r).map_err(agent_err)?;
        let flags = u32::decode(&mut r).map_err(agent_err)?;
        let Some(identity) = self.identities.iter().find(|i| i.blob == blob) else {
            return Ok(None);
        };
        let signature: Signature = match identity.key.key_data() {
            KeypairData::Rsa(rsa) => {
                let hash = if flags & RSA_SHA2_512 != 0 {
                    Some(HashAlg::Sha512)
                } else if flags & RSA_SHA2_256 != 0 {
                    Some(HashAlg::Sha256)
                } else {
                    None
                };
                Signer::try_sign(&(rsa, hash), &data)
            }
            other => Signer::try_sign(other, &data),
        }
        .map_err(|e| Error::Auth(format!("ssh-agent: signing: {e}")))?;
        let encoded = signature.encode_vec().map_err(agent_err)?;
        let mut out = vec![SIGN_RESPONSE];
        encoded.encode(&mut out).map_err(agent_err)?;
        debug!(key = %identity.comment, "signed for the relay");
        Ok(Some(out))
    }
}

#[async_trait]
impl AgentSource for Responder {
    async fn open(&self) -> Result<AgentStream> {
        // The task serving this connection needs the identities; an Arc of
        // the whole responder would need `open` to take `self: Arc<Self>`,
        // so the keys are shared through the parts.
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        let served = Responder {
            identities: self
                .identities
                .iter()
                .map(|i| Identity {
                    blob: i.blob.clone(),
                    key: Arc::clone(&i.key),
                    comment: i.comment.clone(),
                })
                .collect(),
            upstream: self.upstream,
        };
        tokio::spawn(async move {
            if let Err(e) = serve(served, theirs).await {
                debug!("ssh-agent for the relay: {e}");
            }
        });
        Ok(Box::new(mine))
    }
}

/// Serve one connection until it closes.
async fn serve(responder: Responder, mut stream: DuplexStream) -> std::io::Result<()> {
    loop {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("agent message of {len} bytes"),
            ));
        }
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await?;
        let reply = responder.reply(&message).await;
        stream
            .write_all(&(reply.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

/// One request to the local agent, its raw reply back.
async fn forward(message: &[u8]) -> Result<Vec<u8>> {
    let mut upstream = agent::connect_raw().await?;
    upstream
        .write_all(&(message.len() as u32).to_be_bytes())
        .await?;
    upstream.write_all(message).await?;
    upstream.flush().await?;
    let mut len = [0u8; 4];
    upstream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(Error::Auth(format!("ssh-agent: reply of {len} bytes")));
    }
    let mut reply = vec![0u8; len];
    upstream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// Whether a `SIGN_REQUEST` body asks for the signature of an SSH login
/// with the key it names (RFC 4252, section 7): the session id, then
/// `SSH_MSG_USERAUTH_REQUEST`, the user, the service, `publickey` (or
/// OpenSSH's host-bound variant), TRUE, the algorithm and that key.
fn is_login(body: &[u8]) -> bool {
    fn parse(body: &[u8]) -> Option<bool> {
        let mut r = body;
        let blob = Vec::<u8>::decode(&mut r).ok()?;
        let data = Vec::<u8>::decode(&mut r).ok()?;
        let mut d = data.as_slice();
        let session = Vec::<u8>::decode(&mut d).ok()?;
        let kind = u8::decode(&mut d).ok()?;
        let _user = Vec::<u8>::decode(&mut d).ok()?;
        let _service = Vec::<u8>::decode(&mut d).ok()?;
        let method = Vec::<u8>::decode(&mut d).ok()?;
        let signed = u8::decode(&mut d).ok()?;
        let _algorithm = Vec::<u8>::decode(&mut d).ok()?;
        let key = Vec::<u8>::decode(&mut d).ok()?;
        Some(
            !session.is_empty()
                && kind == USERAUTH_REQUEST
                && matches!(
                    method.as_slice(),
                    b"publickey" | b"publickey-hostbound-v00@openssh.com"
                )
                && signed != 0
                && key == blob,
        )
    }
    parse(body).unwrap_or(false)
}

/// The entries of an `IDENTITIES_ANSWER`.
fn parse_identities(answer: &[u8]) -> Result<Vec<(Vec<u8>, String)>> {
    let Some((&IDENTITIES_ANSWER, mut r)) = answer.split_first() else {
        return Err(Error::Auth("ssh-agent: no identities answer".into()));
    };
    let n = u32::decode(&mut r).map_err(agent_err)?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let blob = Vec::<u8>::decode(&mut r).map_err(agent_err)?;
        let comment = String::decode(&mut r).map_err(agent_err)?;
        out.push((blob, comment));
    }
    Ok(out)
}

fn agent_err(e: impl std::fmt::Display) -> Error {
    Error::Auth(format!("ssh-agent: {e}"))
}

impl Scheme {
    /// Whether the scheme authenticates over SSH.
    pub fn is_ssh(&self) -> bool {
        matches!(self, Scheme::Sftp | Scheme::Scp | Scheme::Ssh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::agent::client::AgentClient;
    use russh::keys::ssh_key::{Algorithm, LineEnding};

    fn responder_with(dir: &std::path::Path, key: PrivateKey, name: &str) -> Responder {
        let path = dir.join(name);
        key.write_openssh_file(&path, LineEnding::LF).unwrap();
        let loc = Location::parse(&format!("sftp://u@h/in/?key={}", path.display())).unwrap();
        let mut responder = Responder::for_targets(&[loc]);
        responder.upstream = false;
        responder
    }

    /// What a client signs to log in with `key`.
    fn login(key: &russh::keys::PublicKey) -> Vec<u8> {
        let mut data = Vec::new();
        vec![9u8; 32].encode(&mut data).unwrap();
        data.push(USERAUTH_REQUEST);
        "relay".encode(&mut data).unwrap();
        "ssh-connection".encode(&mut data).unwrap();
        "publickey".encode(&mut data).unwrap();
        data.push(1);
        key.algorithm().as_str().encode(&mut data).unwrap();
        key.to_bytes().unwrap().encode(&mut data).unwrap();
        data
    }

    /// Identities are listed, a login's signature verifies against the
    /// key, anything else is not signed, and anything that would change
    /// the agent is refused.
    #[tokio::test]
    async fn serves_identities_and_signatures_only() {
        let dir = tempfile::tempdir().unwrap();
        let key =
            PrivateKey::random(&mut super::super::sshd::OsRandom, Algorithm::Ed25519).unwrap();
        let responder = responder_with(dir.path(), key, "ed");
        assert_eq!(responder.len(), 1);
        let mut client = AgentClient::connect(responder.open().await.unwrap());
        let identities = client.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        let key = identities[0].public_key().into_owned();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);

        // A login's signature, checked with the public key.
        let data = login(&key);
        let signed = client
            .sign_request(&identities[0], None, data.clone())
            .await
            .unwrap();
        // sign_request appends the signature to the data, length-prefixed.
        let mut r = &signed[data.len() + 4..];
        let sig = Signature::decode(&mut r).unwrap();
        russh::keys::signature::Verifier::verify(&key, &data, &sig).unwrap();

        // Anything else is not signed: arbitrary bytes, a file signature,
        // a login with another key.
        let mut sshsig = b"SSHSIG".to_vec();
        "file".encode(&mut sshsig).unwrap();
        let other =
            PrivateKey::random(&mut super::super::sshd::OsRandom, Algorithm::Ed25519).unwrap();
        for data in [
            b"to sign".to_vec(),
            sshsig,
            login(other.public_key()),
            login(&key)[..40].to_vec(),
        ] {
            let err = client
                .sign_request(&identities[0], None, data)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("failure"), "{err}");
        }

        // Adding a key is not served.
        let stray =
            PrivateKey::random(&mut super::super::sshd::OsRandom, Algorithm::Ed25519).unwrap();
        let err = client.add_identity(&stray, &[]).await.unwrap_err();
        assert!(err.to_string().contains("failure"), "{err}");
    }

    /// RSA is signed with the hash the flags ask for, which is what the
    /// bundled agent server got wrong.
    #[tokio::test]
    async fn rsa_honours_the_hash_flags() {
        let dir = tempfile::tempdir().unwrap();
        // Generating an RSA key takes seconds in a debug build; this one is
        // a throwaway from the fixtures.
        let key =
            PrivateKey::from_openssh(include_str!("../../tests/fixtures/rsa_test_key")).unwrap();
        let responder = responder_with(dir.path(), key, "rsa");
        let mut client = AgentClient::connect(responder.open().await.unwrap());
        let identities = client.request_identities().await.unwrap();
        let key = identities[0].public_key().into_owned();
        let data = login(&key);
        for hash in [HashAlg::Sha256, HashAlg::Sha512] {
            let signed = client
                .sign_request(&identities[0], Some(hash), data.clone())
                .await
                .unwrap();
            let mut r = &signed[data.len() + 4..];
            let sig = Signature::decode(&mut r).unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            russh::keys::signature::Verifier::verify(&key, &data, &sig).unwrap();
        }
    }
}
