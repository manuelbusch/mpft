//! The relay server's `authorized_keys`: who may relay, from where, until
//! when, and whether with a forwarded agent.
//!
//! The file is OpenSSH's format. Of the per-key options, `from=` and
//! `expiry-time=` are honoured, `no-agent-forwarding` and `restrict` keep
//! the client's agent out (`agent-forwarding` after `restrict` lets it in
//! again), and the options that switch off what this server never offers
//! anyway (a pty, port and X11 forwarding, `~/.ssh/rc`) are taken as they
//! are. A key with any other option — `command=`, `permitopen=`,
//! `cert-authority`, … — is left out with a warning: it asks for a limit
//! the relay would not keep.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use russh::keys::PublicKey;
use tracing::{info, warn};

use crate::{Error, Result};

/// What a key in the file allows a login to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Grant {
    /// The client may forward its agent.
    pub agent_forwarding: bool,
}

/// One line of the file that may log in.
#[derive(Debug)]
struct AuthorizedKey {
    key: PublicKey,
    /// `from=`: the patterns the client's address has to match.
    from: Option<Vec<String>>,
    /// `expiry-time=`: not valid after this.
    expires: Option<SystemTime>,
    agent_forwarding: bool,
}

impl AuthorizedKey {
    fn grants(&self, key: &PublicKey, peer: IpAddr, now: SystemTime) -> Option<Grant> {
        if self.key.key_data() != key.key_data() {
            return None;
        }
        if self.expires.is_some_and(|t| now > t) {
            info!(fingerprint = %key.fingerprint(russh::keys::HashAlg::Sha256), "key in authorized_keys has expired");
            return None;
        }
        if let Some(patterns) = &self.from
            && !address_matches(patterns, peer)
        {
            info!(%peer, "key in authorized_keys is not valid from this address (from=)");
            return None;
        }
        Some(Grant {
            agent_forwarding: self.agent_forwarding,
        })
    }
}

/// The file, re-read whenever its content changes.
pub(super) struct Keys {
    path: PathBuf,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// A hash of the content the keys were read from.
    content: Option<blake3::Hash>,
    keys: Vec<AuthorizedKey>,
}

impl Keys {
    /// Read the file; a file that cannot be read is an error here, at
    /// start-up.
    pub fn new(path: &Path) -> Result<Keys> {
        let keys = Keys {
            path: path.to_path_buf(),
            state: Mutex::new(State::default()),
        };
        keys.reload()?;
        Ok(keys)
    }

    /// Read the file again and parse it when its content changed. The
    /// content is compared, not the time stamp: a file replaced within the
    /// same second, or with its old time put back, is still read anew.
    fn reload(&self) -> Result<()> {
        let text = std::fs::read(&self.path);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let text = match text {
            Ok(t) => t,
            Err(e) => {
                // Nobody may log in on the strength of a file that is gone.
                *state = State::default();
                return Err(Error::Config(format!(
                    "authorized_keys {}: {e}",
                    self.path.display()
                )));
            }
        };
        let hash = blake3::hash(&text);
        if state.content == Some(hash) {
            return Ok(());
        }
        let keys = parse(&String::from_utf8_lossy(&text), &self.path);
        info!(keys = keys.len(), path = %self.path.display(), "authorized_keys read");
        *state = State {
            content: Some(hash),
            keys,
        };
        Ok(())
    }

    /// What `key` may do when it logs in from `peer`; `None` when it may
    /// not log in at all.
    pub fn allows(&self, key: &PublicKey, peer: IpAddr) -> Option<Grant> {
        if let Err(e) = self.reload() {
            warn!("{e}; nobody may log in until it can be read again");
        }
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = SystemTime::now();
        state.keys.iter().find_map(|k| k.grants(key, peer, now))
    }
}

/// The keys of the file, each with its options. A line that cannot be
/// read, or that asks for what the relay does not do, is left out with a
/// warning.
fn parse(text: &str, path: &Path) -> Vec<AuthorizedKey> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok(key) => keys.push(key),
            Err(e) => warn!("{}:{}: key left out: {e}", path.display(), n + 1),
        }
    }
    keys
}

fn parse_line(line: &str) -> std::result::Result<AuthorizedKey, String> {
    // A line is `[options] keytype base64 [comment]`; the options are
    // there when the line does not start with the key.
    let (options, key) = match PublicKey::from_openssh(line) {
        Ok(key) => ("", key),
        Err(_) => {
            let end = options_end(line);
            let key = PublicKey::from_openssh(line[end..].trim_start())
                .map_err(|e| format!("not a public key: {e}"))?;
            (&line[..end], key)
        }
    };
    let mut entry = AuthorizedKey {
        key,
        from: None,
        expires: None,
        agent_forwarding: true,
    };
    for option in split_options(options)? {
        let (name, value) = match option.split_once('=') {
            Some((n, v)) => (n, Some(unquote(v)?)),
            None => (option, None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("from", Some(v)) => {
                let patterns: Vec<String> = v.split(',').map(|p| p.trim().to_string()).collect();
                for p in &patterns {
                    check_pattern(p)?;
                }
                entry.from = Some(patterns);
            }
            ("expiry-time", Some(v)) => {
                entry.expires = Some(
                    crate::sign::parse_ssh_time(&v)
                        .map_err(|_| format!("expiry-time=\"{v}\" is not YYYYMMDD[HHMM[SS]]"))?,
                );
            }
            ("restrict" | "no-agent-forwarding", None) => entry.agent_forwarding = false,
            ("agent-forwarding", None) => entry.agent_forwarding = true,
            // What they switch off (or, after `restrict`, on) this server
            // does not offer to anyone.
            (
                "no-port-forwarding" | "no-pty" | "no-x11-forwarding" | "no-user-rc"
                | "port-forwarding" | "pty" | "x11-forwarding" | "user-rc",
                None,
            ) => {}
            _ => return Err(format!("the option '{name}' is not supported by the relay")),
        }
    }
    Ok(entry)
}

/// Where the options end: at the first blank outside quotes.
fn options_end(line: &str) -> usize {
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return i,
            _ => {}
        }
    }
    line.len()
}

/// The options, split at the commas outside quotes.
fn split_options(options: &str) -> std::result::Result<Vec<&str>, String> {
    if options.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let (mut quoted, mut start) = (false, 0);
    for (i, c) in options.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&options[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if quoted {
        return Err("an option's quotes are not closed".into());
    }
    out.push(&options[start..]);
    Ok(out)
}

/// An option's value without its quotes; `\"` stands for a quote.
fn unquote(value: &str) -> std::result::Result<String, String> {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| format!("the value {value} is not in quotes"))?;
    Ok(inner.replace("\\\"", "\""))
}

/// A `from=` pattern this server can match: a wildcard pattern of an
/// address, or an address with a prefix length, optionally negated.
fn check_pattern(pattern: &str) -> std::result::Result<(), String> {
    let p = pattern.strip_prefix('!').unwrap_or(pattern);
    if p.is_empty() {
        return Err("an empty pattern in from=".into());
    }
    if p.contains('/') {
        cidr(p).ok_or_else(|| format!("from=: '{p}' is not an address/length"))?;
    }
    Ok(())
}

fn cidr(p: &str) -> Option<(IpAddr, u8)> {
    let (addr, len) = p.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((addr, len))
}

/// Whether `peer` matches the pattern list as sshd matches `from=` with
/// `UseDNS no`: against the address, never a name. A negated pattern that
/// matches refuses outright; otherwise one pattern has to match.
fn address_matches(patterns: &[String], peer: IpAddr) -> bool {
    let peer = peer.to_canonical();
    let text = peer.to_string();
    let mut matched = false;
    for pattern in patterns {
        let (negated, p) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern.as_str()),
        };
        let hit = match cidr(p) {
            Some((net, len)) => in_network(peer, net, len),
            None => wildcard(p.as_bytes(), text.as_bytes()),
        };
        if hit && negated {
            return false;
        }
        matched |= hit;
    }
    matched
}

fn in_network(addr: IpAddr, net: IpAddr, len: u8) -> bool {
    match (addr, net.to_canonical()) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// `*` for any run of characters, `?` for one, case-insensitive.
fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|i| wildcard(rest, &text[i..])),
        Some((&p, rest)) => match text.split_first() {
            Some((&t, text)) if p == b'?' || p.eq_ignore_ascii_case(&t) => wildcard(rest, text),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key() -> (PublicKey, String) {
        let key = super::super::sshd::generate_key().unwrap();
        let text = key.public_key().to_openssh().unwrap();
        (key.public_key().clone(), text)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn options_limit_where_from_and_how_long() {
        let (k, text) = key();
        let now = SystemTime::now();
        let one = |line: String| parse_line(&line).unwrap();

        let plain = one(format!("{text} comment with spaces"));
        assert_eq!(
            plain.grants(&k, ip("192.0.2.1"), now),
            Some(Grant {
                agent_forwarding: true
            })
        );
        // Options and no comment, which the ssh-key parser does not take.
        let from = one(format!(
            "from=\"10.0.0.0/8,!10.1.2.3,*.example,192.168.1.?\" {text}"
        ));
        assert!(from.grants(&k, ip("10.9.8.7"), now).is_some());
        assert!(from.grants(&k, ip("::ffff:10.9.8.7"), now).is_some());
        assert!(from.grants(&k, ip("10.1.2.3"), now).is_none());
        assert!(from.grants(&k, ip("192.168.1.5"), now).is_some());
        assert!(from.grants(&k, ip("192.168.1.50"), now).is_none());
        assert!(from.grants(&k, ip("192.0.2.1"), now).is_none());
        let v6 = one(format!("from=\"2001:db8::/32\" {text}"));
        assert!(v6.grants(&k, ip("2001:db8::1"), now).is_some());
        assert!(v6.grants(&k, ip("2001:db9::1"), now).is_none());

        let expiring = one(format!("expiry-time=\"20200101\",no-pty {text}"));
        assert!(expiring.grants(&k, ip("192.0.2.1"), now).is_none());
        let later = one(format!("expiry-time=\"20991231235959Z\" {text}"));
        assert!(later.grants(&k, ip("192.0.2.1"), now).is_some());
        assert!(
            later
                .grants(
                    &k,
                    ip("192.0.2.1"),
                    now + Duration::from_secs(100 * 365 * 86_400)
                )
                .is_none()
        );

        for (options, agent) in [
            ("no-agent-forwarding", false),
            ("restrict", false),
            ("restrict,agent-forwarding", true),
            ("no-port-forwarding,no-X11-forwarding", true),
        ] {
            let entry = one(format!("{options} {text}"));
            assert_eq!(
                entry
                    .grants(&k, ip("192.0.2.1"), now)
                    .unwrap()
                    .agent_forwarding,
                agent,
                "{options}"
            );
        }

        let (other, _) = key();
        assert!(plain.grants(&other, ip("192.0.2.1"), now).is_none());
    }

    #[test]
    fn a_key_with_an_option_the_relay_does_not_keep_is_left_out() {
        let (_, text) = key();
        for (line, what) in [
            (format!("command=\"mpt relay\" {text}"), "command"),
            (format!("permitopen=\"h:1\" {text}"), "permitopen"),
            (format!("cert-authority {text}"), "cert-authority"),
            (format!("from=\"10.0.0.0/99\" {text}"), "address/length"),
            (format!("expiry-time=\"soon\" {text}"), "expiry-time"),
            (format!("from=\"10.0.0.1 {text}"), "not a public key"),
            ("no-pty garbage".to_string(), "not a public key"),
        ] {
            let err = parse_line(&line).unwrap_err();
            assert!(err.contains(what), "{line}: {err}");
        }
    }

    #[test]
    fn the_file_is_read_again_on_any_change_and_its_loss_locks_everyone_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        let (a, a_text) = key();
        let (b, b_text) = key();
        let peer = ip("127.0.0.1");
        std::fs::write(&path, format!("{a_text}\n")).unwrap();
        let keys = Keys::new(&path).unwrap();
        assert!(keys.allows(&a, peer).is_some());
        assert!(keys.allows(&b, peer).is_none());

        // Replaced with the same length and the old time stamp put back.
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, format!("{b_text}\n")).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert!(keys.allows(&a, peer).is_none());
        assert!(keys.allows(&b, peer).is_some());

        std::fs::remove_file(&path).unwrap();
        assert!(keys.allows(&b, peer).is_none());
        std::fs::write(&path, format!("# back\n{b_text}\n")).unwrap();
        assert!(keys.allows(&b, peer).is_some());
    }
}
