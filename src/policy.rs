//! Process-wide security policy.
//!
//! The rules here must hold for every endpoint the process opens, not just
//! the one a caller happens to look at, so they live in a global rather than
//! in [`crate::Location`]. Defaults come from the environment; the `[policy]`
//! section of the configuration file replaces them (see
//! [`crate::config::install`]), and the CLI flags replace those; they are
//! kept as [`Overrides`] so that they survive the configuration being
//! installed again.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock, RwLock};

use tracing::warn;

use crate::{Error, Location, Result, Scheme};

/// The rules that hold for the whole process.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Credentials that would travel unencrypted are an error, not a warning.
    pub refuse_plaintext_auth: bool,
    /// `?insecure=true` is refused instead of switching certificate checks off.
    pub refuse_insecure_tls: bool,
    /// `--check` must verify a signature as well as the checksum.
    pub require_signature: bool,
    /// A configuration file with credentials that others can read is an
    /// error rather than a warning.
    pub strict_permissions: bool,
    /// How old a signature may be, judged against the signing time recorded
    /// in the checksum file. `None` puts no limit on it.
    pub max_signature_age: Option<std::time::Duration>,
    /// Default host-key policy for SSH (`strict`, `accept-new`, `off`).
    pub known_hosts: Option<String>,
}

impl Policy {
    /// The defaults, taken from the environment.
    pub fn from_env() -> Policy {
        Policy {
            refuse_plaintext_auth: env_flag("MPT_REFUSE_PLAINTEXT_AUTH"),
            ..Policy::default()
        }
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn slot() -> &'static RwLock<Policy> {
    static POLICY: OnceLock<RwLock<Policy>> = OnceLock::new();
    POLICY.get_or_init(|| RwLock::new(Policy::from_env()))
}

/// The policy in force. Cheap enough to call per endpoint.
pub fn policy() -> Policy {
    slot().read().map(|p| p.clone()).unwrap_or_default()
}

/// Rules the command line sets. They are kept apart from the policy and
/// laid over it whenever it is replaced, so a configuration installed
/// again later (for a job list's endpoints, for a server's submission)
/// cannot undo a flag.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// `--refuse-plaintext-auth`.
    pub refuse_plaintext_auth: Option<bool>,
}

impl Overrides {
    fn apply(&self, p: &mut Policy) {
        if let Some(v) = self.refuse_plaintext_auth {
            p.refuse_plaintext_auth = v;
        }
    }
}

fn overrides() -> &'static RwLock<Overrides> {
    static OVERRIDES: OnceLock<RwLock<Overrides>> = OnceLock::new();
    OVERRIDES.get_or_init(|| RwLock::new(Overrides::default()))
}

/// Replace the policy, usually with the `[policy]` section of the
/// configuration. The command line's [`Overrides`] still win.
pub fn set_policy(mut p: Policy) {
    if let Ok(o) = overrides().read() {
        o.apply(&mut p);
    }
    if let Ok(mut slot) = slot().write() {
        *slot = p;
    }
}

/// Set the command line's rules, which hold from now on over every
/// policy installed.
pub fn set_overrides(o: Overrides) {
    if let Ok(mut slot) = slot().write() {
        o.apply(&mut slot);
    }
    if let Ok(mut current) = overrides().write() {
        *current = o;
    }
}

/// Whether unprotected credentials are an error rather than a warning.
pub fn refuse_plaintext_auth() -> bool {
    policy().refuse_plaintext_auth
}

/// Override just that one rule (the `--refuse-plaintext-auth` flag), for
/// the rest of the process.
pub fn set_refuse_plaintext_auth(refuse: bool) {
    let mut o = overrides().read().map(|o| o.clone()).unwrap_or_default();
    o.refuse_plaintext_auth = Some(refuse);
    set_overrides(o);
}

/// Emit `message` at most once per process; the same warning would otherwise
/// repeat for every sidecar file and every target.
fn warn_once(key: String, message: &str) {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    if let Ok(mut set) = seen.lock()
        && set.insert(key)
    {
        warn!("{message}");
    }
}

/// What would be readable on the wire for this endpoint, if anything.
fn plaintext_exposure(loc: &Location) -> Option<&'static str> {
    let has_password = loc.password().is_some_and(|p| !p.is_empty());
    match loc.scheme() {
        Scheme::Ftp if has_password => Some("FTP without TLS sends the password unencrypted"),
        Scheme::Http | Scheme::WebDav if has_password && loc.username().is_some() => Some(
            "HTTP basic authentication over an unencrypted connection sends the password in the clear",
        ),
        // `mailto:` is judged on its resolved server, see protocols::mail.
        Scheme::Smtp if has_password && smtp_without_tls(loc) => {
            Some("SMTP without TLS sends the password unencrypted")
        }
        _ => None,
    }
}

fn smtp_without_tls(loc: &Location) -> bool {
    match loc.opt("tls").map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("none") | Some("off") | Some("false") => true,
        None => loc.port() == Some(25),
        _ => false,
    }
}

/// Check an endpoint before it is used: unprotected credentials, a password
/// that anyone with `ps` can read, and switched-off certificate checks.
///
/// Returns an error instead of warning where the policy says so.
pub fn check_credentials(loc: &Location) -> Result<()> {
    let policy = policy();
    if let Some(why) = plaintext_exposure(loc) {
        let where_ = format!("{}://{}", loc.scheme(), loc.host().unwrap_or(""));
        if policy.refuse_plaintext_auth {
            return Err(Error::Auth(format!(
                "{where_}: {why} (refused by policy; switch to the TLS variant of the \
                 scheme, or drop --refuse-plaintext-auth / MPT_REFUSE_PLAINTEXT_AUTH)"
            )));
        }
        warn_once(
            format!("plaintext:{where_}"),
            &format!("{where_}: {why}. Prefer the TLS variant of this scheme"),
        );
    }
    if policy.refuse_insecure_tls && loc.opt_bool("insecure")?.unwrap_or(false) {
        return Err(Error::Auth(format!(
            "{}: insecure=true would switch off certificate verification, \
             which policy.refuse_insecure_tls forbids",
            loc.masked()
        )));
    }
    if loc.password_in_url() {
        warn_once(
            format!("urlpassword:{}", loc.scheme()),
            "the password is in the URL, where the process list and the shell history \
             can read it. Use MPT_PASSWORD, --password-file or --password-stdin instead",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(u: &str) -> Location {
        Location::parse(u).unwrap()
    }

    /// The policy is global, so the tests that change it must not overlap.
    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn plaintext_cases() {
        assert!(plaintext_exposure(&loc("ftp://u:p@h/x")).is_some());
        assert!(plaintext_exposure(&loc("ftp://u@h/x")).is_none());
        assert!(plaintext_exposure(&loc("ftps://u:p@h/x")).is_none());
        assert!(plaintext_exposure(&loc("http://u:p@h/x")).is_some());
        assert!(plaintext_exposure(&loc("https://u:p@h/x")).is_none());
        assert!(plaintext_exposure(&loc("webdav://u:p@h/x")).is_some());
        assert!(plaintext_exposure(&loc("webdavs://u:p@h/x")).is_none());
        // A URL password without a user name is not basic auth.
        assert!(plaintext_exposure(&loc("http://:p@h/x")).is_none());
        assert!(plaintext_exposure(&loc("smtp://u:p@h:25/a@b.c")).is_some());
        assert!(plaintext_exposure(&loc("smtp://u:p@h:587/a@b.c?tls=none")).is_some());
        assert!(plaintext_exposure(&loc("smtp://u:p@h:587/a@b.c")).is_none());
        assert!(plaintext_exposure(&loc("sftp://u:p@h/x")).is_none());
    }

    #[test]
    fn url_passwords_are_recognized() {
        assert!(loc("ftp://u:p@h/x").password_in_url());
        assert!(!loc("ftp://u@h/x").password_in_url());
        let mut l = loc("ftp://u:p@h/x");
        l.set_password("other");
        assert!(
            !l.password_in_url(),
            "a password we injected is not in the URL"
        );
    }

    #[test]
    fn refusal_turns_the_warning_into_an_error() {
        let _guard = exclusive();
        let l = loc("ftp://u:p@h/x");
        set_refuse_plaintext_auth(true);
        let err = check_credentials(&l).unwrap_err().to_string();
        assert!(err.contains("unencrypted"), "{err}");
        set_refuse_plaintext_auth(false);
        assert!(check_credentials(&l).is_ok());
        set_overrides(Overrides::default());
    }

    /// A flag holds over a policy installed after it, as a configuration
    /// installed again for new endpoints does.
    #[test]
    fn a_flag_survives_a_new_policy() {
        let _guard = exclusive();
        set_refuse_plaintext_auth(true);
        set_policy(Policy::default());
        assert!(refuse_plaintext_auth());
        set_policy(Policy {
            refuse_insecure_tls: true,
            ..Policy::default()
        });
        assert!(refuse_plaintext_auth());
        assert!(
            policy().refuse_insecure_tls,
            "the rest comes from the policy"
        );
        set_overrides(Overrides::default());
        set_policy(Policy::default());
        assert!(!refuse_plaintext_auth());
    }

    #[test]
    fn insecure_tls_can_be_forbidden() {
        let _guard = exclusive();
        let l = loc("ftps://u@h/x?insecure=true");
        assert!(check_credentials(&l).is_ok());
        set_policy(Policy {
            refuse_insecure_tls: true,
            ..Policy::default()
        });
        let err = check_credentials(&l).unwrap_err().to_string();
        assert!(err.contains("refuse_insecure_tls"), "{err}");
        assert!(
            check_credentials(&loc("ftps://u@h/x")).is_ok(),
            "an endpoint that does not ask for it is unaffected"
        );
        set_policy(Policy::default());
    }
}
