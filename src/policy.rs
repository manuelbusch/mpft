//! Process-wide security policy.
//!
//! Only one rule lives here for now: what to do when credentials would travel
//! unprotected. It is a global because it must hold for every endpoint the
//! process opens, not just the one a caller is looking at. A configuration
//! file will take it over later; until then it is `MPT_REFUSE_PLAINTEXT_AUTH`
//! and `--refuse-plaintext-auth`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use tracing::warn;

use crate::{Error, Location, Result, Scheme};

/// 0 = not resolved yet, 1 = warn only, 2 = refuse.
static REFUSE: AtomicU8 = AtomicU8::new(0);

/// Whether unprotected credentials are an error rather than a warning.
/// Defaults to the `MPT_REFUSE_PLAINTEXT_AUTH` environment variable.
pub fn refuse_plaintext_auth() -> bool {
    match REFUSE.load(Ordering::Relaxed) {
        0 => {
            let on = std::env::var("MPT_REFUSE_PLAINTEXT_AUTH")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            REFUSE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
        2 => true,
        _ => false,
    }
}

/// Override the environment default.
pub fn set_refuse_plaintext_auth(refuse: bool) {
    REFUSE.store(if refuse { 2 } else { 1 }, Ordering::Relaxed);
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

/// Check an endpoint before it is used: unprotected credentials, and a
/// password that anyone with `ps` can read.
///
/// Returns an error instead of warning when [`refuse_plaintext_auth`] is set.
pub fn check_credentials(loc: &Location) -> Result<()> {
    if let Some(why) = plaintext_exposure(loc) {
        let where_ = format!("{}://{}", loc.scheme(), loc.host().unwrap_or(""));
        if refuse_plaintext_auth() {
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
    if loc.password_in_url() {
        warn_once(
            format!("urlpassword:{}", loc.scheme()),
            "the password stands in the URL, where the process list and the shell history \
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
        let l = loc("ftp://u:p@h/x");
        set_refuse_plaintext_auth(true);
        let err = check_credentials(&l).unwrap_err().to_string();
        assert!(err.contains("unencrypted"), "{err}");
        set_refuse_plaintext_auth(false);
        assert!(check_credentials(&l).is_ok());
    }
}
