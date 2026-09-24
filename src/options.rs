//! The options a job may set — over the HTTP API, in a relay header, or
//! wherever a request carries a copy's settings as data rather than flags.

use serde::{Deserialize, Serialize};

use crate::transfer::{CacheMode, CopyOptions};
use crate::{Error, HashAlgo, Location, Result};

/// URL to location, with whatever the process adds (a default timeout,
/// `insecure`, a password from a flag). The job's options are there for
/// `timeout`.
pub type LocateFn = dyn Fn(&str, &JobOptions) -> Result<Location> + Send + Sync;

/// What a request may set per job. Everything is optional; what is not
/// given comes from the server's own settings (its flags and `[defaults]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct JobOptions {
    /// Transfers of this job in flight at once (a batch), capped by the
    /// server's `parallel`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel: Option<usize>,
    /// Stop the batch after the first failed transfer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    /// Checksum algorithm: `sha256`, `sha512`, `blake3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_existing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_source: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atomic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<bool>,
    /// Hold the payload in memory (needed for `retries`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// Inactivity timeout in seconds, `0` for none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// A source pattern that matches nothing is fine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_empty: Option<bool>,
    /// A directory source stands for every file below it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursive: Option<bool>,
}

impl JobOptions {
    /// Refuse what cannot work whatever the server's own settings are. What
    /// depends on them (retries without a memory cache, resuming without
    /// atomic transfers) is judged by [`JobOptions::apply`], on the options
    /// that result, so a job is accepted exactly when it can run.
    pub fn validate(&self) -> Result<()> {
        if self.parallel == Some(0) {
            return Err(Error::invalid_option("parallel", "must be at least 1"));
        }
        if let Some(h) = &self.hash {
            HashAlgo::parse(h).map_err(|e| Error::invalid_option("hash", e))?;
        }
        Ok(())
    }

    /// The options of a copy: the server's, with what the job set laid over.
    /// `cache_limit` bounds the memory cache when the job switches it on.
    pub fn apply(&self, base: &CopyOptions, cache_limit: u64) -> Result<CopyOptions> {
        self.validate()?;
        let mut out = base.clone();
        if let Some(h) = &self.hash {
            out.hash = Some(HashAlgo::parse(h).map_err(|e| Error::invalid_option("hash", e))?);
        }
        if let Some(v) = self.check {
            out.check = v;
        }
        if let Some(v) = self.skip_existing {
            out.skip_existing = v;
        }
        if let Some(v) = self.delete_source {
            out.delete_source = v;
        }
        if let Some(v) = self.atomic {
            out.atomic = v;
        }
        if let Some(v) = self.resume {
            out.resume = v;
        }
        match self.cache {
            Some(true) if out.cache == CacheMode::Stream => {
                out.cache = CacheMode::Memory { limit: cache_limit };
            }
            Some(false) => out.cache = CacheMode::Stream,
            _ => {}
        }
        if let Some(r) = self.retries {
            out.retries = r;
        }
        if let Some(t) = self.timeout {
            out.tee.send_timeout = (t > 0).then(|| std::time::Duration::from_secs(t));
        }
        if out.retries > 0 && out.cache == CacheMode::Stream {
            return Err(Error::invalid_option(
                "retries",
                "retries need the payload in memory: set cache = true",
            ));
        }
        if out.resume && !out.atomic {
            return Err(Error::invalid_option(
                "resume",
                "resuming needs atomic transfers (there is no partial file otherwise)",
            ));
        }
        // A signer wants a checksum; the job may not switch the hash off,
        // but the server's signer must not be left without one either.
        if out.sign.is_some() && out.hash.is_none() {
            out.hash = Some(HashAlgo::Sha256);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_checked_and_laid_over_the_base() {
        let base = CopyOptions::default();
        let opts: JobOptions = serde_json::from_str(
            r#"{"hash": "sha256", "cache": true, "retries": 2, "timeout": 0, "skip_existing": true}"#,
        )
        .unwrap();
        let copy = opts.apply(&base, 1024).unwrap();
        assert_eq!(copy.hash, Some(HashAlgo::Sha256));
        assert_eq!(copy.cache, CacheMode::Memory { limit: 1024 });
        assert_eq!(copy.retries, 2);
        assert!(copy.tee.send_timeout.is_none());
        assert!(copy.skip_existing);

        let bad: JobOptions = serde_json::from_str(r#"{"retries": 1}"#).unwrap();
        assert!(bad.apply(&base, 1024).is_err(), "retries without cache");
        let bad: JobOptions = serde_json::from_str(r#"{"resume": true, "atomic": false}"#).unwrap();
        assert!(bad.apply(&base, 1024).is_err());
        let bad: JobOptions = serde_json::from_str(r#"{"hash": "crc"}"#).unwrap();
        assert!(bad.validate().is_err());
        let bad: JobOptions = serde_json::from_str(r#"{"parallel": 0}"#).unwrap();
        assert!(bad.validate().is_err());
        assert!(serde_json::from_str::<JobOptions>(r#"{"colour": 1}"#).is_err());
    }

    /// Whether retries have their cache, and resuming its part file, is
    /// judged on the options that result: the server's own cache counts,
    /// and so does its own `--no-atomic`.
    #[test]
    fn the_effective_options_decide() {
        let cached = CopyOptions {
            cache: CacheMode::Memory { limit: 1024 },
            ..CopyOptions::default()
        };
        let retries: JobOptions = serde_json::from_str(r#"{"retries": 2}"#).unwrap();
        assert!(retries.validate().is_ok());
        assert_eq!(retries.apply(&cached, 1024).unwrap().retries, 2);
        let off: JobOptions = serde_json::from_str(r#"{"retries": 2, "cache": false}"#).unwrap();
        assert!(off.apply(&cached, 1024).is_err());

        let not_atomic = CopyOptions {
            atomic: false,
            ..CopyOptions::default()
        };
        let resume: JobOptions = serde_json::from_str(r#"{"resume": true}"#).unwrap();
        assert!(resume.apply(&not_atomic, 1024).is_err());
        assert!(resume.apply(&CopyOptions::default(), 1024).is_ok());
    }
}
