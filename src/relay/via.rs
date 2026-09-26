//! The client side of `via`: which relays take part in a job, and running
//! the job through them.
//!
//! [`Via`] holds the relays in play — the default one (`--via`) for every
//! target that has no relay of its own, and the one each profile names —
//! and cuts a job into parts along those lines (see [`super::plan`]). The
//! targets are resolved here, credentials included, so a relay needs no
//! configuration of its own, and the report comes back the way a copy from
//! here would have made it.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::plan::{self, Part, PartOutcome, ViaTable};
use super::{Credentials, Dst, Header, VERSION, agent, broker, client};
use crate::options::JobOptions;
use crate::transfer::{CacheMode, CopyOptions, FanoutReport};
use crate::{Error, Job, Location, Result, Scheme};

/// How the relays are used: the settings of `cp --via` and of
/// `[defaults]` that are not options of the copy itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct ViaSettings {
    /// Whether the targets' passwords travel in the header or are asked
    /// for at every login.
    pub credentials: Credentials,
    /// Forward an ssh-agent serving this side's keys for the SSH targets.
    pub agent: bool,
    /// Let the relay forward it on to the relay of a chained target.
    pub agent_onward: bool,
    /// The timeout in seconds the relay applies to its endpoints.
    pub timeout: u64,
}

/// The relays that copy instead of this process, and how they are used.
pub struct Via {
    table: ViaTable,
    /// What the header carries: the flags of this side that a relay can
    /// honour.
    options: JobOptions,
    /// Whether the targets' passwords travel in the header or are asked
    /// for at every login.
    credentials: Credentials,
    /// Forward an ssh-agent serving this side's keys for the SSH targets.
    agent: bool,
    /// Let the relay forward it on to the relay of a chained target.
    agent_onward: bool,
    /// An option that asks for what only this side has, if one is set: a
    /// job that a relay takes part in is refused with it.
    refused: Option<&'static str>,
}

impl Via {
    /// The relays in play: `default` (the `--via` of the command) and the
    /// relay of every profile in `used` (every profile when that is
    /// `None`), resolved with `locate`. `None` when there is none.
    ///
    /// A relay that is not an `ssh://` URL is refused with an
    /// [`Error::InvalidOption`] named `via`, whose reason names the
    /// setting (`--via`, `[profiles.<name>] via`).
    pub fn table(
        default: Option<&str>,
        used: Option<&BTreeSet<String>>,
        locate: &dyn Fn(&str) -> Result<Location>,
    ) -> Result<Option<ViaTable>> {
        let relay = |what: &str, url: &str| -> Result<Location> {
            let relay = locate(url)?;
            if relay.scheme() != Scheme::Ssh {
                return Err(Error::invalid_option(
                    "via",
                    format!("{what} needs an ssh:// URL (or a profile with one), not {relay}"),
                ));
            }
            Ok(relay)
        };
        let mut table = ViaTable::default();
        if let Some(url) = default {
            table.default = Some(relay("--via", url)?);
        }
        for (name, profile) in &crate::config::global().profiles {
            if used.is_some_and(|used| !used.contains(name)) {
                continue;
            }
            if let Some(url) = &profile.via {
                table
                    .by_profile
                    .insert(name.clone(), relay(&format!("[profiles.{name}] via"), url)?);
            }
        }
        Ok((!table.is_empty()).then_some(table))
    }

    pub fn new(table: ViaTable, opts: &CopyOptions, settings: &ViaSettings) -> Via {
        Via {
            table,
            refused: Via::refusal(opts),
            credentials: settings.credentials,
            agent: settings.agent,
            agent_onward: settings.agent_onward,
            options: JobOptions {
                hash: opts.hash.map(|h| h.name().to_string()),
                atomic: (!opts.atomic).then_some(false),
                skip_existing: opts.skip_existing.then_some(true),
                cache: matches!(opts.cache, CacheMode::Memory { .. }).then_some(true),
                retries: (opts.retries > 0).then_some(opts.retries),
                timeout: Some(settings.timeout),
                ..Default::default()
            },
        }
    }

    /// The first option of `opts` that asks for what only this side has
    /// — `check`, `resume` or `sign` — if one is set.
    pub fn refusal(opts: &CopyOptions) -> Option<&'static str> {
        [
            ("check", opts.check),
            ("resume", opts.resume),
            ("sign", opts.sign.is_some()),
        ]
        .into_iter()
        .find_map(|(name, set)| set.then_some(name))
    }

    /// Whether a relay takes part in `job`, or it is copied from here
    /// alone.
    pub fn relays(&self, job: &Job) -> bool {
        plan::plan(job, &self.table)
            .iter()
            .any(|p| !matches!(p, Part::Local { .. }))
    }

    /// Refuse a job that a relay takes part in when an option asks for
    /// what only this side has: an [`Error::InvalidOption`] named after
    /// the option.
    pub fn check(&self, job: &Job) -> Result<()> {
        self.check_with(job, self.refused)
    }

    /// [`Via::check`] with the options of this job rather than those the
    /// `Via` was made with (see [`Via::refusal`]).
    pub fn check_with(&self, job: &Job, refused: Option<&str>) -> Result<()> {
        match refused {
            Some(name) if self.relays(job) => Err(Error::invalid_option(
                name,
                format!(
                    "not available with a relay: it needs what only this side has \
                     (the checksum file, the source, the key), and a relay takes part in \
                     copying {}",
                    job.src
                ),
            )),
            _ => Ok(()),
        }
    }

    /// One job, its parts side by side: the targets without a relay from
    /// here, the rest through their relays, and one report as if the copy
    /// had run here.
    pub async fn run(&self, job: Job, copy: CopyOptions) -> (Job, Result<FanoutReport>) {
        let started = std::time::Instant::now();
        let parts = plan::plan(&job, &self.table);
        // A job no relay takes part in is copied here, as without relays.
        if parts.iter().all(|p| matches!(p, Part::Local { .. })) {
            let open = |loc: &Location| crate::protocols::open(loc.clone());
            let result = crate::batch::run_job(&job, &open, &copy).await;
            return (job, result);
        }
        // The source is deleted by whoever read it, once every target has
        // the file — which only the relay that reads it can know, and only
        // when it writes every target.
        if copy.delete_source && !matches!(parts.as_slice(), [Part::Pull { .. }]) {
            return (
                job,
                Err(Error::invalid_option(
                    "delete-source",
                    "with a relay, only when the source and every target are behind \
                     the relay that reads the source (a profile with `via`)",
                )),
            );
        }
        let open = |loc: &Location| crate::protocols::open(loc.clone());
        let running = parts.iter().enumerate().map(|(n, part)| {
            let job = &job;
            let copy = &copy;
            async move {
                let indexes = part.indexes();
                let dsts: Vec<Location> = indexes.iter().map(|i| job.dsts[*i].clone()).collect();
                // A pull carries each target with the relay it is written
                // from: none for the relay that reads the source itself.
                let hops: Vec<(Location, Option<Location>)> = match part {
                    Part::Pull { dsts, .. } => dsts
                        .iter()
                        .map(|(i, via)| (job.dsts[*i].clone(), via.clone()))
                        .collect(),
                    _ => Vec::new(),
                };
                // The bytes are counted once, by the first part.
                let mut copy = copy.clone();
                if n > 0 {
                    copy.progress = None;
                }
                let result = match part {
                    Part::Local { .. } => {
                        let local = Job {
                            src: job.src.clone(),
                            dsts,
                        };
                        crate::batch::run_job(&local, &open, &copy).await
                    }
                    Part::Upload { relay, .. } => self.send(relay, &job.src, &dsts, &copy).await,
                    Part::Pull { relay, .. } => self.pull(relay, &job.src, &hops, &copy).await,
                };
                PartOutcome { indexes, result }
            }
        });
        let outcomes = futures::future::join_all(running).await;
        let report = plan::merge(&job, outcomes, started.elapsed());
        (job, Ok(report))
    }

    /// The targets as the header carries them.
    fn header_targets(&self, dsts: &[Location]) -> Result<Vec<String>> {
        dsts.iter().map(|d| self.header_url(d)).collect()
    }

    /// An endpoint as the header carries it: every part encoded, the
    /// password left out when the relay is to ask for it, and the key
    /// files left out when the forwarded agent stands in for them.
    fn header_url(&self, loc: &Location) -> Result<String> {
        let mut loc = loc.clone();
        for opt in ["key", "cert", "passphrase"] {
            if loc.opt(opt).is_some() {
                if self.agent && loc.scheme().is_ssh() {
                    loc.remove_option(opt);
                    continue;
                }
                return Err(Error::invalid_option(
                    opt,
                    format!(
                        "{loc}: names a file on this machine, which the relay cannot read; \
                         let the relay use the forwarded agent (without --no-via-agent), \
                         give the target a password, or put the key on the relay"
                    ),
                ));
            }
        }
        match self.credentials {
            Credentials::Header => Ok(loc.unmasked()),
            Credentials::OnDemand => {
                // The store signs every request itself, so a key handed
                // out per login has nowhere to go.
                if loc.scheme() == Scheme::S3 && loc.password().is_some() {
                    return Err(Error::invalid_option(
                        "via-credentials",
                        format!(
                            "{loc}: an S3 key cannot be asked for on demand; use \
                             --via-credentials header for this target"
                        ),
                    ));
                }
                Ok(loc.without_password().unmasked())
            }
        }
    }

    /// The agent to offer for `endpoints`, when an SSH endpoint could use
    /// it, with the keys this side would have used for them.
    fn responder(&self, endpoints: &[Location]) -> Option<agent::Responder> {
        (self.agent && endpoints.iter().any(|d| d.scheme().is_ssh()))
            .then(|| agent::Responder::for_targets(endpoints))
    }

    /// The relay reads `src` itself and writes `dsts`; nothing of the
    /// file passes through here. With `delete_source` the relay removes
    /// the source once every target has it.
    async fn pull(
        &self,
        relay: &Location,
        src: &Location,
        hops: &[(Location, Option<Location>)],
        copy: &CopyOptions,
    ) -> Result<FanoutReport> {
        // A target with a relay of its own is handed on to it; the others
        // the pulling relay writes itself.
        let mut dst = Vec::with_capacity(hops.len());
        let mut everyone = vec![src.clone()];
        for (target, via) in hops {
            everyone.push(target.clone());
            match via {
                None => dst.push(Dst::Url(self.header_url(target)?)),
                Some(via) => {
                    everyone.push(via.clone());
                    dst.push(Dst::Via {
                        url: self.header_url(target)?,
                        via: self.header_url(via)?,
                    });
                }
            }
        }
        let responder = self.responder(&everyone);
        let mut options = self.options.clone();
        options.delete_source = copy.delete_source.then_some(true);
        let header = Header {
            v: VERSION,
            src: Some(self.header_url(src)?),
            name: None,
            size: None,
            dst,
            credentials: self.credentials,
            agent: responder.is_some(),
            agent_onward: responder.is_some()
                && self.agent_onward
                && hops.iter().any(|(_, via)| via.is_some()),
            options,
        };
        let cancel = copy.cancel.clone().unwrap_or_default();
        let session = client::Session {
            via: relay,
            header: &header,
            body: None,
            cancel: &cancel,
            answer: Arc::new(broker::JobAnswerer {
                src: Some(src.clone()),
                dsts: hops.iter().map(|(t, _)| t.clone()).collect(),
                vias: hops.iter().map(|(_, v)| v.clone()).collect(),
            }),
            agent: responder.map(|r| Arc::new(r) as Arc<dyn crate::broker::AgentSource>),
        };
        let mut report = self.outcome(session, copy).await?;
        report.source = src.to_string();
        Ok(report)
    }

    /// Run the session and turn what the relay said into a report, or
    /// into the error it refused with.
    async fn outcome(
        &self,
        session: client::Session<'_>,
        copy: &CopyOptions,
    ) -> Result<FanoutReport> {
        // The relay's progress is this side's when nothing is uploaded:
        // what it reports as read is added to the shared count.
        let counter = match (&copy.progress, session.body.is_none()) {
            (Some(p), true) => Some(p.counter()),
            _ => None,
        };
        let mut last = 0;
        let outcome = client::send(session, |line| {
            if let (Some(c), Some(read)) = (&counter, line["progress"]["read"].as_u64()) {
                c.fetch_add(
                    read.saturating_sub(last),
                    std::sync::atomic::Ordering::Relaxed,
                );
                last = read;
            }
        })
        .await?;
        for line in outcome.stderr.lines().filter(|l| !l.trim().is_empty()) {
            tracing::debug!("relay: {line}");
        }
        if let Some(err) = &outcome.error {
            return Err(crate::report::error_from_json(err));
        }
        let report = outcome.report.ok_or_else(|| {
            Error::Remote(format!(
                "the relay ended with exit {} and no report",
                outcome.exit
            ))
        })?;
        crate::report::fanout_from_json(&report)
    }

    /// Read `src` here and upload it once to `relay`, which writes `dsts`.
    async fn send(
        &self,
        relay: &Location,
        src: &Location,
        dsts: &[Location],
        copy: &CopyOptions,
    ) -> Result<FanoutReport> {
        let dst = self.header_targets(dsts)?;
        let name = src
            .filename()
            .ok_or_else(|| Error::InvalidUrl(format!("{src}: no file name to relay")))?
            .to_string();
        let source = crate::protocols::open(src.clone())?;
        let receiver = source.receiver()?;
        let size = receiver.size().await?;
        let stream = receiver.receive().await?;
        let (stream, size) = match size {
            Some(n) => (stream, n),
            None => {
                tracing::warn!(%name, "size unknown: spooling the source to a temporary file first");
                let (file, n) = crate::stream::spool_to_tempfile(stream).await?;
                (crate::stream::boxed(file), n)
            }
        };
        let responder = self.responder(dsts);
        let header = Header {
            credentials: self.credentials,
            agent: responder.is_some(),
            options: self.options.clone(),
            ..Header::stream(name, size, dst)
        };
        // The upload is what the progress line counts.
        let body: crate::ByteStream = match &copy.progress {
            Some(p) => {
                crate::stream::boxed(crate::stream::Counted::with_counter(stream, p.counter()))
            }
            None => stream,
        };
        let cancel = copy.cancel.clone().unwrap_or_default();
        let session = client::Session {
            via: relay,
            header: &header,
            body: Some(body),
            cancel: &cancel,
            answer: Arc::new(broker::JobAnswerer {
                src: None,
                dsts: dsts.to_vec(),
                vias: Vec::new(),
            }),
            agent: responder.map(|r| Arc::new(r) as Arc<dyn crate::broker::AgentSource>),
        };
        let mut report = self.outcome(session, copy).await?;
        // The relay knows the file by name only; here it is what was given.
        report.source = src.to_string();
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the relay is sent depends on the credential mode: the
    /// password in the URL, or no password at all.
    #[test]
    fn the_header_carries_passwords_only_when_asked_to() {
        let via = |credentials| Via {
            table: Default::default(),
            options: Default::default(),
            credentials,
            agent: false,
            agent_onward: false,
            refused: None,
        };
        let dsts = vec![
            Location::parse("ftp://u:s3cret@h/in/").unwrap(),
            Location::parse("/tmp/x/").unwrap(),
        ];
        let header = via(Credentials::Header).header_targets(&dsts).unwrap();
        assert_eq!(header, vec!["ftp://u:s3cret@h/in/", "/tmp/x/"]);
        let demand = via(Credentials::OnDemand).header_targets(&dsts).unwrap();
        assert_eq!(demand, vec!["ftp://u@h/in/", "/tmp/x/"]);

        let s3 = vec![Location::parse("s3://bucket/x?endpoint=http://h").unwrap()];
        assert!(via(Credentials::OnDemand).header_targets(&s3).is_ok());
        let mut keyed = s3.clone();
        keyed[0].set_password("k");
        let err = via(Credentials::OnDemand)
            .header_targets(&keyed)
            .unwrap_err();
        assert!(
            err.to_string().contains("--via-credentials header"),
            "{err}"
        );

        // A key file stays here: refused without the agent, dropped from
        // the URL with it.
        let keyed = vec![Location::parse("sftp://u@h/in/?key=/k&known_hosts=off").unwrap()];
        let err = via(Credentials::Header).header_targets(&keyed).unwrap_err();
        assert!(err.to_string().contains("--no-via-agent"), "{err}");
        let mut with_agent = via(Credentials::Header);
        with_agent.agent = true;
        assert_eq!(
            with_agent.header_targets(&keyed).unwrap(),
            vec!["sftp://u@h/in/?known_hosts=off"]
        );
    }

    #[test]
    fn a_relay_refuses_what_only_this_side_has() {
        let table = ViaTable {
            default: Some(Location::parse("ssh://relay@h/").unwrap()),
            ..Default::default()
        };
        let opts = CopyOptions {
            resume: true,
            ..Default::default()
        };
        let via = Via::new(table, &opts, &ViaSettings::default());
        let job = Job {
            src: Location::parse("/tmp/a").unwrap(),
            dsts: vec![Location::parse("/tmp/b/").unwrap()],
        };
        let err = via.check(&job).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidOption { name, reason }
                if name == "resume" && reason.starts_with("not available with a relay")),
            "{err}"
        );
        assert!(via.check_with(&job, None).is_ok());
    }
}
