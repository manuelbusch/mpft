//! Which relay does what for one job.
//!
//! Every target, and the source, may have a relay: the one its profile
//! names, or for a target the default one (`--via`, `[defaults] via`).
//! The job is cut into parts along those lines. Targets without a relay
//! are written from here. Targets behind a relay are written by it: from
//! an upload when the source is read here, or from the relay's own read
//! of the source when the source is behind that relay as well — and
//! targets behind another relay then get their bytes from the first relay,
//! never through here. One relay session per relay, plus the local part.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::transfer::{FanoutReport, TargetReport};
use crate::{Error, Job, Location, Result};

/// The relays a job may go through.
#[derive(Debug, Clone, Default)]
pub struct ViaTable {
    /// The relay for targets whose profile names none.
    pub default: Option<Location>,
    /// The relay each profile names.
    pub by_profile: BTreeMap<String, Location>,
}

impl ViaTable {
    pub fn is_empty(&self) -> bool {
        self.default.is_none() && self.by_profile.is_empty()
    }

    /// The relay a target is written by, if any.
    pub fn for_target(&self, loc: &Location) -> Option<&Location> {
        loc.profile()
            .and_then(|p| self.by_profile.get(p))
            .or(self.default.as_ref())
    }

    /// The relay a source is read by, if any. The default relay does not
    /// count: the source is read here unless its own profile says so.
    pub fn for_source(&self, loc: &Location) -> Option<&Location> {
        loc.profile().and_then(|p| self.by_profile.get(p))
    }
}

/// One part of a job, with the targets it covers as indexes into the
/// job's list.
#[derive(Debug, Clone)]
pub enum Part {
    /// Read the source here, write these targets from here.
    Local { dsts: Vec<usize> },
    /// Read the source here, upload it once to `relay`, which writes these
    /// targets.
    Upload { relay: Location, dsts: Vec<usize> },
    /// `relay` reads the source itself and writes these targets: directly,
    /// or through the relay named for the target.
    Pull {
        relay: Location,
        dsts: Vec<(usize, Option<Location>)>,
    },
}

/// Relays compare by their URL; a location has no equality of its own.
impl PartialEq for Part {
    fn eq(&self, other: &Part) -> bool {
        let url = |l: &Location| l.unmasked();
        match (self, other) {
            (Part::Local { dsts: a }, Part::Local { dsts: b }) => a == b,
            (Part::Upload { relay: r, dsts: a }, Part::Upload { relay: s, dsts: b }) => {
                url(r) == url(s) && a == b
            }
            (Part::Pull { relay: r, dsts: a }, Part::Pull { relay: s, dsts: b }) => {
                url(r) == url(s)
                    && a.len() == b.len()
                    && a.iter().zip(b).all(|((i, v), (j, w))| {
                        i == j && v.as_ref().map(url) == w.as_ref().map(url)
                    })
            }
            _ => false,
        }
    }
}

impl Part {
    /// The indexes of the targets this part covers.
    pub fn indexes(&self) -> Vec<usize> {
        match self {
            Part::Local { dsts } | Part::Upload { dsts, .. } => dsts.clone(),
            Part::Pull { dsts, .. } => dsts.iter().map(|(i, _)| *i).collect(),
        }
    }
}

/// Cut `job` into parts. Targets keep their order within a part; parts
/// come in the order their first target has, the local one included.
pub fn plan(job: &Job, table: &ViaTable) -> Vec<Part> {
    // Targets grouped by relay, keyed by the relay as it prints (a masked
    // URL), in order of first appearance.
    let mut groups: Vec<(Option<Location>, Vec<usize>)> = Vec::new();
    for (i, dst) in job.dsts.iter().enumerate() {
        let via = table.for_target(dst).cloned();
        // Compared in full: the masked form would take two relays that
        // differ only in a secret option for one.
        let key = via.as_ref().map(Location::unmasked);
        match groups
            .iter_mut()
            .find(|(v, _)| v.as_ref().map(Location::unmasked) == key)
        {
            Some((_, dsts)) => dsts.push(i),
            None => groups.push((via, vec![i])),
        }
    }
    match table.for_source(&job.src) {
        None => groups
            .into_iter()
            .map(|(via, dsts)| match via {
                None => Part::Local { dsts },
                Some(relay) => Part::Upload { relay, dsts },
            })
            .collect(),
        Some(source_relay) => {
            let source_key = source_relay.unmasked();
            let mut parts = Vec::new();
            let mut pull: Vec<(usize, Option<Location>)> = Vec::new();
            for (via, dsts) in groups {
                match via {
                    None => parts.push(Part::Local { dsts }),
                    Some(relay) if relay.unmasked() == source_key => {
                        pull.extend(dsts.into_iter().map(|i| (i, None)));
                    }
                    Some(relay) => {
                        pull.extend(dsts.into_iter().map(|i| (i, Some(relay.clone()))));
                    }
                }
            }
            if !pull.is_empty() {
                pull.sort_by_key(|(i, _)| *i);
                let first = pull[0].0;
                let at = parts
                    .iter()
                    .position(|p| p.indexes().iter().all(|i| *i > first))
                    .unwrap_or(parts.len());
                parts.insert(
                    at,
                    Part::Pull {
                        relay: source_relay.clone(),
                        dsts: pull,
                    },
                );
            }
            parts
        }
    }
}

/// What one part came back with.
pub struct PartOutcome {
    pub indexes: Vec<usize>,
    pub result: Result<FanoutReport>,
}

/// One report for the job out of the parts' reports: the targets back in
/// the job's order, a part that failed as a whole failing each of its
/// targets, the bytes read the most any part read, the digests from the
/// first part that has them.
pub fn merge(job: &Job, parts: Vec<PartOutcome>, elapsed: Duration) -> FanoutReport {
    let mut targets: Vec<Option<TargetReport>> = (0..job.dsts.len()).map(|_| None).collect();
    let mut bytes_read = 0;
    let mut digests = Vec::new();
    let mut checked = None;
    let mut source_removed = None;
    for part in parts {
        match part.result {
            Ok(report) => {
                bytes_read = bytes_read.max(report.bytes_read);
                if digests.is_empty() {
                    digests = report.digests;
                }
                if checked.is_none() {
                    checked = report.checked;
                }
                if source_removed.is_none() {
                    source_removed = report.source_removed;
                }
                for (i, target) in part.indexes.into_iter().zip(report.targets) {
                    if let Some(slot) = targets.get_mut(i) {
                        *slot = Some(target);
                    }
                }
            }
            Err(e) => {
                for i in part.indexes {
                    if let Some(slot) = targets.get_mut(i) {
                        *slot = Some(TargetReport {
                            target: job.dsts[i].to_string(),
                            bytes: 0,
                            elapsed,
                            attempts: 1,
                            result: Err(same_kind(&e)),
                            sidecar: None,
                            signature: None,
                            skipped: false,
                        });
                    }
                }
            }
        }
    }
    let targets = targets
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            t.unwrap_or_else(|| TargetReport {
                target: job.dsts[i].to_string(),
                bytes: 0,
                elapsed,
                attempts: 0,
                result: Err(Error::Remote(
                    "no part of the job covered this target".into(),
                )),
                sidecar: None,
                signature: None,
                skipped: false,
            })
        })
        .collect();
    FanoutReport {
        source: job.src.to_string(),
        bytes_read,
        elapsed,
        targets,
        digests,
        checked,
        source_removed,
    }
}

/// An error of the same kind and message, for every target a failed part
/// stood for.
fn same_kind(e: &Error) -> Error {
    crate::report::error_from_json(&crate::report::error_json(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(url: &str, profile: Option<&str>) -> Location {
        let mut l = Location::parse(url).unwrap();
        if let Some(p) = profile {
            l.set_profile(p);
        }
        l
    }

    fn relay(name: &str) -> Location {
        Location::parse(&format!("ssh://{name}/")).unwrap()
    }

    fn table(default: Option<&str>, profiles: &[(&str, &str)]) -> ViaTable {
        ViaTable {
            default: default.map(relay),
            by_profile: profiles
                .iter()
                .map(|(p, r)| (p.to_string(), relay(r)))
                .collect(),
        }
    }

    #[test]
    fn without_relays_everything_is_local() {
        let job = Job {
            src: loc("/in/x", None),
            dsts: vec![loc("/a/", None), loc("sftp://h/b/", Some("b"))],
        };
        assert_eq!(
            plan(&job, &ViaTable::default()),
            vec![Part::Local { dsts: vec![0, 1] }]
        );
    }

    #[test]
    fn the_default_relay_takes_every_target_but_not_the_source() {
        let job = Job {
            src: loc("/in/x", None),
            dsts: vec![loc("/a/", None), loc("sftp://h/b/", Some("b"))],
        };
        assert_eq!(
            plan(&job, &table(Some("r"), &[])),
            vec![Part::Upload {
                relay: relay("r"),
                dsts: vec![0, 1]
            }]
        );
    }

    #[test]
    fn profiles_pick_their_relay_and_the_rest_stays_here() {
        // a via r1, b via r2, c plain, d via r1: three parts, in the order
        // of their first target.
        let job = Job {
            src: loc("/in/x", None),
            dsts: vec![
                loc("sftp://h/a/", Some("a")),
                loc("sftp://h/b/", Some("b")),
                loc("/c/", None),
                loc("sftp://h/d/", Some("d")),
            ],
        };
        let t = table(None, &[("a", "r1"), ("b", "r2"), ("d", "r1")]);
        assert_eq!(
            plan(&job, &t),
            vec![
                Part::Upload {
                    relay: relay("r1"),
                    dsts: vec![0, 3]
                },
                Part::Upload {
                    relay: relay("r2"),
                    dsts: vec![1]
                },
                Part::Local { dsts: vec![2] },
            ]
        );
        // With a default relay the plain target goes through it.
        let t = table(Some("r0"), &[("a", "r1"), ("b", "r2"), ("d", "r1")]);
        assert_eq!(
            plan(&job, &t)[2],
            Part::Upload {
                relay: relay("r0"),
                dsts: vec![2]
            }
        );
    }

    /// Two relays that differ only in a secret — the password, or an
    /// option that is masked when shown — are two relays, not one.
    #[test]
    fn relays_that_differ_only_in_a_secret_are_not_merged() {
        let job = Job {
            src: loc("/in/x", None),
            dsts: vec![
                loc("sftp://h/a/", Some("a")),
                loc("sftp://h/b/", Some("b")),
                loc("sftp://h/c/", Some("c")),
            ],
        };
        let t = table(
            None,
            &[
                ("a", "r:one@h"),
                ("b", "r:two@h"),
                ("c", "r@h/?passphrase=three"),
            ],
        );
        assert_eq!(t.by_profile["a"].to_string(), t.by_profile["b"].to_string());
        let parts = plan(&job, &t);
        assert_eq!(parts.len(), 3, "{parts:?}");
        assert_eq!(
            parts[1],
            Part::Upload {
                relay: relay("r:two@h"),
                dsts: vec![1]
            }
        );
    }

    #[test]
    fn a_source_behind_a_relay_is_pulled_and_chained() {
        // src via r1; a via r1 (direct), b via r2 (a hop from r1), c plain
        // (from here).
        let job = Job {
            src: loc("sftp://h/in/x", Some("src")),
            dsts: vec![
                loc("/c/", None),
                loc("sftp://h/a/", Some("a")),
                loc("sftp://h/b/", Some("b")),
            ],
        };
        let t = table(None, &[("src", "r1"), ("a", "r1"), ("b", "r2")]);
        assert_eq!(
            plan(&job, &t),
            vec![
                Part::Local { dsts: vec![0] },
                Part::Pull {
                    relay: relay("r1"),
                    dsts: vec![(1, None), (2, Some(relay("r2")))]
                },
            ]
        );
        // A default relay makes the plain target a hop as well: nothing
        // flows through here.
        let t = table(Some("r0"), &[("src", "r1"), ("a", "r1"), ("b", "r2")]);
        assert_eq!(
            plan(&job, &t),
            vec![Part::Pull {
                relay: relay("r1"),
                dsts: vec![(0, Some(relay("r0"))), (1, None), (2, Some(relay("r2")))]
            }]
        );
    }

    #[test]
    fn reports_merge_back_into_the_jobs_order() {
        let job = Job {
            src: loc("/in/x", None),
            dsts: vec![loc("/a/", None), loc("/b/", None), loc("/c/", None)],
        };
        let target = |name: &str, ok: bool| TargetReport {
            target: name.into(),
            bytes: 3,
            elapsed: Duration::ZERO,
            attempts: 1,
            result: if ok {
                Ok(())
            } else {
                Err(Error::Remote("no".into()))
            },
            sidecar: None,
            signature: None,
            skipped: false,
        };
        let report = |targets, bytes| FanoutReport {
            source: "x".into(),
            bytes_read: bytes,
            elapsed: Duration::ZERO,
            targets,
            digests: vec![(crate::HashAlgo::Sha256, "ab".into())],
            checked: None,
            source_removed: None,
        };
        let merged = merge(
            &job,
            vec![
                PartOutcome {
                    indexes: vec![1],
                    result: Ok(report(vec![target("/b/", true)], 5)),
                },
                PartOutcome {
                    indexes: vec![0, 2],
                    result: Err(Error::Auth("nope".into())),
                },
            ],
            Duration::from_millis(7),
        );
        assert_eq!(merged.source, "/in/x");
        assert_eq!(merged.bytes_read, 5);
        assert_eq!(merged.elapsed, Duration::from_millis(7));
        let names: Vec<&str> = merged.targets.iter().map(|t| t.target.as_str()).collect();
        assert_eq!(names, vec!["/a/", "/b/", "/c/"]);
        assert!(merged.targets[1].result.is_ok());
        assert!(matches!(merged.targets[0].result, Err(Error::Auth(_))));
        assert!(matches!(merged.targets[2].result, Err(Error::Auth(_))));
        assert_eq!(merged.digests.len(), 1);
        assert!(!merged.all_ok());
    }
}
