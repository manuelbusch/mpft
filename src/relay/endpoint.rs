//! A target behind another relay, as an [`Endpoint`] the copy writes to.
//!
//! When the relay that reads the source has a target behind a relay of
//! its own (a chain, R1 → R2), the copy on R1 writes that target through
//! a [`RelayEndpoint`]: a [`Sender`] that uploads the one file to R2 over
//! the relay protocol, the same way the client uploads to R1. R2's
//! questions come back to R1, which asks the client on R2's behalf — so
//! the password still comes from the client, and the client's forwarded
//! agent is offered on to R2.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use secrecy::SecretString;

use super::broker::{Need, PasswordAnswerer, RemoteBroker, Who};
use super::client::{self, Session};
use super::{Credentials, Header};
use crate::broker::AgentSource;
use crate::options::JobOptions;
use crate::{ByteStream, Endpoint, Error, Location, Receiver, Result, SendMeta, Sender, stream};

/// One target reached through a relay.
pub struct RelayEndpoint {
    /// The far target, as it prints (password masked).
    pub(super) target: Location,
    /// The relay to upload through.
    pub(super) relay: Location,
    /// This relay's `--max-size`, which bounds what is spooled; 0 for none.
    pub(super) max_size: u64,
    /// The far target's URL as the far relay should see it.
    pub(super) header_url: String,
    pub(super) credentials: Credentials,
    /// The options for the far relay's copy: this relay's own, minus what
    /// only the relay that reads the source can do.
    pub(super) options: JobOptions,
    pub(super) agent: Option<Arc<dyn AgentSource>>,
    pub(super) answerer: Arc<dyn PasswordAnswerer>,
    pub(super) cancel: CancellationToken,
}

impl Endpoint for RelayEndpoint {
    fn location(&self) -> &Location {
        &self.target
    }
    fn as_receiver(&self) -> Option<&dyn Receiver> {
        None
    }
    fn as_sender(&self) -> Option<&dyn Sender> {
        Some(self)
    }
}

#[async_trait]
impl Sender for RelayEndpoint {
    fn scheme_name(&self) -> String {
        self.target.scheme().to_string()
    }

    /// The far relay writes its own checksum file on the far side.
    fn places_sidecar(&self) -> bool {
        false
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let name = meta
            .filename
            .clone()
            .or_else(|| self.target.filename().map(String::from))
            .ok_or_else(|| Error::InvalidUrl(format!("{}: no file name to relay", self.target)))?;
        // The far relay needs the size up front: a source that does not
        // say it is spooled here first, no further than --max-size.
        let (body, size) = match meta.size {
            Some(n) => (body, n),
            None => {
                let body = match self.max_size {
                    0 => body,
                    limit => stream::boxed(stream::Limited::new(
                        body,
                        limit,
                        format!("the source is larger than this relay takes ({limit} bytes)"),
                    )),
                };
                let (file, n) = stream::spool_to_tempfile(body).await?;
                (stream::boxed(file), n)
            }
        };
        let header = Header {
            credentials: self.credentials,
            agent: self.agent.is_some(),
            options: self.options.clone(),
            ..Header::stream(name, size, vec![self.header_url.clone()])
        };
        let session = Session {
            via: &self.relay,
            header: &header,
            body: Some(body),
            cancel: &self.cancel,
            answer: Arc::clone(&self.answerer),
            agent: self.agent.clone(),
        };
        let outcome = client::send(session, |_| {}).await?;
        if let Some(err) = &outcome.error {
            return Err(crate::report::error_from_json(err));
        }
        let report = outcome
            .report
            .ok_or_else(|| Error::Remote("the chained relay ended with no report".into()))?;
        let report = crate::report::fanout_from_json(&report)?;
        match report.targets.into_iter().next() {
            Some(t) => t.result,
            None => Err(Error::Remote("the chained relay reported no target".into())),
        }
    }
}

/// The far relay's questions about its one target are this relay's
/// questions about the target at `index`, put to the client. The header
/// it was sent names that one target and nothing else — no source, no
/// relay behind it — so a question about anything else has no answer: it
/// could only be after another password, such as the one for the far
/// relay itself.
pub struct ChainAnswerer {
    pub broker: Arc<RemoteBroker>,
    pub index: usize,
    pub target: Location,
}

#[async_trait]
impl PasswordAnswerer for ChainAnswerer {
    async fn answer(&self, need: &Need) -> Result<Option<SecretString>> {
        match need.who {
            Who::Dst(0) => {
                self.broker
                    .relay(Who::Dst(self.index), need, &self.target)
                    .await
            }
            other => Err(Error::Auth(format!(
                "the chained relay asked for a password it has no use for ({other:?}); \
                 its header names one target and nothing else"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// Only the far relay's one target is asked about; a question about
    /// its source or a relay behind it is refused without asking the
    /// client.
    #[tokio::test]
    async fn the_far_relay_is_answered_about_its_target_only() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let broker = RemoteBroker::new(tx, CancellationToken::new());
        let answerer = ChainAnswerer {
            broker: Arc::clone(&broker),
            index: 3,
            target: Location::parse("ftp://u@far/in/").unwrap(),
        };
        let need = |who| Need {
            id: 1,
            who,
            target: "ftp://u@far/in/".into(),
            user: Some("u".into()),
            attempt: 1,
        };
        for who in [Who::Via(0), Who::Src, Who::Dst(1)] {
            let err = answerer.answer(&need(who)).await.unwrap_err();
            assert!(err.to_string().contains("no use for"), "{err}");
        }
        assert!(rx.try_recv().is_err(), "the client was asked");

        let asking = tokio::spawn(async move { answerer.answer(&need(Who::Dst(0))).await });
        let line = rx.recv().await.unwrap();
        let asked = Need::parse(&line).unwrap();
        assert_eq!(asked.who, Who::Dst(3));
        broker.answer(&serde_json::json!({ "password": { "id": asked.id, "value": "pw" } }));
        assert!(asking.await.unwrap().unwrap().is_some());
    }
}
