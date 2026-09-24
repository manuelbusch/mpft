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
/// questions about the target at `index` (or its via), put to the client.
pub struct ChainAnswerer {
    pub broker: Arc<RemoteBroker>,
    pub index: usize,
    pub target: Location,
}

#[async_trait]
impl PasswordAnswerer for ChainAnswerer {
    async fn answer(&self, need: &Need) -> Result<Option<SecretString>> {
        // The far relay asks about its own dst 0, or the agent for it; here
        // that is the target at `index`.
        let who = match need.who {
            Who::Src | Who::Dst(_) => Who::Dst(self.index),
            Who::Via(_) => Who::Via(self.index),
        };
        self.broker.relay(who, need, &self.target).await
    }
}
