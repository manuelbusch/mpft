//! Credentials fetched at the moment they are used.
//!
//! A [`Location`] carries the password it was given: from its URL, a profile
//! or a provider. Behind a relay it must not, because the relay is not meant
//! to hold it. Such a location carries [`Brokers`] instead: a
//! [`PasswordSource`] that is asked at every login and answers from
//! somewhere else (the client at the other end of the relay session), and an
//! [`AgentSource`] that opens a connection to an ssh-agent, wherever that
//! agent lives (`SSH_AUTH_SOCK`, or the agent channel the client forwarded).
//!
//! Brokers are invisible to `Display`, `Debug` and [`Location::unmasked`]:
//! they are a way to get a secret, never the secret itself.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Location, Result};

/// What a login says when it asks for its password.
pub struct PasswordRequest<'a> {
    /// The endpoint that is logging in, for the asking party to name it.
    pub target: &'a Location,
    /// 1 for the first login of this endpoint, counting up with every
    /// reconnect, so the asking party can tell a retry from a first attempt.
    pub attempt: u32,
}

/// Something that can produce the password for a login.
#[async_trait]
pub trait PasswordSource: Send + Sync {
    /// The password for this login, or `None` when there is none to give.
    async fn password(&self, req: &PasswordRequest<'_>) -> Result<Option<SecretString>>;
}

/// Both halves of an agent connection in one trait object.
pub trait AgentIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AgentIo for T {}

/// One open connection to an ssh-agent, speaking the agent protocol.
pub type AgentStream = Box<dyn AgentIo + Send + Unpin>;

/// Something that can open a connection to an ssh-agent.
#[async_trait]
pub trait AgentSource: Send + Sync {
    /// A fresh connection; every login opens its own.
    async fn open(&self) -> Result<AgentStream>;
}

/// The brokers a location carries, if any.
#[derive(Clone, Default)]
pub struct Brokers {
    pub password: Option<Arc<dyn PasswordSource>>,
    pub agent: Option<Arc<dyn AgentSource>>,
}

impl Brokers {
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.agent.is_none()
    }
}

impl fmt::Debug for Brokers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Brokers")
            .field("password", &self.password.is_some())
            .field("agent", &self.agent.is_some())
            .finish()
    }
}
