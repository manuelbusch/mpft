//! Passwords asked for over the session: the relay's [`RemoteBroker`]
//! writes a `need` line and waits for the client's answer, the client's
//! [`PasswordAnswerer`] produces that answer.
//!
//! A target is named by its index in the header's `dst` list (or as the
//! source), never by its URL: exact, and something a relay in a chain can
//! translate for the relay behind it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::broker::{PasswordRequest, PasswordSource};
use crate::{Error, Location, Result};

/// Which endpoint of the header a request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Src,
    Dst(usize),
    /// The relay the target at this index is reached through.
    Via(usize),
}

/// A `need` line: what the relay asks for.
#[derive(Debug, Clone)]
pub struct Need {
    pub id: u64,
    pub who: Who,
    /// The target as the relay shows it, password masked.
    pub target: String,
    pub user: Option<String>,
    pub attempt: u32,
}

impl Need {
    /// The request in a `{"need": "password", …}` line, if that is one.
    pub fn parse(value: &Value) -> Option<Need> {
        if value.get("need")?.as_str()? != "password" {
            return None;
        }
        let who = match (
            value.get("dst").and_then(Value::as_u64),
            value.get("via").and_then(Value::as_u64),
        ) {
            (Some(i), _) => Who::Dst(i as usize),
            (None, Some(i)) => Who::Via(i as usize),
            (None, None) if value.get("src").and_then(Value::as_bool) == Some(true) => Who::Src,
            (None, None) => return None,
        };
        Some(Need {
            id: value.get("id")?.as_u64()?,
            who,
            target: value
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            user: value.get("user").and_then(Value::as_str).map(String::from),
            attempt: value.get("attempt").and_then(Value::as_u64).unwrap_or(1) as u32,
        })
    }

    fn to_line(&self) -> Value {
        let mut line = json!({
            "need": "password",
            "id": self.id,
            "target": self.target,
            "attempt": self.attempt,
        });
        match self.who {
            Who::Src => line["src"] = json!(true),
            Who::Dst(i) => line["dst"] = json!(i),
            Who::Via(i) => line["via"] = json!(i),
        }
        if let Some(user) = &self.user {
            line["user"] = json!(user);
        }
        line
    }
}

/// The client's answer to a `need`, as a control frame's JSON.
pub fn answer_line(id: u64, answer: &Result<Option<SecretString>>) -> Value {
    match answer {
        Ok(Some(pw)) => json!({ "password": { "id": id, "value": pw.expose_secret() } }),
        Ok(None) => json!({ "password": { "id": id } }),
        Err(e) => json!({ "password": { "id": id, "error": e.to_string() } }),
    }
}

/// Something on the client's side that answers the relay's requests.
#[async_trait]
pub trait PasswordAnswerer: Send + Sync {
    /// The password for this request; `None` when there is none, which
    /// the target then does without.
    async fn answer(&self, need: &Need) -> Result<Option<SecretString>>;
}

/// Answers from the job's own locations: the profile's password, the
/// provider's, the flag's — whatever the client resolved before it sent
/// the job on without them.
pub struct JobAnswerer {
    pub src: Option<Location>,
    pub dsts: Vec<Location>,
    /// The relay of each target, where a target has one of its own.
    pub vias: Vec<Option<Location>>,
}

#[async_trait]
impl PasswordAnswerer for JobAnswerer {
    async fn answer(&self, need: &Need) -> Result<Option<SecretString>> {
        let loc = match need.who {
            Who::Src => self.src.as_ref(),
            Who::Dst(i) => self.dsts.get(i),
            Who::Via(i) => self.vias.get(i).and_then(Option::as_ref),
        }
        .ok_or_else(|| {
            Error::Remote(format!(
                "the relay asked for the password of a target this job does not have ({:?})",
                need.who
            ))
        })?;
        debug!(target = %loc, attempt = need.attempt, "password asked for by the relay");
        loc.login_password(need.attempt).await
    }
}

/// Answers nothing: for sessions that sent every password in the header.
pub struct NoAnswer;

#[async_trait]
impl PasswordAnswerer for NoAnswer {
    async fn answer(&self, need: &Need) -> Result<Option<SecretString>> {
        Err(Error::Auth(format!(
            "the relay asked for a password ({}), but this side sends none on demand",
            need.target
        )))
    }
}

/// The relay's end: hands out a [`PasswordSource`] per target that asks
/// the client through the session and waits for the answer.
pub struct RemoteBroker {
    lines: mpsc::UnboundedSender<Value>,
    cancel: CancellationToken,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    pending: HashMap<u64, oneshot::Sender<Result<Option<SecretString>>>>,
    closed: bool,
}

impl RemoteBroker {
    /// `lines` is where the `need` lines go; `cancel` ends every wait.
    pub fn new(
        lines: mpsc::UnboundedSender<Value>,
        cancel: CancellationToken,
    ) -> Arc<RemoteBroker> {
        Arc::new(RemoteBroker {
            lines,
            cancel,
            state: Mutex::new(State::default()),
        })
    }

    /// A source for the target at `index` of the header.
    pub fn for_dst(self: &Arc<Self>, index: usize) -> Arc<dyn PasswordSource> {
        Arc::new(Remote {
            broker: Arc::clone(self),
            who: Who::Dst(index),
        })
    }

    /// A source for the header's `src`.
    pub fn for_src(self: &Arc<Self>) -> Arc<dyn PasswordSource> {
        Arc::new(Remote {
            broker: Arc::clone(self),
            who: Who::Src,
        })
    }

    /// A source for the relay of the target at `index`.
    pub fn for_via(self: &Arc<Self>, index: usize) -> Arc<dyn PasswordSource> {
        Arc::new(Remote {
            broker: Arc::clone(self),
            who: Who::Via(index),
        })
    }

    /// Ask on behalf of a relay further along: its request about its
    /// target `j` is this relay's request about `who`.
    pub async fn relay(
        &self,
        who: Who,
        need: &Need,
        target: &Location,
    ) -> Result<Option<SecretString>> {
        let need = Need {
            id: 0,
            who,
            target: need.target.clone(),
            user: need.user.clone(),
            attempt: need.attempt,
        };
        let timeout = target
            .timeout_or(Duration::from_secs(30))
            .unwrap_or(Duration::from_secs(30));
        self.ask_within(need, timeout).await
    }

    /// Take in a control frame from the client. Anything that is not a
    /// password answer is logged and dropped.
    pub fn answer(&self, value: &Value) {
        let Some(answer) = value.get("password") else {
            debug!("relay: control frame without a password: {value}");
            return;
        };
        let Some(id) = answer.get("id").and_then(Value::as_u64) else {
            debug!("relay: password answer without an id");
            return;
        };
        let result = if let Some(e) = answer.get("error").and_then(Value::as_str) {
            Err(Error::Auth(format!("the client has no password: {e}")))
        } else {
            Ok(answer
                .get("value")
                .and_then(Value::as_str)
                .map(SecretString::from))
        };
        let waiter = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .remove(&id);
        match waiter {
            Some(tx) => {
                let _ = tx.send(result);
            }
            None => debug!(id, "relay: password answer nobody waits for"),
        }
    }

    /// The client is gone: every open request fails, and no new one is
    /// sent.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        for (_, tx) in state.pending.drain() {
            let _ = tx.send(Err(Error::Cancelled));
        }
    }

    async fn ask_within(&self, mut need: Need, timeout: Duration) -> Result<Option<SecretString>> {
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                return Err(Error::Cancelled);
            }
            state.next_id += 1;
            need.id = state.next_id;
            state.pending.insert(need.id, tx);
        }
        let id = need.id;
        if self.lines.send(need.to_line()).is_err() {
            self.forget(id);
            return Err(Error::Cancelled);
        }
        tokio::select! {
            () = self.cancel.cancelled() => {
                self.forget(id);
                Err(Error::Cancelled)
            }
            () = tokio::time::sleep(timeout) => {
                self.forget(id);
                Err(Error::Auth(format!(
                    "no password from the client within {}s",
                    timeout.as_secs()
                )))
            }
            r = rx => r.unwrap_or(Err(Error::Cancelled)),
        }
    }

    fn forget(&self, id: u64) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .remove(&id);
    }
}

/// One target's view of the broker.
struct Remote {
    broker: Arc<RemoteBroker>,
    who: Who,
}

#[async_trait]
impl PasswordSource for Remote {
    async fn password(&self, req: &PasswordRequest<'_>) -> Result<Option<SecretString>> {
        let need = Need {
            id: 0,
            who: self.who,
            target: req.target.to_string(),
            user: req.target.username().map(String::from),
            attempt: req.attempt,
        };
        let timeout = req
            .target
            .timeout_or(Duration::from_secs(30))
            .unwrap_or(Duration::from_secs(30));
        debug!(target = %req.target, attempt = req.attempt, "asking the client for the password");
        self.broker.ask_within(need, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_need_is_written_and_its_answer_delivered() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let broker = RemoteBroker::new(tx, CancellationToken::new());
        let source = broker.for_dst(2);
        let target = Location::parse("ftp://u@h/in/").unwrap();
        let asking = {
            let source = source.clone();
            let target = target.clone();
            tokio::spawn(async move {
                source
                    .password(&PasswordRequest {
                        target: &target,
                        attempt: 3,
                    })
                    .await
            })
        };
        let line = rx.recv().await.unwrap();
        let need = Need::parse(&line).unwrap();
        assert_eq!(need.who, Who::Dst(2));
        assert_eq!(need.attempt, 3);
        assert_eq!(need.user.as_deref(), Some("u"));
        assert_eq!(need.target, "ftp://u@h/in/");
        broker.answer(&json!({ "password": { "id": need.id, "value": "s3cret" } }));
        let pw = asking.await.unwrap().unwrap().unwrap();
        assert_eq!(pw.expose_secret(), "s3cret");

        // No value: no password, which is not an error.
        let asking = {
            let source = source.clone();
            let target = target.clone();
            tokio::spawn(async move {
                source
                    .password(&PasswordRequest {
                        target: &target,
                        attempt: 1,
                    })
                    .await
            })
        };
        let need = Need::parse(&rx.recv().await.unwrap()).unwrap();
        broker.answer(&json!({ "password": { "id": need.id } }));
        assert!(asking.await.unwrap().unwrap().is_none());

        // An error from the client fails the login.
        let asking = {
            let source = source.clone();
            let target = target.clone();
            tokio::spawn(async move {
                source
                    .password(&PasswordRequest {
                        target: &target,
                        attempt: 1,
                    })
                    .await
            })
        };
        let need = Need::parse(&rx.recv().await.unwrap()).unwrap();
        broker.answer(&json!({ "password": { "id": need.id, "error": "none configured" } }));
        let err = asking.await.unwrap().unwrap_err();
        assert!(matches!(err, Error::Auth(_)), "{err}");
        assert!(err.to_string().contains("none configured"));

        // Closing fails what is still open.
        let asking = {
            let source = source.clone();
            let target = target.clone();
            tokio::spawn(async move {
                source
                    .password(&PasswordRequest {
                        target: &target,
                        attempt: 1,
                    })
                    .await
            })
        };
        rx.recv().await.unwrap();
        broker.close();
        assert!(matches!(asking.await.unwrap(), Err(Error::Cancelled)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_times_out_with_the_targets_timeout() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let broker = RemoteBroker::new(tx, CancellationToken::new());
        let source = broker.for_src();
        let target = Location::parse("ftp://u@h/in/?timeout=2").unwrap();
        let asking = tokio::spawn(async move {
            source
                .password(&PasswordRequest {
                    target: &target,
                    attempt: 1,
                })
                .await
        });
        let need = Need::parse(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(need.who, Who::Src);
        let err = asking.await.unwrap().unwrap_err().to_string();
        assert!(err.contains("within 2s"), "{err}");
    }

    #[tokio::test]
    async fn the_job_answers_from_its_locations() {
        let answerer = JobAnswerer {
            src: None,
            dsts: vec![
                Location::parse("ftp://u:one@h/").unwrap(),
                Location::parse("ftp://u@h/").unwrap(),
            ],
            vias: vec![None, Some(Location::parse("ssh://r:two@h/").unwrap())],
        };
        let need = |who| Need {
            id: 1,
            who,
            target: String::new(),
            user: None,
            attempt: 1,
        };
        assert_eq!(
            answerer
                .answer(&need(Who::Dst(0)))
                .await
                .unwrap()
                .unwrap()
                .expose_secret(),
            "one"
        );
        assert!(answerer.answer(&need(Who::Dst(1))).await.unwrap().is_none());
        assert!(answerer.answer(&need(Who::Dst(5))).await.is_err());
        assert!(answerer.answer(&need(Who::Src)).await.is_err());
        assert_eq!(
            answerer
                .answer(&need(Who::Via(1)))
                .await
                .unwrap()
                .unwrap()
                .expose_secret(),
            "two"
        );
        assert!(answerer.answer(&need(Who::Via(0))).await.is_err());
        let line = Need {
            id: 3,
            who: Who::Via(1),
            target: "ssh://r@h/".into(),
            user: Some("r".into()),
            attempt: 1,
        }
        .to_line();
        assert_eq!(Need::parse(&line).unwrap().who, Who::Via(1));
        let line = answer_line(7, &Ok(Some(SecretString::from("x"))));
        assert_eq!(line["password"]["value"], "x");
        assert_eq!(line["password"]["id"], 7);
    }
}
