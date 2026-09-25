//! Events over WebSocket, and the ticker that turns byte counters into
//! `progress` events while somebody is watching.
//!
//! `GET /v1/jobs/{id}/events` sends the job's snapshot first, then every
//! event of that job, and closes after `done`; a client that falls behind
//! gets a fresh snapshot instead of the events it missed. `GET /v1/events`
//! sends a snapshot (without transfers) of every job not yet over, then
//! every job's events, and stays open; a client that falls behind gets a
//! `lagged` frame and those snapshots again. Both are one JSON object per
//! text frame.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use tokio::sync::broadcast::error::RecvError;
use tracing::debug;

use super::AppState;
use super::api::Reject;
use super::model::{Event, JobId};

/// A client is a sender that must not hold the server up.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Nothing a client sends is read, so nothing big needs buffering.
const CLIENT_MESSAGE_LIMIT: usize = 4096;

pub(super) async fn job_events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, Reject> {
    let id = JobId::parse(&id)
        .filter(|id| state.store.snapshot(id, false).is_some())
        .ok_or_else(|| {
            Reject::new(
                axum::http::StatusCode::NOT_FOUND,
                "not_found",
                format!("no job {id}"),
            )
        })?;
    Ok(ws
        .max_message_size(CLIENT_MESSAGE_LIMIT)
        .on_upgrade(move |socket| watch(state, socket, Some(id))))
}

pub(super) async fn all_events(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.max_message_size(CLIENT_MESSAGE_LIMIT)
        .on_upgrade(move |socket| watch(state, socket, None))
}

/// Counts the client for the ticker while it is connected.
struct Watching(Arc<AppState>);

impl Watching {
    fn new(state: Arc<AppState>) -> Watching {
        state.watchers.fetch_add(1, Ordering::Relaxed);
        Watching(state)
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        self.0.watchers.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn send(socket: &mut WebSocket, event: &Event) -> bool {
    let text = match serde_json::to_string(event) {
        Ok(t) => t,
        Err(_) => return false,
    };
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

/// A snapshot of every job not yet over, without its transfers: what a
/// client of `/v1/events` starts from, and starts again from after it fell
/// behind.
async fn send_open_jobs(state: &AppState, socket: &mut WebSocket) -> bool {
    for job in state.store.open_jobs() {
        if !send(socket, &Event::Snapshot { job: Box::new(job) }).await {
            return false;
        }
    }
    true
}

async fn watch(state: Arc<AppState>, mut socket: WebSocket, filter: Option<JobId>) {
    let _watching = Watching::new(Arc::clone(&state));
    // Subscribed before the snapshot is taken, so nothing falls between.
    let mut rx = state.store.subscribe();
    if let Some(id) = &filter {
        let Some(snap) = state.store.snapshot(id, true) else {
            let _ = socket.send(Message::Close(None)).await;
            return;
        };
        let over = snap.state.is_final();
        if !send(
            &mut socket,
            &Event::Snapshot {
                job: Box::new(snap),
            },
        )
        .await
            || over
        {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    } else if !send_open_jobs(&state, &mut socket).await {
        return;
    }
    debug!(job = ?filter, "websocket client connected");
    loop {
        tokio::select! {
            biased;
            () = state.closing.cancelled() => break,
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => continue,
            },
            ev = rx.recv() => match ev {
                Ok(ev) => {
                    if filter.as_ref().is_some_and(|id| ev.job_id() != Some(id)) {
                        continue;
                    }
                    if !send(&mut socket, &ev).await {
                        return;
                    }
                    if filter.is_some() && matches!(ev, Event::Done { .. }) {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    debug!(missed = n, "websocket client fell behind");
                    if let Some(id) = &filter {
                        let Some(snap) = state.store.snapshot(id, true) else {
                            break;
                        };
                        let over = snap.state.is_final();
                        if !send(&mut socket, &Event::Snapshot { job: Box::new(snap) }).await
                            || over
                        {
                            break;
                        }
                    } else if !send(&mut socket, &Event::Lagged { missed: n }).await
                        || !send_open_jobs(&state, &mut socket).await
                    {
                        return;
                    }
                }
                Err(RecvError::Closed) => break,
            },
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}

/// Four times a second, while a client is connected, tell the bytes of
/// every running job that has moved since the last look.
pub(super) fn spawn_ticker(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut last: HashMap<JobId, u64> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if state.watchers.load(Ordering::Relaxed) == 0 {
                last.clear();
                continue;
            }
            let mut seen = HashSet::new();
            for (id, bytes, transfers) in state.store.running_progress() {
                seen.insert(id.clone());
                if last.get(&id) == Some(&bytes) {
                    continue;
                }
                last.insert(id.clone(), bytes);
                state.store.publish(Event::Progress {
                    id,
                    bytes,
                    transfers,
                });
            }
            last.retain(|id, _| seen.contains(id));
        }
    });
}
