//! The HTTP side: routes, the bearer check, and errors as JSON.
//!
//! Every error is `{"error": {"kind": …, "message": …}}` with a status
//! that says whose fault it is: 400 for a request the server cannot act
//! on, 401 without the token, 404 for a job it does not know, 409 for a
//! job that would write what another writes (a job with a pattern or a
//! tree is checked once it is expanded, after the 202), 413 for a body over the
//! limit, 415 for a body in a form it does not read, 503 while it shuts
//! down.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tracing::debug;

use super::model::{
    ApiError, JobId, JobKind, JobOptions, JobState, Submission, SubmitBatch, SubmitJob, specs_of,
};
use super::{AppState, scheduler, ws};
use crate::Error;
use crate::batch::jobs::{Format, JobSpec, JsonJob};

/// The routes under `/v1`, with the bearer check on everything but
/// `healthz`. Embed it in another axum application or serve it as is.
pub fn router(state: Arc<AppState>) -> Router {
    let guarded = Router::new()
        .route("/v1/jobs", post(submit_job).get(list_jobs))
        .route("/v1/batches", post(submit_batch))
        .route("/v1/jobs/{id}", get(get_job).delete(cancel_job))
        .route("/v1/jobs/{id}/transfers/{index}", get(get_transfer))
        .route("/v1/jobs/{id}/events", get(ws::job_events))
        .route("/v1/events", get(ws::all_events))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), auth));
    Router::new()
        .route("/v1/healthz", get(healthz))
        .merge(guarded)
        .fallback(not_found)
        .with_state(state)
}

/// A request that is refused: the status and what to tell the client.
#[derive(Debug)]
pub struct Reject {
    pub status: StatusCode,
    pub error: ApiError,
}

impl Reject {
    pub fn new(status: StatusCode, kind: &str, message: impl std::fmt::Display) -> Reject {
        Reject {
            status,
            error: ApiError::new(kind, message),
        }
    }

    fn bad_request(err: &Error) -> Reject {
        Reject {
            status: StatusCode::BAD_REQUEST,
            error: ApiError::from(err),
        }
    }

    fn not_found(what: impl std::fmt::Display) -> Reject {
        Reject::new(StatusCode::NOT_FOUND, "not_found", what)
    }
}

impl From<Error> for Reject {
    fn from(e: Error) -> Self {
        Reject::bad_request(&e)
    }
}

impl IntoResponse for Reject {
    fn into_response(self) -> Response {
        let mut resp = (self.status, Json(json!({ "error": self.error }))).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

/// The bearer token, compared in constant time. A request a browser
/// makes on some page's behalf carries an `Origin` header; the API is
/// not for pages, so such a request is refused whatever else it carries.
/// That keeps a site the operator visits from posting jobs to a server
/// on loopback that runs without a token, or from opening its WebSocket.
async fn auth(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if req.headers().contains_key(header::ORIGIN) {
        return Reject::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "requests from a web page are not accepted (Origin header present)",
        )
        .into_response();
    }
    match bearer(&state, req.headers()) {
        Bearer::Ok => next.run(req).await,
        Bearer::Wrong => {
            // Slow a guess down; four tries a second per connection is
            // nothing against a random token, and costs a client with the
            // right one nothing.
            tokio::time::sleep(WRONG_TOKEN_DELAY).await;
            Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", "wrong token").into_response()
        }
        Bearer::Missing => Reject::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "send the token as `Authorization: Bearer <token>`",
        )
        .into_response(),
    }
}

const WRONG_TOKEN_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

enum Bearer {
    Ok,
    Wrong,
    Missing,
}

/// Whether the request carries the token. Without one configured, every
/// request is fine (the server is on loopback then).
fn bearer(state: &AppState, headers: &HeaderMap) -> Bearer {
    let Some(expected) = &state.cfg.token else {
        return Bearer::Ok;
    };
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, token) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
        });
    match given {
        Some(token) if token_matches(token, expected.expose_secret()) => Bearer::Ok,
        Some(_) => Bearer::Wrong,
        None => Bearer::Missing,
    }
}

fn token_matches(given: &str, expected: &str) -> bool {
    // A different length is refused in constant time over the shorter one;
    // that leaks the length, which is not the secret.
    given.len() == expected.len() && bool::from(given.as_bytes().ct_eq(expected.as_bytes()))
}

async fn not_found() -> Reject {
    Reject::not_found("no such route")
}

/// Alive or not, for a probe; what else is going on only with the token.
async fn healthz(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let accepting = state.accepting();
    let body = if matches!(bearer(&state, &headers), Bearer::Ok) {
        let (queued, running) = state.store.counts();
        json!({
            "ok": accepting,
            "version": env!("CARGO_PKG_VERSION"),
            "accepting": accepting,
            "jobs": { "queued": queued, "running": running },
        })
    } else {
        json!({ "ok": accepting })
    };
    let status = if accepting {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

/// The body, within the limit; 413 beyond it.
async fn read_body(state: &AppState, body: Body) -> Result<bytes::Bytes, Reject> {
    axum::body::to_bytes(body, state.cfg.max_body)
        .await
        .map_err(|_| {
            Reject::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                format!(
                    "the body exceeds the limit of {} bytes ([server] max_body)",
                    state.cfg.max_body
                ),
            )
        })
}

/// The media type of the body, without parameters, lower case; `None`
/// when the header is missing.
fn content_type(headers: &HeaderMap) -> Option<String> {
    headers.get(header::CONTENT_TYPE)?.to_str().ok().map(|v| {
        v.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    })
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, Reject> {
    serde_json::from_slice(bytes).map_err(|e| {
        Reject::new(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            format!("JSON: {e}"),
        )
    })
}

/// JSON, or nothing said. `curl -d` labels its body as a form, which is
/// let through as JSON too, so trying the API needs no extra header.
fn is_json(content_type: Option<&str>) -> bool {
    matches!(
        content_type,
        None | Some("application/json") | Some("application/x-www-form-urlencoded")
    )
}

fn expect_json(headers: &HeaderMap) -> Result<(), Reject> {
    match content_type(headers).as_deref() {
        ct if is_json(ct) => Ok(()),
        None => unreachable!("None is JSON"),
        Some(other) => Err(Reject::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            format!("{other}: send JSON (Content-Type: application/json)"),
        )),
    }
}

/// `POST /v1/jobs`: one transfer.
async fn submit_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Reject> {
    expect_json(&headers)?;
    let bytes = read_body(&state, body).await?;
    let req: SubmitJob = parse_json(&bytes)?;
    let spec = JsonJob {
        src: req.src,
        dst: req.dst,
    }
    .into_spec()
    .map_err(|e| Reject::new(StatusCode::BAD_REQUEST, "invalid_url", e))?;
    accept(
        &state,
        Submission {
            kind: JobKind::Single,
            specs: vec![spec],
            options: req.options,
        },
    )
    .await
}

/// `POST /v1/batches`: a list of transfers, as JSON or as one of the job
/// list formats of `mpt batch` (then the options come from the query).
async fn submit_batch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<JobOptions>, axum::extract::rejection::QueryRejection>,
    body: Body,
) -> Result<Response, Reject> {
    let Query(query_options) =
        query.map_err(|e| Reject::new(StatusCode::BAD_REQUEST, "invalid_option", e.body_text()))?;
    let format = match content_type(&headers).as_deref() {
        ct if is_json(ct) => None,
        None => unreachable!("None is JSON"),
        Some("application/x-ndjson")
        | Some("application/jsonl")
        | Some("application/json-lines") => Some(Format::Jsonl),
        Some("text/csv") | Some("text/tab-separated-values") => Some(Format::Csv),
        Some("text/plain") => Some(Format::Lines),
        Some(other) => {
            return Err(Reject::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                format!(
                    "{other}: send application/json, application/x-ndjson, text/csv or text/plain"
                ),
            ));
        }
    };
    let bytes = read_body(&state, body).await?;
    let (specs, options): (Vec<JobSpec>, JobOptions) = match format {
        None => {
            if query_options != JobOptions::default() {
                return Err(Reject::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_option",
                    "with a JSON body the options go in the body, not the query",
                ));
            }
            let req: SubmitBatch = parse_json(&bytes)?;
            (specs_of(req.jobs)?, req.options)
        }
        Some(format) => {
            let text = std::str::from_utf8(&bytes).map_err(|e| {
                Reject::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_body",
                    format!("not UTF-8: {e}"),
                )
            })?;
            (crate::batch::jobs::parse(text, format)?, query_options)
        }
    };
    if specs.is_empty() {
        return Err(Reject::new(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "the batch has no jobs",
        ));
    }
    accept(
        &state,
        Submission {
            kind: JobKind::Batch,
            specs,
            options,
        },
    )
    .await
}

/// What is checked before a job is taken: nothing that needs I/O. The
/// rest (a source that does not exist, a pattern that matches nothing)
/// shows up as the job's failure.
async fn accept(state: &Arc<AppState>, submission: Submission) -> Result<Response, Reject> {
    if !state.accepting() {
        return Err(Reject::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "the server is shutting down and takes no new jobs",
        ));
    }
    // Judged on the options the job would run with, as the scheduler
    // will lay them over the server's.
    state.admit(&submission).map_err(|error| Reject {
        status: StatusCode::BAD_REQUEST,
        error,
    })?;
    if state.store.unfinished() >= state.cfg.max_queued {
        let mut resp = Reject::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_jobs",
            format!(
                "{} jobs are still open; the limit is {} ([server] max_queued)",
                state.store.unfinished(),
                state.cfg.max_queued
            ),
        )
        .into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return Ok(resp);
    }
    let mut jobs = Vec::with_capacity(submission.specs.len());
    // What was submitted next to what it resolved to, so a refusal can be
    // worded in the client's terms.
    let mut refs: Vec<(String, crate::Location)> = Vec::new();
    for spec in &submission.specs {
        let locate = |url: &str| -> Result<crate::Location, Reject> {
            crate::config::locate(url).map_err(|e| Reject {
                status: StatusCode::BAD_REQUEST,
                error: ApiError::client_safe(&e, url),
            })
        };
        let src = locate(&spec.src)?;
        if src.scheme().is_mail() {
            return Err(Reject::new(
                StatusCode::BAD_REQUEST,
                "invalid_url",
                format!("{} cannot be a source", spec.src),
            ));
        }
        let dsts = spec
            .dsts
            .iter()
            .map(|d| locate(d))
            .collect::<Result<Vec<_>, _>>()?;
        refs.push((spec.src.clone(), src.clone()));
        for (url, loc) in spec.dsts.iter().zip(&dsts) {
            refs.push((url.clone(), loc.clone()));
        }
        jobs.push(crate::batch::Job { src, dsts });
    }
    // Two jobs on one file can be told apart now unless a pattern or a
    // tree is still to be expanded; then the check runs after that.
    let expands = submission.options.recursive.unwrap_or(false)
        || jobs
            .iter()
            .any(|j| crate::batch::expand::has_pattern(&j.src));
    if !expands {
        if let Err(e) = crate::batch::check_collisions(&jobs) {
            let error = ApiError::new("conflict", scheduler::conflict_text(&e));
            return Err(Reject {
                status: StatusCode::CONFLICT,
                error: scheduler::redact(error, &refs),
            });
        }
        // And against what the jobs running now write. Only a hint: the
        // claim itself is made when the job is prepared, and a job that
        // loses a race to it fails there with the same kind.
        let taken = state
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_all(&jobs, 1)
            .err();
        if let Some(e) = taken {
            let error = ApiError::new("conflict", scheduler::conflict_text(&e));
            return Err(Reject {
                status: StatusCode::CONFLICT,
                error: scheduler::redact(error, &refs),
            });
        }
    }
    let transfers = submission.specs.len();
    let id = state.submit(submission).await.map_err(|e| {
        Reject::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            e.kind(),
            format!("cannot accept the job: {e}"),
        )
    })?;
    debug!(%id, transfers, "accepted");
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "id": id,
            "url": format!("/v1/jobs/{id}"),
            "state": JobState::Queued,
            "transfers": transfers,
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    state: Option<String>,
    limit: Option<usize>,
}

/// `GET /v1/jobs?state=running&limit=50`: summaries, newest first.
async fn list_jobs(
    State(state): State<Arc<AppState>>,
    query: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, Reject> {
    let Query(q) =
        query.map_err(|e| Reject::new(StatusCode::BAD_REQUEST, "invalid_option", e.body_text()))?;
    let filter = q
        .state
        .as_deref()
        .map(|s| {
            s.parse::<JobState>()
                .map_err(|e| Reject::new(StatusCode::BAD_REQUEST, "invalid_option", e))
        })
        .transpose()?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    Ok(Json(state.store.list(filter, limit)).into_response())
}

fn job_id(raw: &str) -> Result<JobId, Reject> {
    JobId::parse(raw).ok_or_else(|| Reject::not_found(format!("no job {raw}")))
}

/// `GET /v1/jobs/{id}`: the job with its transfers.
async fn get_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let id = job_id(&id)?;
    let snap = state
        .store
        .snapshot(&id, true)
        .ok_or_else(|| Reject::not_found(format!("no job {id}")))?;
    Ok(Json(snap).into_response())
}

/// `GET /v1/jobs/{id}/transfers/{index}`: one transfer.
async fn get_transfer(
    State(state): State<Arc<AppState>>,
    Path((id, index)): Path<(String, String)>,
) -> Result<Response, Reject> {
    let id = job_id(&id)?;
    let index: usize = index
        .parse()
        .map_err(|_| Reject::not_found(format!("no transfer {index} in job {id}")))?;
    let snap = state
        .store
        .transfer(&id, index)
        .ok_or_else(|| Reject::not_found(format!("no transfer {index} in job {id}")))?;
    Ok(Json(snap).into_response())
}

/// `DELETE /v1/jobs/{id}`: stop the job. 202 while it stops, 200 with the
/// final state once it is over (so a repeat is harmless).
async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, Reject> {
    let id = job_id(&id)?;
    let was = state
        .store
        .cancel(&id)
        .ok_or_else(|| Reject::not_found(format!("no job {id}")))?;
    Ok(if was.is_final() {
        (StatusCode::OK, Json(json!({ "id": id, "state": was }))).into_response()
    } else {
        (
            StatusCode::ACCEPTED,
            Json(json!({ "id": id, "state": was, "cancelling": true })),
        )
            .into_response()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UrlRule;
    use crate::server::{Runtime, ServerConfig};
    use crate::transfer::CopyOptions;
    use axum::body::to_bytes;
    use axum::http::{Method, Request as HttpRequest};
    use tower::ServiceExt;

    fn app(cfg: ServerConfig) -> Router {
        let state = AppState::new(cfg, Runtime::new(CopyOptions::default())).unwrap();
        router(state)
    }

    fn with_token(urls: UrlRule) -> ServerConfig {
        ServerConfig {
            token: Some("s3cret".into()),
            urls,
            ..Default::default()
        }
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        token: Option<&str>,
        content_type: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = HttpRequest::builder().method(method).uri(path);
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
                String::from_utf8_lossy(&bytes).into_owned(),
            ))
        };
        (status, json)
    }

    #[tokio::test]
    async fn the_token_guards_everything_but_health() {
        let app = app(with_token(UrlRule::Any));
        let (status, body) = call(&app, Method::GET, "/v1/healthz", None, None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({ "ok": true }),
            "no details without the token"
        );
        let (status, body) = call(&app, Method::GET, "/v1/healthz", Some("s3cret"), None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accepting"], true);
        assert!(body["version"].is_string());
        let started = std::time::Instant::now();
        let (status, _) = call(&app, Method::GET, "/v1/jobs", Some("guess"), None, "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            started.elapsed() >= WRONG_TOKEN_DELAY,
            "a wrong token is slowed down"
        );
        let (status, body) = call(&app, Method::GET, "/v1/jobs", None, None, "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["kind"], "unauthorized");
        let (status, _) = call(&app, Method::GET, "/v1/jobs", Some("wrong"), None, "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = call(&app, Method::GET, "/v1/jobs", Some("s3cret"), None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!([]));
        let (status, _) = call(&app, Method::GET, "/v1/nothing", Some("s3cret"), None, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_request_from_a_page_is_refused_even_with_the_token() {
        let app = app(with_token(UrlRule::Any));
        let req = HttpRequest::builder()
            .method(Method::GET)
            .uri("/v1/jobs")
            .header("authorization", "Bearer s3cret")
            .header("origin", "http://evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Also without a token, where a page on the same machine would
        // otherwise get in with a text/plain batch.
        let open = self::app(ServerConfig {
            urls: UrlRule::Any,
            ..Default::default()
        });
        let req = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/batches")
            .header("origin", "http://evil.example")
            .header("content-type", "text/plain")
            .body(Body::from("/etc/passwd /tmp/out/\n"))
            .unwrap();
        let resp = open.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_profile_reference_may_not_carry_options() {
        let app = app(with_token(UrlRule::Profiles));
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            Some("s3cret"),
            None,
            r#"{"src": "mpt://src/a?known_hosts=off", "dst": "mpt://dst/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("?options"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn no_token_means_no_check_on_loopback() {
        let app = app(ServerConfig {
            urls: UrlRule::Any,
            ..Default::default()
        });
        let (status, _) = call(&app, Method::GET, "/v1/jobs", None, None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            ServerConfig {
                bind: "0.0.0.0:0".parse().unwrap(),
                ..Default::default()
            }
            .check()
            .is_err()
        );
    }

    #[tokio::test]
    async fn bad_submissions_are_told_apart() {
        let app = app(with_token(UrlRule::Any));
        let t = Some("s3cret");
        let (status, body) = call(&app, Method::POST, "/v1/jobs", t, None, "{").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["kind"], "invalid_body");
        let (status, _) = call(&app, Method::POST, "/v1/jobs", t, Some("text/xml"), "<x/>").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            None,
            r#"{"src": "/tmp/a", "dst": "/tmp/b/", "options": {"retries": 2}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["kind"], "invalid_option");
        let (status, _) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            None,
            r#"{"src": "mailto:a@b.c", "dst": "/tmp/b/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/batches",
            t,
            None,
            r#"{"jobs": [{"src": "/tmp/a/x", "dst": "/tmp/out/"}, {"src": "/tmp/b/x", "dst": "/tmp/out/"}]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, _) = call(
            &app,
            Method::POST,
            "/v1/batches",
            t,
            None,
            r#"{"jobs": []}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/batches?parallel=2",
            t,
            None,
            r#"{"jobs": [{"src": "/tmp/a", "dst": "/tmp/out/"}]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, _) = call(&app, Method::GET, "/v1/jobs?state=odd", t, None, "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(&app, Method::GET, "/v1/jobs/notanid", t, None, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &app,
            Method::DELETE,
            &format!("/v1/jobs/{}", "0".repeat(32)),
            t,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deleting_and_flooding_need_permission() {
        let app = app(with_token(UrlRule::Any));
        let t = Some("s3cret");
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            None,
            r#"{"src": "/tmp/a", "dst": "/tmp/out/", "options": {"delete_source": true}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("allow_delete"),
            "{body}"
        );
        let app = self::app(ServerConfig {
            allow_delete: true,
            max_transfers: 2,
            max_queued: 1,
            parallel: 1,
            ..with_token(UrlRule::Any)
        });
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/batches",
            t,
            None,
            r#"{"jobs": [{"src": "/tmp/a", "dst": "/tmp/o/"}, {"src": "/tmp/b", "dst": "/tmp/o/"}, {"src": "/tmp/c", "dst": "/tmp/o/"}]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["kind"], "too_many_transfers");
        // One job that cannot start (no slot) fills the queue; the next is
        // told to come back.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), "a").unwrap();
        let body_a = format!(
            r#"{{"src": "{0}/a", "dst": "{0}/out/", "options": {{"delete_source": true}}}}"#,
            dir.path().display()
        );
        let (status, body) = call(&app, Method::POST, "/v1/jobs", t, None, &body_a).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let url = body["url"].as_str().unwrap().to_string();
        let (status, body) = call(&app, Method::POST, "/v1/jobs", t, None, &body_a).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(body["error"]["kind"], "too_many_jobs");
        // The accepted job runs to its end and, allowed to, deletes its source.
        for _ in 0..200 {
            let (_, snap) = call(&app, Method::GET, &url, t, None, "").await;
            if matches!(
                snap["state"].as_str(),
                Some("done" | "failed" | "cancelled")
            ) {
                assert_eq!(snap["state"], "done", "{snap}");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!dir.path().join("a").exists());
        let (status, _) = call(&app, Method::POST, "/v1/jobs", t, None, &body_a).await;
        assert_eq!(status, StatusCode::ACCEPTED, "the queue is free again");
    }

    #[tokio::test]
    async fn a_target_a_running_job_writes_is_a_conflict_at_once() {
        let state = AppState::new(
            with_token(UrlRule::Any),
            Runtime::new(CopyOptions::default()),
        )
        .unwrap();
        // What a job being run holds.
        let running = crate::batch::Job {
            src: crate::Location::parse("/tmp/a/x.bin").unwrap(),
            dsts: vec![crate::Location::parse("/tmp/out/").unwrap()],
        };
        state.targets.lock().unwrap().note(&running, 1).unwrap();
        let app = router(Arc::clone(&state));
        let t = Some("s3cret");
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            None,
            r#"{"src": "/tmp/b/x.bin", "dst": "/tmp/out/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["kind"], "conflict");
        assert_eq!(
            body["error"]["message"],
            "job 1 writes the target /tmp/out/x.bin, which another job is writing now"
        );
        // A pattern is expanded first, so its conflicts show up later.
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            None,
            r#"{"src": "/tmp/nothing-here/*.bin", "dst": "/tmp/out/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        // Another file in the same directory is free.
        state.targets.lock().unwrap().release(&running);
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            None,
            r#"{"src": "/tmp/b/x.bin", "dst": "/tmp/out/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_413() {
        let app = app(ServerConfig {
            max_body: 64,
            ..with_token(UrlRule::Any)
        });
        let big = format!(
            r#"{{"src": "/tmp/{}", "dst": "/tmp/out/"}}"#,
            "a".repeat(100)
        );
        let (status, body) = call(&app, Method::POST, "/v1/jobs", Some("s3cret"), None, &big).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["kind"], "too_large");
    }

    #[tokio::test]
    async fn only_profiles_by_default() {
        // No profiles are installed in this process, so every mpt:// URL
        // is unknown; a raw URL is refused with the hint.
        let app = app(with_token(UrlRule::Profiles));
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            Some("s3cret"),
            None,
            r#"{"src": "/tmp/a", "dst": "/tmp/out/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["kind"], "invalid_url");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("urls = \"any\""),
            "{body}"
        );
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            Some("s3cret"),
            None,
            r#"{"src": "mpt://nowhere/a", "dst": "mpt://nowhere/out/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("no profile 'nowhere'"),
            "{body}"
        );
        // An allow-list is checked before the configuration is.
        let app = self::app(ServerConfig {
            profiles: vec!["prod".into()],
            ..with_token(UrlRule::Profiles)
        });
        let (_, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            Some("s3cret"),
            None,
            r#"{"src": "mpt://other/a", "dst": "mpt://prod/"}"#,
        )
        .await;
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not among those"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_job_is_accepted_run_and_shown() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.bin");
        std::fs::write(&src, "hello").unwrap();
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let app = app(with_token(UrlRule::Any));
        let t = Some("s3cret");
        let body = format!(
            r#"{{"src": "{}", "dst": ["{}/out/"]}}"#,
            src.display(),
            dir.path().display()
        );
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/jobs",
            t,
            Some("application/json; charset=utf-8"),
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["state"], "queued");
        assert_eq!(body["transfers"], 1);
        let url = body["url"].as_str().unwrap().to_string();
        let mut snap = serde_json::Value::Null;
        for _ in 0..200 {
            let (status, body) = call(&app, Method::GET, &url, t, None, "").await;
            assert_eq!(status, StatusCode::OK);
            snap = body;
            if matches!(
                snap["state"].as_str(),
                Some("done" | "failed" | "cancelled")
            ) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(snap["state"], "done", "{snap}");
        assert_eq!(snap["kind"], "single");
        assert_eq!(snap["progress"]["bytes"], 5);
        assert_eq!(snap["transfers"][0]["report"]["ok"], true);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("out/a.bin")).unwrap(),
            "hello"
        );
        let (status, one) = call(
            &app,
            Method::GET,
            &format!("{url}/transfers/0"),
            t,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(one["state"], "done");
        assert_eq!(one["progress"]["read"], 5);
        let (status, _) = call(
            &app,
            Method::GET,
            &format!("{url}/transfers/1"),
            t,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, list) = call(&app, Method::GET, "/v1/jobs?state=done", t, None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert!(list[0].get("transfers").is_none());
        // Cancelling a finished job reports its state with 200.
        let (status, body) = call(&app, Method::DELETE, &url, t, None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "done");
    }

    #[tokio::test]
    async fn a_batch_comes_as_ndjson_with_query_options() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), "1").unwrap();
        std::fs::write(dir.path().join("b"), "22").unwrap();
        std::fs::create_dir(dir.path().join("out")).unwrap();
        let app = app(with_token(UrlRule::Any));
        let t = Some("s3cret");
        let d = dir.path().display();
        let body = format!(
            "{{\"src\": \"{d}/a\", \"dst\": \"{d}/out/\"}}\n{{\"src\": \"{d}/b\", \"dst\": \"{d}/out/\"}}\n{{\"src\": \"{d}/missing\", \"dst\": \"{d}/out/\"}}\n"
        );
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/batches?parallel=2&skip_existing=true",
            t,
            Some("application/x-ndjson"),
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["transfers"], 3);
        let url = body["url"].as_str().unwrap().to_string();
        let mut snap = serde_json::Value::Null;
        for _ in 0..200 {
            let (_, body) = call(&app, Method::GET, &url, t, None, "").await;
            snap = body;
            if matches!(
                snap["state"].as_str(),
                Some("done" | "failed" | "cancelled")
            ) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(snap["state"], "failed", "{snap}");
        assert_eq!(snap["kind"], "batch");
        assert_eq!(snap["options"]["parallel"], 2);
        assert_eq!(snap["options"]["skip_existing"], true);
        assert_eq!(snap["progress"]["transfers"]["done"], 2);
        assert_eq!(snap["progress"]["transfers"]["failed"], 1);
        assert_eq!(snap["transfers"][2]["error"]["kind"], "io");
        assert_eq!(snap["progress"]["bytes"], 3);
    }
}
