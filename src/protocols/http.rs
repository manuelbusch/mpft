//! `http://` / `https://`: GET to receive, PUT (or `?method=post`) to send.
//!
//! Query parameters other than the transceiver options (`method`, `header`,
//! `insecure`, `timeout`) are passed through to the server.

use std::time::Duration;

use async_trait::async_trait;
use futures::TryStreamExt;
use reqwest::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue,
};
use reqwest::{Client, Method, Url};
use secrecy::ExposeSecret;
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::debug;

use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, Scheme, SendMeta, Sender,
    stream,
};

/// Option names consumed by this crate and not forwarded as query parameters.
pub(crate) const OWN_OPTIONS: &[&str] = &[
    "method",
    "header",
    "insecure",
    "timeout",
    "token",
    "connect_retries",
];

pub struct HttpEndpoint {
    loc: Location,
    client: Client,
    method: Method,
    headers: HeaderMap,
}

impl HttpEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        loc.host_required()?;
        // Redirects are followed by hand (`fetch`), so that the endpoint's
        // headers stay with its own host.
        let client = build_client(&loc, reqwest::redirect::Policy::none())?;
        let method = match loc.opt("method").map(|m| m.to_ascii_uppercase()).as_deref() {
            None | Some("PUT") => Method::PUT,
            Some("POST") => Method::POST,
            Some("PATCH") => Method::PATCH,
            Some(other) => {
                return Err(Error::invalid_option(
                    "method",
                    format!("expected put|post|patch, got '{other}'"),
                ));
            }
        };
        let headers = parse_headers(&loc)?;
        Ok(HttpEndpoint {
            loc,
            client,
            method,
            headers,
        })
    }

    /// The URL to talk to (with pass-through query parameters).
    fn url(&self, filename: Option<&str>) -> Result<Url> {
        let mut url = base_url(&self.loc, &["http", "https"])?;
        // Encoded segment by segment: `set_path` takes `%` as it is.
        url.set_path(&self.loc.encoded_target_path(filename)?);
        let passthrough: Vec<(&str, &str)> = self
            .loc
            .options()
            .iter()
            .filter(|(k, _)| !OWN_OPTIONS.contains(&k.as_str()))
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if !passthrough.is_empty() {
            url.query_pairs_mut().extend_pairs(passthrough);
        }
        Ok(url)
    }

    /// A GET or HEAD of the endpoint's URL, following redirects by hand:
    /// its headers, token and password go to its own host only, and to no
    /// host a redirect points somewhere else (reqwest would keep a custom
    /// header such as `X-Api-Key`). A redirect from `https://` to anything
    /// else is refused.
    async fn fetch(&self, method: Method) -> Result<reqwest::Response> {
        let first = self.url(None)?;
        let mut url = first.clone();
        let mut own_host = true;
        for _ in 0..=MAX_REDIRECTS {
            let rb = if own_host {
                self.request(method.clone(), url.clone()).await?
            } else {
                self.client.request(method.clone(), url.clone())
            };
            let resp = rb.send().await.map_err(http_err)?;
            if !resp.status().is_redirection() {
                return Ok(resp);
            }
            let next = redirect_target(&url, &resp)?;
            if own_host && next.origin() != first.origin() {
                debug!(%next, "redirected to another host: the endpoint's headers stay behind");
                own_host = false;
            }
            url = next;
        }
        Err(Error::Remote(format!(
            "http: more than {MAX_REDIRECTS} redirects"
        )))
    }

    /// A request with the endpoint's headers and, for a user name, basic
    /// authentication. The password is fetched for this request only.
    async fn request(&self, method: Method, url: Url) -> Result<reqwest::RequestBuilder> {
        let mut rb = self
            .client
            .request(method, url)
            .headers(self.headers.clone());
        if let Some(user) = self.loc.username() {
            let pw = self.loc.login_password(1).await?;
            rb = rb.basic_auth(user, pw.as_ref().map(|p| p.expose_secret()));
        }
        Ok(rb)
    }
}

/// The most redirects one request follows, as reqwest's own default.
const MAX_REDIRECTS: usize = 10;

pub(crate) fn build_client(loc: &Location, redirect: reqwest::redirect::Policy) -> Result<Client> {
    build_client_with(loc, redirect, HeaderMap::new())
}

/// [`build_client`] with headers every request carries.
pub(crate) fn build_client_with(
    loc: &Location,
    redirect: reqwest::redirect::Policy,
    headers: HeaderMap,
) -> Result<Client> {
    crate::init_crypto();
    let insecure = loc.opt_bool("insecure")?.unwrap_or(false);
    let timeout = loc.timeout_or(Duration::from_secs(30))?;
    let mut b = Client::builder()
        .danger_accept_invalid_certs(insecure)
        .connect_timeout(timeout)
        .redirect(redirect)
        .default_headers(headers)
        .user_agent(concat!("mpt/", env!("CARGO_PKG_VERSION")));
    if let Some(idle) = loc.timeout()? {
        // Per-read deadline for responses, plus TCP keepalive so a peer that
        // silently disappears mid-upload is noticed as well.
        b = b.read_timeout(idle).tcp_keepalive(idle);
    }
    b.build().map_err(|e| Error::transport("http", e))
}

/// `scheme://host[:port]` for the location, mapping the location scheme onto
/// `schemes[0]` (plain) or `schemes[1]` (TLS).
pub(crate) fn base_url(loc: &Location, schemes: &[&str; 2]) -> Result<Url> {
    let tls = matches!(loc.scheme(), Scheme::Https | Scheme::WebDavs);
    let scheme = if tls { schemes[1] } else { schemes[0] };
    loc.host_required()?;
    let host = loc.url_host().unwrap_or_default();
    let mut url =
        Url::parse(&format!("{scheme}://{host}/")).map_err(|e| Error::InvalidUrl(e.to_string()))?;
    if let Some(p) = loc.port() {
        url.set_port(Some(p))
            .map_err(|_| Error::InvalidUrl("cannot set port".into()))?;
    }
    Ok(url)
}

/// The endpoint's own headers: `?header=` and a bearer token, which WebDAV
/// sends the same way.
pub(crate) fn parse_headers(loc: &Location) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    // A bearer token: `?token=` for one call, [http] token in the
    // configuration for a provider that fetches it (SharePoint, Nextcloud,
    // Artifactory and everything else that speaks OAuth2).
    if let Some(token) = bearer_token(loc) {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| Error::invalid_option("token", e))?;
        value.set_sensitive(true);
        map.insert(AUTHORIZATION, value);
    }
    for h in loc.opts("header") {
        let (name, value) = h.split_once(':').ok_or_else(|| {
            Error::invalid_option("header", format!("expected Name:Value, got '{h}'"))
        })?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|e| Error::invalid_option("header", e))?;
        let value =
            HeaderValue::from_str(value.trim()).map_err(|e| Error::invalid_option("header", e))?;
        map.append(name, value);
    }
    Ok(map)
}

/// The token for this endpoint: the URL's own, else `[http] token` where
/// the configuration binds it to this host ([`crate::Config::http_token_for`]).
fn bearer_token(loc: &Location) -> Option<String> {
    if let Some(t) = loc.opt("token").filter(|t| !t.is_empty()) {
        return Some(t.to_string());
    }
    crate::config::global()
        .http_token_for(loc)
        .map(|t| t.expose_secret().to_string())
}

pub(crate) fn http_err(e: reqwest::Error) -> Error {
    match e.status() {
        Some(status) => status_err(status),
        // A redirect the policy refused is refused again next time.
        None if e.is_redirect() => {
            let why = std::error::Error::source(&e)
                .map(|s| s.to_string())
                .unwrap_or_else(|| e.to_string());
            Error::Remote(format!("http: {why}"))
        }
        None => Error::transport("http", e),
    }
}

/// Where a redirect from `from` points, as long as it is one to follow: not
/// from `https://` to anything else, and not away from HTTP.
fn redirect_target(from: &Url, resp: &reqwest::Response) -> Result<Url> {
    let status = resp.status();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Remote(format!("http {status} without a Location")))?;
    let next = from
        .join(location)
        .map_err(|e| Error::Remote(format!("http {status} to '{location}': {e}")))?;
    check_redirect(from, &next)?;
    Ok(next)
}

/// Refuse a redirect that would leave TLS, or HTTP altogether.
pub(crate) fn check_redirect(from: &Url, to: &Url) -> Result<()> {
    if from.scheme() == "https" && to.scheme() != "https" {
        return Err(Error::Remote(format!(
            "http: refusing a redirect from https:// to {}://{}",
            to.scheme(),
            to.host_str().unwrap_or("")
        )));
    }
    if !matches!(to.scheme(), "http" | "https") {
        return Err(Error::Remote(format!(
            "http: refusing a redirect to {}:",
            to.scheme()
        )));
    }
    Ok(())
}

/// The redirect policy of a client that cannot follow by hand (WebDAV,
/// whose requests reqwest_dav makes): the same refusals as
/// [`check_redirect`], and, when the endpoint sends headers of its own, no
/// redirect to another host at all, since reqwest would take them along.
pub(crate) fn guarded_redirects(own_headers: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let previous = attempt.previous();
        if previous.len() > MAX_REDIRECTS {
            return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
        }
        let (Some(first), Some(last)) = (previous.first(), previous.last()) else {
            return attempt.follow();
        };
        if let Err(e) = check_redirect(last, attempt.url()) {
            return attempt.error(e.to_string());
        }
        if own_headers && attempt.url().origin() != first.origin() {
            let to = attempt.url().host_str().unwrap_or("").to_string();
            return attempt.error(format!(
                "refusing a redirect to {to}: the endpoint's headers would go along"
            ));
        }
        attempt.follow()
    })
}

/// The error for a status the server answered with, shared with WebDAV:
/// refused credentials are [`Error::Auth`], a missing resource is
/// [`Error::not_found`], and the rest is the server's word as it stands.
pub(crate) fn status_err(status: reqwest::StatusCode) -> Error {
    use reqwest::StatusCode as S;
    match status {
        S::UNAUTHORIZED | S::FORBIDDEN => Error::Auth(format!("http {status}")),
        S::NOT_FOUND | S::GONE => Error::not_found(format!("http {status}")),
        _ => Error::Remote(format!("http {status}")),
    }
}

impl Endpoint for HttpEndpoint {
    fn location(&self) -> &Location {
        &self.loc
    }
    fn as_receiver(&self) -> Option<&dyn Receiver> {
        Some(self)
    }
    fn as_sender(&self) -> Option<&dyn Sender> {
        Some(self)
    }
}

#[async_trait]
impl Receiver for HttpEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        debug!(url = %self.url(None)?, "http GET");
        let resp = self
            .fetch(Method::GET)
            .await?
            .error_for_status()
            .map_err(http_err)?;
        let reader = StreamReader::new(resp.bytes_stream().map_err(std::io::Error::other));
        Ok(stream::boxed(stream::Idle::maybe(
            reader,
            self.loc.timeout()?,
        )))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        Err(Error::UnsupportedOperation {
            scheme: self.loc.scheme().to_string(),
            op: "list (use webdav:// for PROPFIND)",
        })
    }

    /// From a HEAD request. Whatever status it gets means "unknown": a
    /// server may answer HEAD differently from GET (a presigned URL is
    /// signed for GET alone and refuses HEAD with 403), and the GET that
    /// follows says what is true. A connection that fails is an error.
    async fn size(&self) -> Result<Option<u64>> {
        let resp = match self.fetch(Method::HEAD).await {
            Ok(r) => r,
            // A refused redirect: the GET will meet it again and say so.
            Err(e @ Error::Remote(_)) => {
                debug!("http HEAD: size unknown ({e})");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if !resp.status().is_success() {
            debug!(status = %resp.status(), "http HEAD: size unknown");
            return Ok(None);
        }
        // The header, not `content_length()`: a HEAD response has no body,
        // and reqwest reports the length of that body, 0.
        Ok(resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok()))
    }
}

#[async_trait]
impl Sender for HttpEndpoint {
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let url = self.url(meta.filename.as_deref())?;
        debug!(%url, method = %self.method, "http upload");
        let mut rb = self.request(self.method.clone(), url).await?;
        if !self.headers.contains_key(CONTENT_TYPE) {
            rb = rb.header(CONTENT_TYPE, meta.mime());
        }
        if let Some(n) = meta.size {
            rb = rb.header(CONTENT_LENGTH, n);
        }
        let resp = rb
            .body(reqwest::Body::wrap_stream(ReaderStream::new(body)))
            .send()
            .await
            .map_err(http_err)?;
        // The body is a stream that has been sent once and cannot be sent
        // again: a redirect is a failed upload, not a finished one.
        if resp.status().is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("?");
            return Err(Error::Remote(format!(
                "http {}: the upload was redirected to {to}; send it there",
                resp.status()
            )));
        }
        resp.error_for_status().map_err(http_err)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn headers(url: &str) -> HeaderMap {
        parse_headers(&Location::parse(url).unwrap()).unwrap()
    }

    #[test]
    fn a_token_becomes_an_authorization_header() {
        let h = headers("https://h/x?token=abc123");
        assert_eq!(h[AUTHORIZATION], "Bearer abc123");
        assert!(
            h[AUTHORIZATION].is_sensitive(),
            "the token must not be logged"
        );
        assert!(headers("https://h/x").get(AUTHORIZATION).is_none());
        // An explicit header still wins nothing away from the token: both are
        // rejected as a pair, so a caller does not end up sending two.
        let h = headers("https://h/x?header=Accept:text/plain");
        assert_eq!(h["accept"], "text/plain");
    }

    /// The request path is the one the URL named, byte for byte: nothing
    /// decoded twice, no `%2F` turned into a separator, and names that
    /// need encoding encoded.
    #[test]
    fn the_request_path_keeps_its_encoding() {
        let url = |u: &str, name: Option<&str>| {
            HttpEndpoint::new(Location::parse(u).unwrap())
                .unwrap()
                .url(name)
                .unwrap()
                .to_string()
        };
        assert_eq!(url("https://h/a%2520b", None), "https://h/a%2520b");
        assert_eq!(
            url("https://h/api/projects/group%2Fproject/raw", None),
            "https://h/api/projects/group%2Fproject/raw"
        );
        assert_eq!(
            url("http://h/in/", Some("M\u{e4}rz #1?100%.pdf")),
            "http://h/in/M%C3%A4rz%20%231%3F100%25.pdf"
        );
        assert_eq!(
            url("https://h/x?format=json", None),
            "https://h/x?format=json"
        );
        assert_eq!(url("http://[::1]:8080/x", None), "http://[::1]:8080/x");
    }

    #[test]
    fn statuses_map_to_the_same_kinds_everywhere() {
        use reqwest::StatusCode as S;
        for s in [S::UNAUTHORIZED, S::FORBIDDEN] {
            assert!(matches!(status_err(s), Error::Auth(_)), "{s}");
        }
        for s in [S::NOT_FOUND, S::GONE] {
            let e = status_err(s);
            assert!(e.is_not_found() && !e.is_transient(), "{s}: {e}");
        }
        assert!(status_err(S::SERVICE_UNAVAILABLE).is_transient());
        assert!(!status_err(S::CONFLICT).is_transient());
    }

    #[tokio::test]
    async fn an_unsupported_operation_names_the_scheme() {
        let ep = HttpEndpoint::new(Location::parse("https://h/x").unwrap()).unwrap();
        let err = ep.rename("a", "b").await.unwrap_err().to_string();
        assert_eq!(err, "scheme 'https' cannot rename");
    }

    /// Answer one request on `listener` with `reply(request head)`.
    pub(crate) async fn serve_once(
        listener: tokio::net::TcpListener,
        reply: impl FnOnce(&str) -> String + Send + 'static,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        let answer = reply(&String::from_utf8_lossy(&head));
        conn.write_all(answer.as_bytes()).await.unwrap();
        conn.shutdown().await.unwrap();
    }

    /// The size is the one the HEAD response announces, not the length of
    /// its (empty) body.
    #[tokio::test]
    async fn the_size_comes_from_the_head_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve_once(listener, |head| {
            assert!(head.starts_with("HEAD /f "), "{head}");
            "HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n".to_string()
        }));
        let ep = HttpEndpoint::new(Location::parse(&format!("http://127.0.0.1:{port}/f")).unwrap())
            .unwrap();
        assert_eq!(ep.size().await.unwrap(), Some(12345));
    }

    /// A redirect to another host takes neither the custom headers nor
    /// the token along; reqwest alone would have kept `X-Api-Key`.
    #[tokio::test]
    async fn headers_stay_with_their_own_host() {
        use tokio::io::AsyncReadExt;
        let here = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let there = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let there_port = there.local_addr().unwrap().port();
        let here_port = here.local_addr().unwrap().port();
        tokio::spawn(serve_once(here, move |head| {
            assert!(
                head.to_ascii_lowercase().contains("x-api-key: k3y"),
                "{head}"
            );
            // `localhost` is another origin than `127.0.0.1`.
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://localhost:{there_port}/f\r\n\
                 Content-Length: 0\r\n\r\n"
            )
        }));
        tokio::spawn(serve_once(there, |head| {
            let head = head.to_ascii_lowercase();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{head}",
                head.len()
            )
        }));
        let ep = HttpEndpoint::new(
            Location::parse(&format!(
                "http://127.0.0.1:{here_port}/f?header=X-Api-Key:k3y&token=t0k"
            ))
            .unwrap(),
        )
        .unwrap();
        let mut body = ep.receive().await.unwrap();
        let mut seen = String::new();
        body.read_to_string(&mut seen).await.unwrap();
        assert!(seen.starts_with("get /f "), "{seen}");
        assert!(!seen.contains("x-api-key"), "{seen}");
        assert!(!seen.contains("authorization"), "{seen}");
    }

    #[test]
    fn a_redirect_does_not_leave_tls() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(check_redirect(&u("https://a/x"), &u("http://a/x")).is_err());
        assert!(check_redirect(&u("https://a/x"), &u("ftp://a/x")).is_err());
        assert!(check_redirect(&u("https://a/x"), &u("https://b/x")).is_ok());
        assert!(check_redirect(&u("http://a/x"), &u("https://a/x")).is_ok());
        let e = check_redirect(&u("https://a/x"), &u("http://a/x")).unwrap_err();
        assert!(!e.is_transient(), "{e}");
    }

    #[test]
    fn own_options_do_not_reach_the_server() {
        for name in ["token", "timeout", "insecure", "method", "header"] {
            assert!(OWN_OPTIONS.contains(&name), "{name}");
        }
    }
}
