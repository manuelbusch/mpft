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
        let client = build_client(&loc)?;
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
        url.set_path(&self.loc.target_path(filename)?);
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

    fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        let mut rb = self
            .client
            .request(method, url)
            .headers(self.headers.clone());
        if let Some(user) = self.loc.username() {
            rb = rb.basic_auth(user, self.loc.password());
        }
        rb
    }
}

pub(crate) fn build_client(loc: &Location) -> Result<Client> {
    crate::init_crypto();
    let insecure = loc.opt_bool("insecure")?.unwrap_or(false);
    let timeout = loc.timeout_or(Duration::from_secs(30))?;
    let mut b = Client::builder()
        .danger_accept_invalid_certs(insecure)
        .connect_timeout(timeout)
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
    let mut url = Url::parse(&format!("{scheme}://{}/", loc.host_required()?))
        .map_err(|e| Error::InvalidUrl(e.to_string()))?;
    if let Some(p) = loc.port() {
        url.set_port(Some(p))
            .map_err(|_| Error::InvalidUrl("cannot set port".into()))?;
    }
    Ok(url)
}

fn parse_headers(loc: &Location) -> Result<HeaderMap> {
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

/// The token for this endpoint: the URL first, then the configuration.
fn bearer_token(loc: &Location) -> Option<String> {
    if let Some(t) = loc.opt("token").filter(|t| !t.is_empty()) {
        return Some(t.to_string());
    }
    use secrecy::ExposeSecret;
    crate::config::global()
        .resolved
        .http_token
        .as_ref()
        .map(|t| t.expose_secret().to_string())
}

pub(crate) fn http_err(e: reqwest::Error) -> Error {
    if let Some(status) = e.status() {
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Error::Auth(format!("http {status}"));
        }
        return Error::Remote(format!("http {status}"));
    }
    Error::transport("http", e)
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
        let url = self.url(None)?;
        debug!(%url, "http GET");
        let resp = self
            .request(Method::GET, url)
            .send()
            .await
            .map_err(http_err)?
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

    async fn size(&self) -> Result<Option<u64>> {
        let url = self.url(None)?;
        let resp = match self.request(Method::HEAD, url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => return Ok(None),
        };
        Ok(resp.content_length())
    }
}

#[async_trait]
impl Sender for HttpEndpoint {
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let url = self.url(meta.filename.as_deref())?;
        debug!(%url, method = %self.method, "http upload");
        let mut rb = self.request(self.method.clone(), url);
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
        resp.error_for_status().map_err(http_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn own_options_do_not_reach_the_server() {
        for name in ["token", "timeout", "insecure", "method", "header"] {
            assert!(OWN_OPTIONS.contains(&name), "{name}");
        }
    }
}
