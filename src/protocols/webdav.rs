//! `webdav://` (HTTP) and `webdavs://` (HTTPS): GET / PUT / PROPFIND via reqwest_dav.
//!
//! reqwest_dav puts a path into its URL (and the `Destination` of a MOVE)
//! as it is given, so every path handed to it here is already encoded
//! ([`Location::encoded_path`]).

use async_trait::async_trait;
use futures::TryStreamExt;
use percent_encoding::percent_decode_str;
use reqwest_dav::{Auth, Client, ClientBuilder, Depth, list_cmd::ListEntity};
use secrecy::ExposeSecret;
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::debug;

use super::http::{base_url, build_client};
use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, SendMeta, Sender, stream,
};

pub struct WebDavEndpoint {
    loc: Location,
    host: String,
    /// The HTTP client with its connection pool, shared by every operation.
    agent: reqwest::Client,
}

impl WebDavEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        let base = base_url(&loc, &["http", "https"])?;
        let agent = build_client(&loc, super::http::guarded_redirects(false))?;
        Ok(WebDavEndpoint {
            host: base.to_string().trim_end_matches('/').to_string(),
            loc,
            agent,
        })
    }

    /// A DAV client for one operation, with the password fetched for it
    /// only. The underlying HTTP client is shared, so this costs no
    /// connection.
    async fn client(&self) -> Result<Client> {
        let auth = match self.loc.username() {
            Some(u) => {
                let pw = self.loc.login_password(1).await?;
                let pw = pw.as_ref().map(|p| p.expose_secret()).unwrap_or("");
                Auth::Basic(u.to_string(), pw.to_string())
            }
            None => Auth::Anonymous,
        };
        ClientBuilder::new()
            .set_host(self.host.clone())
            .set_auth(auth)
            .set_agent(self.agent.clone())
            .build()
            .map_err(dav_err)
    }
}

fn dav_err(e: reqwest_dav::Error) -> Error {
    use reqwest_dav::DecodeError as D;
    match e {
        reqwest_dav::Error::Reqwest(e) => super::http::http_err(e),
        reqwest_dav::Error::ReqwestDecode(e) => Error::Remote(format!("webdav: {e:?}")),
        // A status other than the one expected comes back decoded; it
        // means what it means over plain HTTP.
        reqwest_dav::Error::Decode(D::Server(reqwest_dav::ServerError {
            response_code, ..
        }))
        | reqwest_dav::Error::Decode(D::StatusMismatched(reqwest_dav::StatusMismatchedError {
            response_code,
            ..
        })) => match reqwest::StatusCode::from_u16(response_code) {
            Ok(status) => super::http::status_err(status),
            Err(_) => Error::Remote(format!("webdav: status {response_code}")),
        },
        reqwest_dav::Error::Decode(e) => Error::Remote(format!("webdav: {e:?}")),
        reqwest_dav::Error::MissingAuthContext => {
            Error::Auth("webdav: server requires authentication".into())
        }
    }
}

impl Endpoint for WebDavEndpoint {
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

fn href_name(href: &str) -> String {
    let trimmed = href.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    percent_decode_str(last).decode_utf8_lossy().into_owned()
}

#[async_trait]
impl Receiver for WebDavEndpoint {
    async fn receive(&self) -> Result<ByteStream> {
        debug!(path = self.loc.path(), "webdav GET");
        let resp = self
            .client()
            .await?
            .get(&self.loc.encoded_path())
            .await
            .map_err(dav_err)?;
        let reader = StreamReader::new(resp.bytes_stream().map_err(std::io::Error::other));
        let reader = stream::Idle::maybe(reader, self.loc.timeout()?);
        Ok(stream::boxed(reader))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        let path = self.loc.encoded_path();
        let entities = self
            .client()
            .await?
            .list(&path, Depth::Number(1))
            .await
            .map_err(dav_err)?;
        let self_name = href_name(&path);
        let mut out = Vec::new();
        for (i, ent) in entities.into_iter().enumerate() {
            match ent {
                ListEntity::Folder(f) => {
                    let name = href_name(&f.href);
                    // The first entry is the collection itself.
                    if i == 0 && (name == self_name || name.is_empty()) {
                        continue;
                    }
                    out.push(Entry {
                        name,
                        size: None,
                        is_dir: true,
                        modified: Some(f.last_modified.into()),
                    });
                }
                ListEntity::File(f) => out.push(Entry {
                    name: href_name(&f.href),
                    size: Some(f.content_length.max(0) as u64),
                    is_dir: false,
                    modified: Some(f.last_modified.into()),
                }),
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn size(&self) -> Result<Option<u64>> {
        let entities = match self
            .client()
            .await?
            .list(&self.loc.encoded_path(), Depth::Number(0))
            .await
            .map_err(dav_err)
        {
            Ok(e) => e,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(entities.into_iter().find_map(|e| match e {
            ListEntity::File(f) => Some(f.content_length.max(0) as u64),
            ListEntity::Folder(_) => None,
        }))
    }
}

#[async_trait]
impl Sender for WebDavEndpoint {
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let target = self.loc.encoded_target_path(meta.filename.as_deref())?;
        debug!(%target, "webdav PUT");
        let body = reqwest::Body::wrap_stream(ReaderStream::new(body));
        self.client()
            .await?
            .put(&target, body)
            .await
            .map_err(dav_err)
    }

    async fn is_dir(&self) -> Result<bool> {
        let entities = self
            .client()
            .await?
            .list(&self.loc.encoded_path(), Depth::Number(0))
            .await
            .map_err(dav_err);
        match entities {
            Ok(e) => Ok(matches!(e.first(), Some(ListEntity::Folder(_)))),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn supports_rename(&self) -> bool {
        true
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        // Encoded, the destination is plain ASCII and fits in its header.
        let from = self.loc.sibling(from)?.encoded_path();
        let to = self.loc.sibling(to)?.encoded_path();
        debug!(%from, %to, "webdav MOVE");
        self.client().await?.mv(&from, &to).await.map_err(dav_err)
    }

    fn supports_remove(&self) -> bool {
        true
    }

    async fn remove(&self, name: &str) -> Result<()> {
        let path = self.loc.sibling(name)?.encoded_path();
        debug!(%path, "webdav DELETE");
        self.client().await?.delete(&path).await.map_err(dav_err)
    }

    fn supports_mkdir(&self) -> bool {
        true
    }

    async fn mkdir_all(&self) -> Result<()> {
        let dir = self.loc.parent()?.encoded_path();
        // MKCOL one collection at a time; one that exists is left alone.
        let client = self.client().await?;
        let mut path = String::new();
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            path.push('/');
            path.push_str(part);
            if client.list(&path, Depth::Number(0)).await.is_ok() {
                continue;
            }
            debug!(%path, "webdav MKCOL");
            client.mkcol(&path).await.map_err(dav_err)?;
        }
        Ok(())
    }
}
