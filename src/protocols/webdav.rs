//! `webdav://` (HTTP) and `webdavs://` (HTTPS): GET / PUT / PROPFIND via reqwest_dav.

use async_trait::async_trait;
use futures::TryStreamExt;
use percent_encoding::percent_decode_str;
use reqwest_dav::{Auth, Client, ClientBuilder, Depth, list_cmd::ListEntity};
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::debug;

use super::http::{base_url, build_client};
use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, SendMeta, Sender, stream,
};

pub struct WebDavEndpoint {
    loc: Location,
    client: Client,
}

impl WebDavEndpoint {
    pub fn new(loc: Location) -> Result<Self> {
        let base = base_url(&loc, &["http", "https"])?;
        let auth = match (loc.username(), loc.password()) {
            (Some(u), p) => Auth::Basic(u.to_string(), p.unwrap_or("").to_string()),
            _ => Auth::Anonymous,
        };
        let client = ClientBuilder::new()
            .set_host(base.to_string().trim_end_matches('/').to_string())
            .set_auth(auth)
            .set_agent(build_client(&loc)?)
            .build()
            .map_err(dav_err)?;
        Ok(WebDavEndpoint { loc, client })
    }
}

fn dav_err(e: reqwest_dav::Error) -> Error {
    match e {
        reqwest_dav::Error::Reqwest(e) => super::http::http_err(e),
        reqwest_dav::Error::ReqwestDecode(e) => Error::Remote(format!("webdav: {e:?}")),
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
        let resp = self.client.get(self.loc.path()).await.map_err(dav_err)?;
        let reader = StreamReader::new(resp.bytes_stream().map_err(std::io::Error::other));
        Ok(stream::boxed(reader))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        let path = self.loc.path();
        let entities = self
            .client
            .list(path, Depth::Number(1))
            .await
            .map_err(dav_err)?;
        let self_name = href_name(path);
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
        let entities = match self.client.list(self.loc.path(), Depth::Number(0)).await {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        Ok(entities.into_iter().find_map(|e| match e {
            ListEntity::File(f) => Some(f.content_length.max(0) as u64),
            ListEntity::Folder(_) => None,
        }))
    }
}

#[async_trait]
impl Sender for WebDavEndpoint {
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let target = self.loc.target_path(meta.filename.as_deref())?;
        debug!(%target, "webdav PUT");
        let body = reqwest::Body::wrap_stream(ReaderStream::new(body));
        self.client.put(&target, body).await.map_err(dav_err)
    }
}
