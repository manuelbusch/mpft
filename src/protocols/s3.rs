//! `s3://bucket/key` for S3-compatible object storage via `object_store`.
//!
//! Credentials and region come from the usual `AWS_*` environment variables
//! (or `user:pass@` in the URL for access key / secret). Options:
//! `endpoint=<url>` (MinIO etc., implies path-style), `region=`, `path_style=`,
//! `insecure=`.

use std::sync::Arc;

use async_trait::async_trait;
use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::buffered::BufWriter;
use object_store::path::Path as ObjPath;
use object_store::{ClientOptions, ObjectStore, ObjectStoreExt};
use tokio::io::AsyncWriteExt;
use tokio_util::io::StreamReader;
use tracing::debug;

use crate::{
    ByteStream, Endpoint, Entry, Error, Location, Receiver, Result, SendMeta, Sender, stream,
};

pub struct S3Endpoint {
    loc: Location,
    bucket: String,
    key: String,
    store: Arc<dyn ObjectStore>,
}

impl S3Endpoint {
    pub fn new(loc: Location) -> Result<Self> {
        crate::init_crypto();
        let (bucket, key) = match loc.path().split_once('/') {
            Some((b, k)) => (b.to_string(), k.to_string()),
            None => (loc.path().to_string(), String::new()),
        };
        if bucket.is_empty() {
            return Err(Error::InvalidUrl("s3: missing bucket".into()));
        }

        let cfg = crate::config::global();
        let insecure = loc.opt_bool("insecure")?.unwrap_or(false);
        let endpoint = loc
            .opt("endpoint")
            .map(String::from)
            .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok())
            .or_else(|| cfg.s3.endpoint.clone());
        let path_style = loc
            .opt_bool("path_style")?
            .or(cfg.s3.path_style)
            .unwrap_or(endpoint.is_some());

        // Client options first: the builder's `with_allow_http` writes into
        // them, so setting them afterwards would undo it.
        let mut client = ClientOptions::new();
        if insecure {
            client = client
                .with_allow_invalid_certificates(true)
                .with_allow_http(true);
        }
        if let Some(t) = loc.timeout()? {
            // `timeout` bounds one request (object_store defaults to 30 s too),
            // `read_timeout` the gap between two reads of a response.
            client = client
                .with_connect_timeout(t)
                .with_read_timeout(t)
                .with_timeout(t);
        } else {
            client = client
                .with_timeout_disabled()
                .with_read_timeout_disabled()
                .with_connect_timeout_disabled();
        }

        let mut b = AmazonS3Builder::from_env()
            .with_bucket_name(&bucket)
            .with_client_options(client)
            .with_virtual_hosted_style_request(!path_style);
        if let Some(ep) = &endpoint {
            b = b
                .with_endpoint(ep)
                .with_allow_http(ep.starts_with("http://"));
        }
        if let Some(r) = loc.opt("region") {
            b = b.with_region(r);
        } else if std::env::var_os("AWS_REGION").is_none()
            && std::env::var_os("AWS_DEFAULT_REGION").is_none()
        {
            b = b.with_region(cfg.s3.region.as_deref().unwrap_or("us-east-1"));
        }
        if let (Some(u), Some(p)) = (loc.username(), loc.password()) {
            b = b.with_access_key_id(u).with_secret_access_key(p);
        }
        let store = b.build().map_err(|e| Error::transport("s3", e))?;
        Ok(S3Endpoint {
            loc,
            bucket,
            key,
            store: Arc::new(store),
        })
    }

    fn obj_path(&self, filename: Option<&str>) -> Result<ObjPath> {
        let key = match (self.loc.is_dir_target(), filename) {
            (true, Some(name)) => format!("{}{}", self.key, crate::location::safe_name(name)?),
            _ => self.key.clone(),
        };
        Ok(ObjPath::from(key))
    }
}

fn s3_err(e: object_store::Error) -> Error {
    match e {
        object_store::Error::NotFound { path, .. } => {
            Error::Remote(format!("s3: not found: {path}"))
        }
        other => Error::transport("s3", other),
    }
}

impl Endpoint for S3Endpoint {
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
impl Receiver for S3Endpoint {
    async fn receive(&self) -> Result<ByteStream> {
        let path = self.obj_path(None)?;
        debug!(bucket = %self.bucket, %path, "s3 get");
        let res = self.store.get(&path).await.map_err(s3_err)?;
        let reader = StreamReader::new(res.into_stream().map_err(std::io::Error::other));
        Ok(stream::boxed(stream::Idle::maybe(
            reader,
            self.loc.timeout()?,
        )))
    }

    async fn list(&self) -> Result<Vec<Entry>> {
        let prefix = if self.key.is_empty() {
            None
        } else {
            Some(ObjPath::from(self.key.trim_end_matches('/')))
        };
        let res = self
            .store
            .list_with_delimiter(prefix.as_ref())
            .await
            .map_err(s3_err)?;
        let mut out: Vec<Entry> = res
            .common_prefixes
            .iter()
            .map(|p| Entry {
                name: p.filename().unwrap_or("").to_string(),
                size: None,
                is_dir: true,
                modified: None,
            })
            .chain(res.objects.iter().map(|o| Entry {
                name: o.location.filename().unwrap_or("").to_string(),
                size: Some(o.size),
                is_dir: false,
                modified: Some(o.last_modified.into()),
            }))
            .filter(|e| !e.name.is_empty())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn size(&self) -> Result<Option<u64>> {
        match self.store.head(&self.obj_path(None)?).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(_) => Ok(None),
        }
    }
}

#[async_trait]
impl Sender for S3Endpoint {
    async fn send(&self, body: ByteStream, meta: &SendMeta) -> Result<()> {
        let path = self.obj_path(meta.filename.as_deref())?;
        debug!(bucket = %self.bucket, %path, "s3 put");
        let mut w = stream::Idle::maybe(
            BufWriter::new(self.store.clone(), path),
            self.loc.timeout()?,
        );
        let result = stream::pipe(body, &mut w).await;
        match result {
            Ok(_) => w.shutdown().await?,
            Err(e) => {
                let _ = w.into_inner().abort().await;
                return Err(e);
            }
        }
        Ok(())
    }
}
