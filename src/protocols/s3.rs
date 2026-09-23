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
        } else if loc.username().is_some() && loc.brokers().password.is_some() {
            // The store signs every request itself and is built once, so
            // a key that is only handed out per login has nowhere to go.
            return Err(Error::Auth(
                "s3: the secret key cannot be asked for on demand; send it in the header                  (--via-credentials header) or let the relay use its own AWS credentials"
                    .into(),
            ));
        } else if let (Some(id), Some(key)) = (
            &cfg.resolved.s3_access_key_id,
            &cfg.resolved.s3_secret_access_key,
        ) {
            use secrecy::ExposeSecret;
            b = b
                .with_access_key_id(id.expose_secret())
                .with_secret_access_key(key.expose_secret());
        } else if let Some(profile) = aws_profile(&loc, cfg)? {
            b = attach_chain(b, profile, loc.opt("region").map(String::from));
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
        obj_key(&key)
    }
}

/// An object key as it is, not escaped: `Path::from` would percent-encode
/// characters such as `%`, `#` or `[`, storing a key under another name
/// than the one asked for, and one that a listing hands back escaped.
fn obj_key(key: &str) -> Result<ObjPath> {
    ObjPath::parse(key).map_err(|e| Error::InvalidUrl(format!("s3: {e}")))
}

/// Which AWS profile to take credentials from, if the chain should be used
/// at all: `?profile=`, `[s3] profile`, `$AWS_PROFILE`, or `?aws_chain=true`
/// for the chain without a named profile.
fn aws_profile(loc: &Location, cfg: &crate::Config) -> Result<Option<Option<String>>> {
    let named = loc
        .opt("profile")
        .map(String::from)
        .or_else(|| cfg.s3.profile.clone())
        .or_else(|| std::env::var("AWS_PROFILE").ok())
        .filter(|p| !p.is_empty());
    if named.is_some() {
        return Ok(Some(named));
    }
    Ok(loc.opt_bool("aws_chain")?.unwrap_or(false).then_some(None))
}

#[cfg(feature = "s3-aws-auth")]
fn attach_chain(
    b: AmazonS3Builder,
    profile: Option<String>,
    region: Option<String>,
) -> AmazonS3Builder {
    b.with_credentials(std::sync::Arc::new(chain::Chain::new(profile, region)))
}

/// Without the feature the profile is only a hint that something is missing.
#[cfg(not(feature = "s3-aws-auth"))]
fn attach_chain(
    b: AmazonS3Builder,
    profile: Option<String>,
    _region: Option<String>,
) -> AmazonS3Builder {
    tracing::warn!(
        "AWS profile {} is ignored: compiled without the 's3-aws-auth' feature, \
         so only AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY and user:pass@ work",
        profile.as_deref().unwrap_or("(default)")
    );
    b
}

/// Credentials from the AWS chain instead of from the URL: the SSO cache
/// (`aws sso login`), `~/.aws/config` profiles, AssumeRole, web identity and
/// the instance metadata service. Only compiled with the `s3-aws-auth`
/// feature, and only used when a profile is named or `?aws_chain=true` asks
/// for it, so nothing reaches for the network unbidden.
#[cfg(feature = "s3-aws-auth")]
mod chain {
    use std::sync::Arc;

    use async_trait::async_trait;
    use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
    use object_store::CredentialProvider;
    use object_store::aws::AwsCredential;
    use tokio::sync::OnceCell;
    use tracing::debug;

    #[derive(Debug)]
    pub struct Chain {
        profile: Option<String>,
        region: Option<String>,
        /// Loaded on first use: reading the SSO cache and the profile files
        /// is async, while the endpoint is built synchronously.
        loaded: OnceCell<SharedCredentialsProvider>,
    }

    impl Chain {
        pub fn new(profile: Option<String>, region: Option<String>) -> Self {
            Chain {
                profile,
                region,
                loaded: OnceCell::new(),
            }
        }

        async fn provider(&self) -> &SharedCredentialsProvider {
            self.loaded
                .get_or_init(|| async {
                    debug!(profile = ?self.profile, "loading the AWS credential chain");
                    let mut b = aws_config::defaults(aws_config::BehaviorVersion::latest());
                    if let Some(p) = &self.profile {
                        b = b.profile_name(p);
                    }
                    if let Some(r) = &self.region {
                        b = b.region(aws_config::Region::new(r.clone()));
                    }
                    b.load()
                        .await
                        .credentials_provider()
                        .expect("the default chain always provides one")
                })
                .await
        }
    }

    #[async_trait]
    impl CredentialProvider for Chain {
        type Credential = AwsCredential;

        async fn get_credential(&self) -> object_store::Result<Arc<AwsCredential>> {
            let creds = self
                .provider()
                .await
                .provide_credentials()
                .await
                .map_err(|e| object_store::Error::Generic {
                    store: "S3",
                    source: Box::new(e),
                })?;
            Ok(Arc::new(AwsCredential {
                key_id: creds.access_key_id().to_string(),
                secret_key: creds.secret_access_key().to_string(),
                token: creds.session_token().map(String::from),
            }))
        }
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
            Some(obj_key(self.key.trim_end_matches('/'))?)
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

    fn supports_remove(&self) -> bool {
        true
    }

    async fn remove(&self, name: &str) -> Result<()> {
        let sibling = self.loc.sibling(name)?;
        let key = sibling.path().split_once('/').map(|(_, k)| k).unwrap_or("");
        let path = obj_key(key)?;
        debug!(bucket = %self.bucket, %path, "s3 delete");
        self.store.delete(&path).await.map_err(s3_err)
    }

    /// Keys are flat; a "directory" appears with its first object.
    fn supports_mkdir(&self) -> bool {
        true
    }

    async fn mkdir_all(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stored_as_they_are_named() {
        let ep = S3Endpoint::new(
            Location::parse("s3://bucket/in/?endpoint=http://127.0.0.1:1").unwrap(),
        )
        .unwrap();
        let path = ep.obj_path(Some("report [1] #2 100%.pdf")).unwrap();
        assert_eq!(path.as_ref(), "in/report [1] #2 100%.pdf");
        // A listing hands the key back the same way.
        assert_eq!(path.filename(), Some("report [1] #2 100%.pdf"));
    }
}
