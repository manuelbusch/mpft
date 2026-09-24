//! `s3://bucket/key` for S3-compatible object storage via `object_store`.
//!
//! Credentials and region come from the usual `AWS_*` environment variables
//! (or `user:pass@` in the URL for access key / secret). Options:
//! `endpoint=<url>` (MinIO etc., implies path-style), `region=`, `path_style=`,
//! `insecure=`.

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjPath;
use object_store::{ClientOptions, MultipartUpload, ObjectStore, ObjectStoreExt};
use tokio::io::AsyncReadExt;
use tokio_util::io::StreamReader;
use tracing::{debug, warn};

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
            // An inactivity limit, as everywhere else, and no deadline for a
            // whole request: object_store's own default of 30 s would cut off
            // any download that takes longer. `read_timeout` covers the wait
            // for a reply, which includes sending one part of an upload, and
            // then the gap between two reads of it.
            client = client
                .with_connect_timeout(t)
                .with_read_timeout(t)
                .with_timeout_disabled();
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
                "s3: the secret key cannot be asked for on demand; send it in the header \
                 (--via-credentials header) or let the relay use its own AWS credentials"
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
        } else if let Some(profile) = aws_profile(&loc, &cfg)? {
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

/// The store's error as one of ours: a missing object and refused
/// credentials the way every protocol reports them, the store's own word
/// for what another attempt would meet again, and the rest as transport
/// trouble. (object_store retries what it can itself first.)
fn s3_err(e: object_store::Error) -> Error {
    use object_store::Error as E;
    match e {
        E::NotFound { path, .. } => Error::not_found(format!("s3: not found: {path}")),
        // 403 is also what S3 says for a missing key to someone who may
        // not list the bucket, and for a signature that does not match.
        E::PermissionDenied { path, .. } => Error::Auth(format!("s3: access denied: {path}")),
        E::Unauthenticated { path, .. } => Error::Auth(format!("s3: not authenticated: {path}")),
        e @ (E::AlreadyExists { .. }
        | E::Precondition { .. }
        | E::NotModified { .. }
        | E::NotSupported { .. }
        | E::NotImplemented { .. }
        | E::InvalidPath { .. }) => Error::Remote(format!("s3: {e}")),
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
    fn scheme_name(&self) -> String {
        self.loc.scheme().to_string()
    }

    async fn send(&self, mut body: ByteStream, meta: &SendMeta) -> Result<()> {
        let path = self.obj_path(meta.filename.as_deref())?;
        debug!(bucket = %self.bucket, %path, "s3 put");
        let first = read_part(&mut body).await?;
        if first.len() < PART_SIZE {
            self.store.put(&path, first.into()).await.map_err(s3_err)?;
            return Ok(());
        }
        debug!(bucket = %self.bucket, %path, "s3 multipart upload");
        let upload = self.store.put_multipart(&path).await.map_err(s3_err)?;
        send_multipart(upload, first, &mut body).await
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

/// Size of one part of a multipart upload, and the most a single PUT carries.
const PART_SIZE: usize = 10 * 1024 * 1024;

/// Parts uploaded in parallel.
const PARTS_IN_FLIGHT: usize = 8;

/// Up to [`PART_SIZE`] bytes of `body`; fewer only at its end.
async fn read_part(body: &mut ByteStream) -> Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::with_capacity(PART_SIZE);
    while buf.len() < PART_SIZE {
        if body.read_buf(&mut buf).await? == 0 {
            break;
        }
    }
    Ok(buf.freeze())
}

/// Send `first` and the rest of `body` through `upload`, and complete it.
///
/// A multipart upload that is neither completed nor aborted keeps its parts,
/// and their cost, until a lifecycle rule removes them. Every way out other
/// than completion therefore aborts it: a failure here, and the future being
/// dropped (a cancel) through the guard.
async fn send_multipart(
    upload: Box<dyn MultipartUpload>,
    first: bytes::Bytes,
    body: &mut ByteStream,
) -> Result<()> {
    let mut guard = AbortOnDrop(Some(upload));
    let upload = guard.0.as_deref_mut().expect("armed");
    let result = upload_parts(upload, first, body).await;
    let mut upload = guard.0.take().expect("armed");
    if let Err(e) = result {
        debug!("aborting the multipart upload");
        if let Err(abort) = upload.abort().await {
            warn!("s3: could not abort the multipart upload: {abort}");
        }
        return Err(e);
    }
    Ok(())
}

/// Send `first` and the rest of `body` as parts, then complete the upload.
async fn upload_parts(
    upload: &mut dyn MultipartUpload,
    first: bytes::Bytes,
    body: &mut ByteStream,
) -> Result<()> {
    let mut parts = futures::stream::FuturesUnordered::new();
    parts.push(upload.put_part(first.into()));
    loop {
        while parts.len() >= PARTS_IN_FLIGHT {
            if let Some(done) = parts.next().await {
                done.map_err(s3_err)?;
            }
        }
        let part = read_part(body).await?;
        if part.is_empty() {
            break;
        }
        let last = part.len() < PART_SIZE;
        parts.push(upload.put_part(part.into()));
        if last {
            break;
        }
    }
    while let Some(done) = parts.next().await {
        done.map_err(s3_err)?;
    }
    upload.complete().await.map_err(s3_err)?;
    Ok(())
}

/// Aborts a multipart upload that is dropped before it was completed or
/// aborted. `Drop` cannot wait, so the abort runs as a task of its own.
struct AbortOnDrop(Option<Box<dyn MultipartUpload>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        let Some(mut upload) = self.0.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                debug!("aborting an unfinished multipart upload");
                rt.spawn(async move {
                    if let Err(e) = upload.abort().await {
                        warn!("s3: could not abort the multipart upload: {e}");
                    }
                });
            }
            Err(_) => warn!("s3: an unfinished multipart upload was left behind"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts what happens to it; parts fail from `fail_from` on, and a part
    /// never finishes when `hang` is set.
    #[derive(Debug, Default)]
    struct Upload {
        parts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        completed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
        fail_from: Option<usize>,
        fail_complete: bool,
        hang: bool,
    }

    #[async_trait]
    impl MultipartUpload for Upload {
        fn put_part(&mut self, _: object_store::PutPayload) -> object_store::UploadPart {
            let n = self
                .parts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let fail = self.fail_from.is_some_and(|f| n >= f);
            let hang = self.hang;
            Box::pin(async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                if fail {
                    return Err(object_store::Error::Generic {
                        store: "test",
                        source: "part refused".into(),
                    });
                }
                Ok(())
            })
        }
        async fn complete(&mut self) -> object_store::Result<object_store::PutResult> {
            if self.fail_complete {
                return Err(object_store::Error::Generic {
                    store: "test",
                    source: "complete refused".into(),
                });
            }
            self.completed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(object_store::PutResult {
                e_tag: None,
                version: None,
                extensions: Default::default(),
            })
        }
        async fn abort(&mut self) -> object_store::Result<()> {
            self.aborted
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    fn payload(len: usize) -> ByteStream {
        Box::pin(std::io::Cursor::new(vec![7u8; len]))
    }

    #[tokio::test]
    async fn every_failed_multipart_upload_is_aborted() {
        use std::sync::atomic::Ordering::Relaxed;
        let body_len = PART_SIZE * 2 + 5;

        let ok = Upload::default();
        let (completed, aborted) = (ok.completed.clone(), ok.aborted.clone());
        let mut body = payload(body_len);
        let first = read_part(&mut body).await.unwrap();
        send_multipart(Box::new(ok), first, &mut body)
            .await
            .unwrap();
        assert!(completed.load(Relaxed) && !aborted.load(Relaxed));

        for up in [
            Upload {
                fail_from: Some(1),
                ..Default::default()
            },
            Upload {
                fail_complete: true,
                ..Default::default()
            },
        ] {
            let aborted = up.aborted.clone();
            let mut body = payload(body_len);
            let first = read_part(&mut body).await.unwrap();
            assert!(
                send_multipart(Box::new(up), first, &mut body)
                    .await
                    .is_err()
            );
            assert!(aborted.load(Relaxed));
        }

        // Dropped mid-way, as a cancel does.
        let up = Upload {
            hang: true,
            ..Default::default()
        };
        let aborted = up.aborted.clone();
        let mut body = payload(body_len);
        let first = read_part(&mut body).await.unwrap();
        let sending = send_multipart(Box::new(up), first, &mut body);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), sending)
                .await
                .is_err()
        );
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(aborted.load(Relaxed), "a dropped upload is aborted");
    }

    /// A download that takes longer than the timeout, but never pauses that
    /// long, is not cut off.
    #[tokio::test]
    async fn a_slow_but_steady_download_is_not_cut_off() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = conn.read(&mut req).await;
            conn.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\
                  Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nETag: \"x\"\r\n\r\n",
            )
            .await
            .unwrap();
            for _ in 0..15 {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                conn.write_all(b"z").await.unwrap();
            }
        });
        let ep = S3Endpoint::new(
            Location::parse(&format!(
                "s3://k:s@bucket/slow.bin?endpoint=http://127.0.0.1:{port}&timeout=1"
            ))
            .unwrap(),
        )
        .unwrap();
        let mut body = ep.receive().await.expect("get");
        let mut got = Vec::new();
        body.read_to_end(&mut got).await.expect("a steady trickle");
        assert_eq!(got, b"zzzzzzzzzzzzzzz");
    }

    #[test]
    fn a_missing_object_and_a_refusal_are_told_apart() {
        let src = || -> Box<dyn std::error::Error + Send + Sync> { "x".into() };
        let e = s3_err(object_store::Error::NotFound {
            path: "b/k".into(),
            source: src(),
        });
        assert!(e.is_not_found() && !e.is_transient(), "{e}");
        for e in [
            object_store::Error::PermissionDenied {
                path: "b/k".into(),
                source: src(),
            },
            object_store::Error::Unauthenticated {
                path: "b/k".into(),
                source: src(),
            },
        ] {
            let e = s3_err(e);
            assert!(matches!(e, Error::Auth(_)), "{e}");
            assert_eq!(e.exit_code(), 4);
        }
    }

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
