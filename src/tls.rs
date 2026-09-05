//! Shared rustls client configuration (platform trust store, optional
//! "insecure" mode that skips certificate verification).

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::ConfigVerifierExt;

use crate::{Error, Result};

/// Build a rustls client config. With `insecure = true` every certificate is
/// accepted (for self-signed test servers only).
pub fn client_config(insecure: bool) -> Result<Arc<ClientConfig>> {
    crate::init_crypto();
    if insecure {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::transport("tls", e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        return Ok(Arc::new(cfg));
    }
    let cfg = ClientConfig::with_platform_verifier().map_err(|e| Error::transport("tls", e))?;
    Ok(Arc::new(cfg))
}

/// Certificate verifier that accepts everything. Only used with `?insecure=true`.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
