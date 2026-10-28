//! TLS 1.3 configuration for the clipboard channel.
//!
//! Both ends authenticate with the same self-signed certificate that is
//! used for DTLS. Instead of a CA, peers are identified by the sha256
//! fingerprint of their certificate:
//! - the listening side only accepts clients whose fingerprint is authorized
//!   (the same list that is used for incoming DTLS connections),
//! - the connecting side pins the fingerprint of the certificate presented by
//!   the peer over DTLS, so clipboard contents only ever go to the device that
//!   also receives our input events.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    version::TLS13,
};
use webrtc_dtls::crypto::Certificate;

use crate::crypto;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn cert_and_key(cert: &Certificate) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let chain = cert.certificate.clone();
    let key = PrivatePkcs8KeyDer::from(cert.private_key.serialized_der.clone()).into();
    (chain, key)
}

/// server config accepting only authorized client certificates
pub(crate) fn server_config(
    cert: &Certificate,
    authorized_keys: Arc<RwLock<HashMap<String, String>>>,
) -> Result<Arc<ServerConfig>, Error> {
    let provider = provider();
    let verifier = AuthorizedClientVerifier {
        authorized_keys,
        algorithms: provider.signature_verification_algorithms,
    };
    let (chain, key) = cert_and_key(cert);
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

/// client config accepting only a server presenting the given certificate
pub(crate) fn client_config(
    cert: &Certificate,
    server_fingerprint: String,
) -> Result<Arc<ClientConfig>, Error> {
    let provider = provider();
    let verifier = PinnedServerVerifier {
        fingerprint: server_fingerprint,
        algorithms: provider.signature_verification_algorithms,
    };
    let (chain, key) = cert_and_key(cert);
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(chain, key)?;
    Ok(Arc::new(config))
}

/// name sent in the SNI extension, ignored by [`PinnedServerVerifier`]
pub(crate) fn server_name() -> ServerName<'static> {
    ServerName::try_from("lan-mouse").expect("valid dns name")
}

#[derive(Debug)]
struct AuthorizedClientVerifier {
    authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AuthorizedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let fingerprint = crypto::generate_fingerprint(end_entity);
        if self
            .authorized_keys
            .read()
            .expect("lock")
            .contains_key(&fingerprint)
        {
            Ok(ClientCertVerified::assertion())
        } else {
            log::warn!("clipboard: rejected unauthorized client {fingerprint}");
            Err(Error::General("unauthorized client certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedServerVerifier {
    fingerprint: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fingerprint = crypto::generate_fingerprint(end_entity);
        if fingerprint == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            log::warn!(
                "clipboard: peer presented {fingerprint}, expected {}",
                self.fingerprint
            );
            Err(Error::General("unexpected server certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
