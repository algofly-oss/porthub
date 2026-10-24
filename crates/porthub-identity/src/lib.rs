//! Certificate-key identity shared by the native agent and gateway. Pins must
//! come from an authenticated enrollment/API response, never an unauthenticated
//! origin probe. TLS handshake signatures still prove possession of the key.
use anyhow::{Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn spki_sha256(certificate: &[u8]) -> Result<[u8; 32]> {
    let (remaining, certificate) = x509_parser::parse_x509_certificate(certificate)
        .map_err(|_| anyhow::anyhow!("invalid certificate"))?;
    anyhow::ensure!(remaining.is_empty(), "trailing certificate data");
    Ok(Sha256::digest(certificate.public_key().raw).into())
}
struct Pinned {
    expected: [u8; 32],
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl std::fmt::Debug for Pinned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertificateKey")
            .finish_non_exhaustive()
    }
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let actual = spki_sha256(certificate.as_ref())
            .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if actual.ct_eq(&self.expected).unwrap_u8() != 1 {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
/// A supplied pin is the trust anchor. Public CA/name validation remains the
/// default for every endpoint without an explicitly authenticated pin.
pub fn pinned_client_config(pin: &str) -> Result<rustls::ClientConfig> {
    let expected: [u8; 32] = hex::decode(pin)
        .context("invalid SHA256 key pin")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA256 key pin must contain 32 bytes"))?;
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Pinned {
        expected,
        algorithms: provider.signature_verification_algorithms,
    };
    Ok(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
            .with_no_client_auth(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_identity_is_stable_across_renewals_and_rejects_changed_keys_and_bad_der() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["gateway.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let renewed = rcgen::CertificateParams::new(vec!["renamed.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["gateway.example".into()]).unwrap();
        assert_eq!(
            spki_sha256(cert.der()).unwrap(),
            spki_sha256(renewed.der()).unwrap()
        );
        assert_ne!(
            spki_sha256(cert.der()).unwrap(),
            spki_sha256(other.cert.der()).unwrap()
        );
        assert!(spki_sha256(b"invalid").is_err());
        assert!(pinned_client_config("abcd").is_err());
        assert!(pinned_client_config(&"x".repeat(64)).is_err());
    }
}

pub mod origin;
