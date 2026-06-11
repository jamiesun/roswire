use crate::error::{RosWireError, RosWireResult};
use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, STANDARD_NO_PAD as BASE64_NO_PAD,
};
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SHA256_HEX_LEN: usize = 64;
const SHA256_BYTE_LEN: usize = 32;

/// A pinned RouterOS TLS certificate fingerprint (SHA-256 of the leaf
/// certificate DER), stored as normalized lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFingerprint {
    hex: String,
}

impl TlsFingerprint {
    /// Parses a user-provided fingerprint. Accepts an optional `sha256:` prefix
    /// followed by either hex (with optional `:`/whitespace separators) or
    /// base64 (padded or unpadded) of the 32-byte SHA-256 digest.
    pub fn parse(value: &str) -> RosWireResult<Self> {
        let trimmed = value.trim();
        let body = strip_sha256_prefix(trimmed);

        if let Some(hex) = normalize_hex(body) {
            return Ok(Self { hex });
        }
        if let Some(hex) = base64_to_hex(body) {
            return Ok(Self { hex });
        }

        Err(Box::new(RosWireError::usage(format!(
            "invalid TLS fingerprint `{value}`; expected SHA-256 as hex or base64, optionally prefixed with sha256:",
        ))))
    }

    /// Parses an optional fingerprint reference.
    pub fn parse_optional(value: Option<&str>) -> RosWireResult<Option<Self>> {
        match value {
            Some(value) if !value.trim().is_empty() => Self::parse(value).map(Some),
            _ => Ok(None),
        }
    }

    fn matches_der(&self, der: &[u8]) -> bool {
        hex_encode(Sha256::digest(der).as_slice()) == self.hex
    }
}

fn strip_sha256_prefix(value: &str) -> &str {
    if value.len() >= 7 && value[..7].eq_ignore_ascii_case("sha256:") {
        &value[7..]
    } else {
        value
    }
}

fn normalize_hex(value: &str) -> Option<String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if cleaned.len() == SHA256_HEX_LEN && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(cleaned.to_ascii_lowercase())
    } else {
        None
    }
}

fn base64_to_hex(value: &str) -> Option<String> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = BASE64_STANDARD
        .decode(&cleaned)
        .or_else(|_| BASE64_NO_PAD.decode(&cleaned))
        .ok()?;
    if decoded.len() == SHA256_BYTE_LEN {
        Some(hex_encode(&decoded))
    } else {
        None
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0F) as usize] as char);
    }
    encoded
}

/// Builds a rustls client config. When a fingerprint is supplied, the leaf
/// certificate is pinned by SHA-256 (handshake signatures are still verified);
/// otherwise standard public-CA (webpki) verification is used.
pub fn client_config(fingerprint: Option<&TlsFingerprint>) -> Arc<ClientConfig> {
    match fingerprint {
        Some(fingerprint) => Arc::new(pinned_client_config(fingerprint.clone())),
        None => Arc::new(webpki_client_config()),
    }
}

fn webpki_client_config() -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn pinned_client_config(fingerprint: TlsFingerprint) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedServerCertVerifier {
        fingerprint,
        provider,
    });
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

#[derive(Debug)]
struct PinnedServerCertVerifier {
    fingerprint: TlsFingerprint,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self.fingerprint.matches_der(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "RouterOS TLS certificate fingerprint does not match the pinned tls_fingerprint"
                    .to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{client_config, hex_encode, TlsFingerprint};
    use sha2::{Digest, Sha256};

    fn digest_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
    }

    #[test]
    fn parse_accepts_hex_with_and_without_prefix_and_separators() {
        let hex = digest_hex(b"roswire-cert");
        let plain = TlsFingerprint::parse(&hex).expect("plain hex should parse");
        let prefixed =
            TlsFingerprint::parse(&format!("SHA256:{hex}")).expect("prefixed hex should parse");

        let colon_separated = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let separated =
            TlsFingerprint::parse(&colon_separated).expect("colon-separated hex should parse");

        assert_eq!(plain, prefixed);
        assert_eq!(plain, separated);
    }

    #[test]
    fn parse_accepts_base64() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let digest = Sha256::digest(b"roswire-cert");
        let base64 = STANDARD.encode(digest);
        let from_base64 =
            TlsFingerprint::parse(&format!("sha256:{base64}")).expect("base64 should parse");
        let from_hex =
            TlsFingerprint::parse(&digest_hex(b"roswire-cert")).expect("hex should parse");

        assert_eq!(from_base64, from_hex);
    }

    #[test]
    fn parse_rejects_invalid_values() {
        TlsFingerprint::parse("not-a-fingerprint").expect_err("garbage should fail");
        TlsFingerprint::parse("abc123").expect_err("short hex should fail");
        TlsFingerprint::parse("").expect_err("empty should fail");
    }

    #[test]
    fn parse_optional_handles_none_and_blank() {
        assert!(TlsFingerprint::parse_optional(None)
            .expect("none is ok")
            .is_none());
        assert!(TlsFingerprint::parse_optional(Some("  "))
            .expect("blank is ok")
            .is_none());
        assert!(TlsFingerprint::parse_optional(Some(&digest_hex(b"x")))
            .expect("valid is ok")
            .is_some());
    }

    #[test]
    fn matches_der_compares_certificate_digest() {
        let fingerprint = TlsFingerprint::parse(&digest_hex(b"leaf-der-bytes"))
            .expect("fingerprint should parse");
        assert!(fingerprint.matches_der(b"leaf-der-bytes"));
        assert!(!fingerprint.matches_der(b"other-der-bytes"));
    }

    #[test]
    fn client_config_builds_for_pinned_and_default() {
        let pinned = TlsFingerprint::parse(&digest_hex(b"leaf")).expect("parse");
        let _ = client_config(Some(&pinned));
        let _ = client_config(None);
    }
}
