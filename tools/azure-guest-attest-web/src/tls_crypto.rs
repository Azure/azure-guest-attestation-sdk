// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;
#[cfg(any(not(feature = "symcrypt"), test))]
use std::sync::Arc;

pub(crate) fn server_builder(
) -> io::Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>> {
    #[cfg(feature = "symcrypt")]
    let provider = rustls_symcrypt::default_symcrypt_provider_arc();
    #[cfg(not(feature = "symcrypt"))]
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("TLS protocol configuration: {e}")))
}

#[cfg(not(feature = "symcrypt"))]
pub(crate) fn self_signed(sans: Vec<String>) -> io::Result<(String, String)> {
    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| io::Error::other(format!("generate self-signed certificate: {e}")))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(feature = "symcrypt")]
pub(crate) fn self_signed(sans: Vec<String>) -> io::Result<(String, String)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
    let signer = SymCryptSigner::new(
        EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa)
            .map_err(|e| io::Error::other(format!("SymCrypt TLS key generation: {e}")))?,
    )?;
    let private = signer
        .key
        .export_private_key()
        .map_err(|e| io::Error::other(format!("SymCrypt TLS key export: {e}")))?;
    let sec1 = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(1);
            writer.next().write_bytes(&private);
            writer
                .next()
                .write_tagged(yasna::Tag::context(0), |writer| {
                    writer.write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                        1, 2, 840, 10045, 3, 1, 7,
                    ]));
                });
            writer
                .next()
                .write_tagged(yasna::Tag::context(1), |writer| {
                    writer.write_bitvec_bytes(&signer.public, signer.public.len() * 8);
                });
        });
    });
    let encoded = STANDARD.encode(sec1);
    let mut key_pem = String::from("-----BEGIN EC PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        key_pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        key_pem.push('\n');
    }
    key_pem.push_str("-----END EC PRIVATE KEY-----\n");
    let key_pair = rcgen::KeyPair::from_remote(Box::new(signer))
        .map_err(|e| io::Error::other(format!("SymCrypt certificate signer: {e}")))?;
    let mut params = rcgen::CertificateParams::new(sans)
        .map_err(|e| io::Error::other(format!("TLS certificate parameters: {e}")))?;
    let mut serial = [0; 20];
    symcrypt::symcrypt_random(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 1;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::other(format!("SymCrypt certificate signing: {e}")))?;
    Ok((cert.pem(), key_pem))
}

#[cfg(feature = "symcrypt")]
struct SymCryptSigner {
    key: symcrypt::ecc::EcKey,
    public: Vec<u8>,
}

#[cfg(feature = "symcrypt")]
impl SymCryptSigner {
    fn new(key: symcrypt::ecc::EcKey) -> io::Result<Self> {
        let mut public = vec![4];
        public.extend(
            key.export_public_key()
                .map_err(|e| io::Error::other(format!("SymCrypt TLS public key: {e}")))?,
        );
        Ok(Self { key, public })
    }
}

#[cfg(feature = "symcrypt")]
impl rcgen::RemoteKeyPair for SymCryptSigner {
    fn public_key(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature = self
            .key
            .ecdsa_sign(&symcrypt::hash::sha256(message))
            .map_err(|e| {
                tracing::error!(error = %e, "SymCrypt TLS certificate signing failed");
                rcgen::Error::RemoteKeyError
            })?;
        Ok(yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_bigint_bytes(&signature[..32], true);
                writer.next().write_bigint_bytes(&signature[32..], true);
            });
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
    use std::io::{Cursor, Read, Write};

    #[test]
    fn generated_certificate_survives_pem_reload_and_tls_handshake() {
        let (cert, key) = self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        let server_config = server_builder()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.clone_key())
            .unwrap();
        #[cfg(feature = "symcrypt")]
        {
            let rustls::pki_types::PrivateKeyDer::Sec1(sec1) = &key else {
                panic!("SymCrypt self-signed keys are SEC1");
            };
            let pkcs8 = yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_u8(0);
                    w.next().write_sequence(|w| {
                        w.next()
                            .write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                                1, 2, 840, 10045, 2, 1,
                            ]));
                        w.next()
                            .write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                                1, 2, 840, 10045, 3, 1, 7,
                            ]));
                    });
                    w.next().write_bytes(sec1.secret_sec1_der());
                })
            });
            server_builder()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8).into(),
                )
                .expect("existing PKCS8 P-256 keys remain loadable");
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        #[cfg(feature = "symcrypt")]
        let provider = rustls_symcrypt::default_symcrypt_provider_arc();
        #[cfg(not(feature = "symcrypt"))]
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        for protocol in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[protocol])
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap();
            let mut server =
                rustls::ServerConnection::new(Arc::new(server_config.clone())).unwrap();
            for _ in 0..10 {
                let mut wire = Vec::new();
                client.write_tls(&mut wire).unwrap();
                server.read_tls(&mut Cursor::new(wire)).unwrap();
                server.process_new_packets().unwrap();
                let mut wire = Vec::new();
                server.write_tls(&mut wire).unwrap();
                client.read_tls(&mut Cursor::new(wire)).unwrap();
                client.process_new_packets().unwrap();
                if !client.is_handshaking() && !server.is_handshaking() {
                    break;
                }
            }
            assert!(!client.is_handshaking() && !server.is_handshaking());
            client.writer().write_all(b"attestation").unwrap();
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            server.read_tls(&mut Cursor::new(wire)).unwrap();
            server.process_new_packets().unwrap();
            let mut plaintext = [0; 11];
            server.reader().read_exact(&mut plaintext).unwrap();
            assert_eq!(&plaintext, b"attestation");
        }
    }
}
