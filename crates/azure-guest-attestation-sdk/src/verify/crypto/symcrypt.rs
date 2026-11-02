// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SymCrypt signatures and WebPKI path building against caller-supplied roots.

use super::{other, DigestAlg};
use der::{asn1::AnyRef, Decode, Reader, SliceReader};
use rustls::pki_types::{
    alg_id, pem::PemObject, AlgorithmIdentifier, CertificateDer, InvalidSignature,
    SignatureVerificationAlgorithm, UnixTime,
};
use std::{io, sync::OnceLock};
use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};
use x509_parser::prelude::*;

#[derive(Clone)]
pub(crate) struct Cert(CertificateDer<'static>);

impl Cert {
    fn parsed(&self) -> io::Result<X509Certificate<'_>> {
        let (rest, cert) =
            parse_x509_certificate(&self.0).map_err(|e| other("parse DER certificate", e))?;
        if !rest.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing certificate data",
            ));
        }
        Ok(cert)
    }
}

pub(crate) fn sha256(data: &[u8]) -> io::Result<Vec<u8>> {
    Ok(symcrypt::hash::sha256(data).to_vec())
}

pub(crate) fn parse_pem_chain(pem: &[u8]) -> io::Result<Vec<Cert>> {
    CertificateDer::pem_slice_iter(pem)
        .map(|der| {
            let cert = Cert(der.map_err(|e| other("parse PEM certificate", e))?);
            cert.parsed()?;
            Ok(cert)
        })
        .collect()
}

pub(crate) fn cert_from_pem(pem: &[u8]) -> io::Result<Cert> {
    parse_pem_chain(pem)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty certificate PEM"))
}

pub(crate) fn cert_to_der(cert: &Cert) -> io::Result<Vec<u8>> {
    Ok(cert.0.to_vec())
}

pub(crate) fn cert_is_self_signed(cert: &Cert) -> bool {
    let verify = || -> io::Result<()> {
        let parsed = cert.parsed()?;
        if parsed.subject() != parsed.issuer()
            || parsed.signature_algorithm != parsed.tbs_certificate.signature
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not self-signed",
            ));
        }
        // Match the exact, signed AlgorithmIdentifier, not just its OID.
        let outer = AnyRef::from_der(&cert.0).map_err(|e| other("certificate DER", e))?;
        let mut reader =
            SliceReader::new(outer.value()).map_err(|e| other("certificate DER", e))?;
        reader
            .tlv_bytes()
            .map_err(|e| other("certificate TBS", e))?;
        let algorithm =
            AnyRef::from_der(reader.tlv_bytes().map_err(|e| other("signature DER", e))?)
                .map_err(|e| other("signature algorithm", e))?;
        let end_entity = webpki::EndEntityCert::try_from(&cert.0)
            .map_err(|e| other("certificate public key", e))?;
        for alg in algorithms() {
            if alg.signature_alg_id().as_ref() == algorithm.value()
                && end_entity
                    .verify_signature(
                        alg,
                        parsed.tbs_certificate.as_ref(),
                        parsed.signature_value.data.as_ref(),
                    )
                    .is_ok()
            {
                return Ok(());
            }
        }
        Err(io::Error::other("self-signature verification failed"))
    };
    verify().is_ok()
}

pub(crate) fn ecdsa_verify_raw(
    cert: &Cert,
    digest: DigestAlg,
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    let parsed = cert.parsed()?;
    let spki = parsed.public_key();
    if spki.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected EC public key",
        ));
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.as_oid().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing EC named curve"))?;
    let (curve, width) = match curve.to_id_string().as_str() {
        "1.2.840.10045.3.1.7" => (CurveType::NistP256, 32),
        "1.3.132.0.34" => (CurveType::NistP384, 48),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported EC curve",
            ))
        }
    };
    let point = spki.subject_public_key.data.as_ref();
    if point.first() != Some(&4) || point.len() != 1 + 2 * width {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid uncompressed EC point",
        ));
    }
    verify_ec(curve, width, &point[1..], digest, msg, r_be, s_be)
}

pub(crate) fn ecdsa_p256_verify_point(
    x_y: &[u8],
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    if x_y.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "P-256 point must be 64 bytes",
        ));
    }
    verify_ec(
        CurveType::NistP256,
        32,
        x_y,
        DigestAlg::Sha256,
        msg,
        r_be,
        s_be,
    )
}

fn verify_ec(
    curve: CurveType,
    width: usize,
    point: &[u8],
    digest: DigestAlg,
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    let mut signature = vec![0; 2 * width];
    for (integer, component) in [r_be, s_be].into_iter().zip(signature.chunks_mut(width)) {
        let first = integer
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(integer.len());
        let integer = &integer[first..];
        if integer.len() > width {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ECDSA component exceeds curve width",
            ));
        }
        component[width - integer.len()..].copy_from_slice(integer);
    }
    let key = EcKey::set_public_key(curve, point, EcKeyUsage::EcDsa)
        .map_err(|e| other("SymCrypt EC public key", e))?;
    let hash = match digest {
        DigestAlg::Sha256 => symcrypt::hash::sha256(msg).to_vec(),
        DigestAlg::Sha384 => symcrypt::hash::sha384(msg).to_vec(),
    };
    match key.ecdsa_verify(&signature, &hash) {
        Ok(()) => Ok(true),
        Err(symcrypt::errors::SymCryptError::SignatureVerificationFailure) => Ok(false),
        Err(e) => Err(other("SymCrypt ECDSA verification", e)),
    }
}

// AMD certificates explicitly encode the default trailerField=1. Accept only
// this exact SHA-384/MGF1-SHA384/saltLen=48 encoding; never rewrite signed TBS.
const AMD_PSS_SHA384: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x39\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\xa2\x03\x02\x01\x30\xa3\x03\x02\x01\x01";

#[derive(Debug)]
struct AmdPssEncoding(&'static dyn SignatureVerificationAlgorithm);

impl SignatureVerificationAlgorithm for AmdPssEncoding {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.0.public_key_alg_id()
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(AMD_PSS_SHA384)
    }
    fn verify_signature(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        self.0.verify_signature(key, message, signature)
    }
}

fn algorithms() -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    static AMD: OnceLock<AmdPssEncoding> = OnceLock::new();
    let all = rustls_symcrypt::default_symcrypt_provider()
        .signature_verification_algorithms
        .all;
    let amd = AMD.get_or_init(|| {
        AmdPssEncoding(
            all.iter()
                .copied()
                .find(|alg| alg.signature_alg_id() == alg_id::RSA_PSS_SHA384)
                .expect("rustls-symcrypt provides RSA-PSS/SHA-384"),
        )
    });
    let mut algorithms = all.to_vec();
    algorithms.push(amd);
    algorithms
}

struct AttestationUsage;

impl webpki::ExtendedKeyUsageValidator for AttestationUsage {
    fn validate(&self, purposes: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in purposes {
            purpose?;
        }
        Ok(())
    }
}

pub(crate) fn verify_cert_chain(
    leaf: &Cert,
    intermediates: &[Cert],
    roots: &[Cert],
) -> io::Result<()> {
    verify_cert_chain_at(leaf, intermediates, roots, UnixTime::now())
}

fn verify_cert_chain_at(
    leaf: &Cert,
    intermediates: &[Cert],
    roots: &[Cert],
    time: UnixTime,
) -> io::Result<()> {
    let anchors = roots
        .iter()
        .map(|cert| webpki::anchor_from_trusted_cert(&cert.0))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| other("pinned root", e))?;
    let intermediates: Vec<_> = intermediates.iter().map(|cert| cert.0.clone()).collect();
    let policy = |path: &webpki::VerifiedPath<'_>| {
        let mut subordinate_cas = 0;
        for issuer in path.intermediate_certificates() {
            let der = issuer.der();
            let (_, cert) = parse_x509_certificate(&der).map_err(|_| webpki::Error::BadDer)?;
            issuer_key_usage(&cert)?;
            if cert.subject() != cert.issuer() {
                subordinate_cas += 1;
            }
        }
        let mut error = webpki::Error::UnknownIssuer;
        for (root, anchor) in roots.iter().zip(&anchors) {
            if anchor.subject != path.anchor().subject
                || anchor.subject_public_key_info != path.anchor().subject_public_key_info
                || anchor.name_constraints != path.anchor().name_constraints
            {
                continue;
            }
            match root_policy(root, time, subordinate_cas) {
                Ok(()) => return Ok(()),
                Err(e) => error = e,
            }
        }
        Err(error)
    };
    webpki::EndEntityCert::try_from(&leaf.0)
        .map_err(|e| other("leaf certificate", e))?
        .verify_for_usage(
            &algorithms(),
            &anchors,
            &intermediates,
            time,
            AttestationUsage,
            None,
            Some(&policy),
        )
        .map(|_| ())
        .map_err(|e| other("SymCrypt certificate chain validation", e))
}

fn issuer_key_usage(cert: &X509Certificate<'_>) -> Result<(), webpki::Error> {
    if cert
        .key_usage()
        .map_err(|_| webpki::Error::ExtensionValueInvalid)?
        .is_some_and(|usage| !usage.value.key_cert_sign())
    {
        return Err(webpki::Error::ExtensionValueInvalid);
    }
    Ok(())
}

fn root_policy(root: &Cert, time: UnixTime, subordinate_cas: u32) -> Result<(), webpki::Error> {
    let cert = root.parsed().map_err(|_| webpki::Error::BadDer)?;
    let seconds = i64::try_from(time.as_secs()).map_err(|_| webpki::Error::InvalidCertValidity)?;
    let when = ASN1Time::from_timestamp(seconds).map_err(|_| webpki::Error::InvalidCertValidity)?;
    if !cert.validity().is_valid_at(when) {
        return Err(webpki::Error::InvalidCertValidity);
    }
    cert.extensions_map()
        .map_err(|_| webpki::Error::ExtensionValueInvalid)?;
    for extension in cert.extensions() {
        if extension.critical
            && !matches!(
                extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::BasicConstraints(_)
                    | x509_parser::extensions::ParsedExtension::KeyUsage(_)
                    | x509_parser::extensions::ParsedExtension::NameConstraints(_)
            )
        {
            return Err(webpki::Error::UnsupportedCriticalExtension);
        }
    }
    issuer_key_usage(&cert)?;
    match cert
        .basic_constraints()
        .map_err(|_| webpki::Error::ExtensionValueInvalid)?
    {
        Some(constraints) => {
            if !constraints.value.ca {
                return Err(webpki::Error::EndEntityUsedAsCa);
            }
            if constraints
                .value
                .path_len_constraint
                .is_some_and(|max| subordinate_cas > max)
            {
                return Err(webpki::Error::PathLenConstraintViolated);
            }
        }
        None if cert.version() != X509Version::V1 => return Err(webpki::Error::EndEntityUsedAsCa),
        None => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    struct Signer {
        key: EcKey,
        public: Vec<u8>,
    }

    impl rcgen::RemoteKeyPair for Signer {
        fn public_key(&self) -> &[u8] {
            &self.public
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            let sig = self.key.ecdsa_sign(&symcrypt::hash::sha256(msg)).unwrap();
            Ok(yasna::construct_der(|w| {
                w.write_sequence(|w| {
                    w.next().write_bigint_bytes(&sig[..32], true);
                    w.next().write_bigint_bytes(&sig[32..], true);
                })
            }))
        }
    }

    fn key_pair() -> KeyPair {
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let mut public = vec![4];
        public.extend(key.export_public_key().unwrap());
        KeyPair::from_remote(Box::new(Signer { key, public })).unwrap()
    }

    fn params(name: &str, ca: bool) -> CertificateParams {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.serial_number = Some(1u64.into());
        params.key_identifier_method =
            rcgen::KeyIdMethod::PreSpecified(symcrypt::hash::sha256(name.as_bytes()).to_vec());
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        }
        params
    }

    fn cert(cert: &Certificate) -> Cert {
        Cert(cert.der().clone())
    }

    fn time() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000))
    }

    #[test]
    fn validates_selected_root_not_unrelated_or_expired_alternatives() {
        let root_key = key_pair();
        let root = params("root", true).self_signed(&root_key).unwrap();
        let leaf_key = key_pair();
        let leaf = params("localhost", false)
            .signed_by(&leaf_key, &root, &root_key)
            .unwrap();
        let mut expired_params = params("root", true);
        expired_params.not_after = rcgen::date_time_ymd(2026, 1, 1);
        let expired = expired_params.self_signed(&root_key).unwrap();
        assert!(verify_cert_chain_at(&cert(&leaf), &[], &[cert(&expired)], time()).is_err());
        for roots in [
            vec![cert(&expired), cert(&root)],
            vec![cert(&root), cert(&expired)],
        ] {
            verify_cert_chain_at(&cert(&leaf), &[], &roots, time()).unwrap();
        }
        let unrelated_key = key_pair();
        let unrelated = params("unrelated", true)
            .self_signed(&unrelated_key)
            .unwrap();
        assert!(verify_cert_chain_at(&cert(&leaf), &[], &[cert(&unrelated)], time()).is_err());
        assert!(verify_cert_chain_at(&cert(&leaf), &[], &[], time()).is_err());
        verify_cert_chain_at(&cert(&leaf), &[], &[cert(&unrelated), cert(&root)], time()).unwrap();
        assert!(cert_is_self_signed(&cert(&root)));
        assert!(!cert_is_self_signed(&cert(&leaf)));
    }

    #[test]
    fn rejects_invalid_root_constraints_key_usage_and_critical_extensions() {
        let root_key = key_pair();
        let good_root = params("root", true).self_signed(&root_key).unwrap();
        let intermediate_key = key_pair();
        let intermediate = params("intermediate", true)
            .signed_by(&intermediate_key, &good_root, &root_key)
            .unwrap();
        let leaf_key = key_pair();
        let leaf = params("localhost", false)
            .signed_by(&leaf_key, &intermediate, &intermediate_key)
            .unwrap();
        verify_cert_chain_at(
            &cert(&leaf),
            &[cert(&intermediate)],
            &[cert(&good_root)],
            time(),
        )
        .unwrap();
        for case in 0..5 {
            let mut root_params = params("root", true);
            match case {
                0 => root_params.is_ca = IsCa::ExplicitNoCa,
                1 => root_params.key_usages = vec![KeyUsagePurpose::DigitalSignature],
                2 => root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)),
                3 => root_params.not_before = rcgen::date_time_ymd(2030, 1, 1),
                _ => {
                    let mut ext =
                        rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]);
                    ext.set_criticality(true);
                    root_params.custom_extensions.push(ext);
                }
            }
            let bad_root = root_params.self_signed(&root_key).unwrap();
            assert!(
                verify_cert_chain_at(
                    &cert(&leaf),
                    &[cert(&intermediate)],
                    &[cert(&bad_root)],
                    time()
                )
                .is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn rejects_invalid_intermediates_and_tampered_certificates() {
        let root_key = key_pair();
        let root = params("root", true).self_signed(&root_key).unwrap();
        let issuer_key = key_pair();
        let leaf_key = key_pair();
        for case in 0..4 {
            let mut issuer_params = params("issuer", true);
            match case {
                0 => issuer_params.key_usages = vec![KeyUsagePurpose::DigitalSignature],
                1 => issuer_params.is_ca = IsCa::ExplicitNoCa,
                2 => issuer_params.not_after = rcgen::date_time_ymd(2026, 1, 1),
                _ => {
                    let mut ext =
                        rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]);
                    ext.set_criticality(true);
                    issuer_params.custom_extensions.push(ext);
                }
            }
            let issuer = issuer_params
                .signed_by(&issuer_key, &root, &root_key)
                .unwrap();
            let leaf = params("localhost", false)
                .signed_by(&leaf_key, &issuer, &issuer_key)
                .unwrap();
            assert!(
                verify_cert_chain_at(&cert(&leaf), &[cert(&issuer)], &[cert(&root)], time())
                    .is_err(),
                "case {case}"
            );
        }
        let leaf = params("localhost", false)
            .signed_by(&leaf_key, &root, &root_key)
            .unwrap();
        let mut tampered = leaf.der().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_cert_chain_at(&Cert(tampered.into()), &[], &[cert(&root)], time()).is_err());
    }

    #[test]
    fn reqwest_uses_symcrypt_and_rejects_untrusted_hostname_and_expiry() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::Arc,
            time::Duration,
        };
        let root_key = key_pair();
        let root = params("root", true).self_signed(&root_key).unwrap();
        let server_key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let mut point = vec![4];
        point.extend(server_key.export_public_key().unwrap());
        let private = server_key.export_private_key().unwrap();
        let private_der = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(1);
                w.next().write_bytes(&private);
                w.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_oid(&yasna::models::ObjectIdentifier::from_slice(&[
                        1, 2, 840, 10045, 3, 1, 7,
                    ]));
                });
            })
        });
        let signer = KeyPair::from_remote(Box::new(Signer {
            key: server_key,
            public: point,
        }))
        .unwrap();
        for case in 0..4 {
            let mut leaf_params = params(
                if case == 2 {
                    "wrong.example"
                } else {
                    "localhost"
                },
                false,
            );
            if case == 3 {
                leaf_params.not_after = rcgen::date_time_ymd(2026, 1, 1);
            }
            let leaf = leaf_params.signed_by(&signer, &root, &root_key).unwrap();
            let server_config = rustls::ServerConfig::builder_with_provider(
                rustls_symcrypt::default_symcrypt_provider_arc(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateSec1KeyDer::from(private_der.clone()).into(),
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, socket);
                let mut request = [0; 4096];
                match stream.read(&mut request) {
                    Ok(size) if size > 0 => stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .unwrap(),
                    Ok(_) => {}
                    Err(error) => assert_ne!(case, 0, "{error}"),
                }
            });
            let mut builder = crate::crypto::http_client_builder()
                .no_proxy()
                .timeout(Duration::from_secs(5));
            if case != 1 {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(root.der().clone()).unwrap();
                let config = rustls::ClientConfig::builder_with_provider(
                    rustls_symcrypt::default_symcrypt_provider_arc(),
                )
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                builder = builder.use_preconfigured_tls(config);
            }
            let result = builder
                .build()
                .unwrap()
                .get(format!("https://localhost:{port}"))
                .send();
            if case == 0 {
                assert_eq!(result.unwrap().text().unwrap(), "OK");
            } else {
                assert!(result.unwrap_err().is_connect(), "case {case}");
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn amd_pss_encoding_is_exact_and_delegates_signature_validation() {
        let algorithms = algorithms();
        let adapter = algorithms
            .iter()
            .find(|alg| alg.signature_alg_id().as_ref() == AMD_PSS_SHA384)
            .unwrap();
        for offset in [27, 57, AMD_PSS_SHA384.len() - 6, AMD_PSS_SHA384.len() - 1] {
            let mut altered = AMD_PSS_SHA384.to_vec();
            altered[offset] ^= 1;
            assert!(algorithms
                .iter()
                .all(|alg| alg.signature_alg_id().as_ref() != altered));
        }
        assert!(adapter.verify_signature(&[], b"message", &[]).is_err());
    }

    #[test]
    fn malformed_pem_and_der_are_rejected() {
        assert!(cert_from_pem(b"not PEM").is_err());
        assert!(
            cert_from_pem(b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----").is_err()
        );
    }
}
