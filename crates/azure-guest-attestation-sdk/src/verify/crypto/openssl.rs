// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL implementation of the [`super`] crypto interface (Linux).

use super::{other, unix_time_to_filetime_ticks, DigestAlg};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509StoreContext, X509VerifyResult, X509};
use std::io;

/// An X.509 certificate handle.
#[derive(Clone)]
pub(crate) struct Cert(X509);

impl DigestAlg {
    fn message_digest(self) -> MessageDigest {
        match self {
            DigestAlg::Sha256 => MessageDigest::sha256(),
            DigestAlg::Sha384 => MessageDigest::sha384(),
        }
    }
}

/// SHA-256 digest of `data`.
pub(crate) fn sha256(data: &[u8]) -> io::Result<Vec<u8>> {
    Ok(hash(MessageDigest::sha256(), data)
        .map_err(|e| other("sha256", e))?
        .to_vec())
}

/// Parse a buffer of one or more concatenated PEM certificates, leaf first.
pub(crate) fn parse_pem_chain(pem: &[u8]) -> io::Result<Vec<Cert>> {
    Ok(X509::stack_from_pem(pem)
        .map_err(|e| other("parse PEM cert chain", e))?
        .into_iter()
        .map(Cert)
        .collect())
}

/// Parse a single PEM certificate.
pub(crate) fn cert_from_pem(pem: &[u8]) -> io::Result<Cert> {
    Ok(Cert(
        X509::from_pem(pem).map_err(|e| other("parse PEM certificate", e))?,
    ))
}

/// Encode a certificate as DER.
pub(crate) fn cert_to_der(cert: &Cert) -> io::Result<Vec<u8>> {
    cert.0
        .to_der()
        .map_err(|e| other("encode DER certificate", e))
}

/// Whether `cert` is self-signed (subject == issuer and the signature verifies
/// under its own public key).
pub(crate) fn cert_is_self_signed(cert: &Cert) -> bool {
    cert.0.issued(&cert.0) == X509VerifyResult::OK
}

/// Verify an ECDSA signature given raw big-endian `r`/`s` integers over `msg`,
/// using the public key in `cert` and the supplied message digest.
///
/// The curve (P-256 / P-384) is taken from the certificate's public key, so the
/// same routine serves both TDX (P-256/SHA-256) and SEV-SNP (P-384/SHA-384).
pub(crate) fn ecdsa_verify_raw(
    cert: &Cert,
    digest: DigestAlg,
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    let pkey = cert
        .0
        .public_key()
        .map_err(|e| other("certificate public key", e))?;
    let ec = pkey.ec_key().map_err(|e| other("EC public key", e))?;
    let r = BigNum::from_slice(r_be).map_err(|e| other("ECDSA r", e))?;
    let s = BigNum::from_slice(s_be).map_err(|e| other("ECDSA s", e))?;
    let sig = EcdsaSig::from_private_components(r, s).map_err(|e| other("ECDSA sig", e))?;
    let dgst = hash(digest.message_digest(), msg).map_err(|e| other("digest", e))?;
    sig.verify(&dgst, &ec).map_err(|e| other("ECDSA verify", e))
}

/// Verify an ECDSA P-256/SHA-256 signature (raw big-endian `r`/`s`) over `msg`
/// using a raw uncompressed public point `x_y` (64 bytes, big-endian `x‖y`).
///
/// TDX quotes carry the attestation key as a bare `x‖y` point (not a cert), so
/// this builds the `EcKey` directly.
pub(crate) fn ecdsa_p256_verify_point(
    x_y: &[u8],
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::nid::Nid;

    if x_y.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("P-256 public point must be 64 bytes, got {}", x_y.len()),
        ));
    }
    let group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| other("P-256 group", e))?;
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04); // uncompressed point marker
    uncompressed.extend_from_slice(x_y);
    let mut ctx = BigNumContext::new().map_err(|e| other("bn context", e))?;
    let point =
        EcPoint::from_bytes(&group, &uncompressed, &mut ctx).map_err(|e| other("EC point", e))?;
    let ec = EcKey::from_public_key(&group, &point).map_err(|e| other("EC public key", e))?;
    let r = BigNum::from_slice(r_be).map_err(|e| other("ECDSA r", e))?;
    let s = BigNum::from_slice(s_be).map_err(|e| other("ECDSA s", e))?;
    let sig = EcdsaSig::from_private_components(r, s).map_err(|e| other("ECDSA sig", e))?;
    let dgst = hash(MessageDigest::sha256(), msg).map_err(|e| other("sha256", e))?;
    sig.verify(&dgst, &ec).map_err(|e| other("ECDSA verify", e))
}

/// Validate that `leaf` chains up (via `intermediates`) to one of the trusted
/// `roots`. Returns `Ok(())` on success, or an error describing the failure.
pub(crate) fn verify_cert_chain(
    leaf: &Cert,
    intermediates: &[Cert],
    roots: &[Cert],
) -> io::Result<()> {
    verify_cert_chain_at(leaf, intermediates, roots, None)
}

/// Validate a chain against pinned `roots` at `unix_time`, or the wall clock
/// when `None`. Explicit times must be nonnegative and fit both the shared
/// FILETIME range and native `time_t`; invalid times return `InvalidInput`.
pub(crate) fn verify_cert_chain_at(
    leaf: &Cert,
    intermediates: &[Cert],
    roots: &[Cert],
    unix_time: Option<i64>,
) -> io::Result<()> {
    let param = unix_time
        .map(|seconds| -> io::Result<_> {
            unix_time_to_filetime_ticks(seconds)?;
            // time_t is i64 here on 64-bit Linux, but can be narrower elsewhere.
            #[allow(clippy::useless_conversion)]
            let time = seconds.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "certificate validation time is outside native time_t range",
                )
            })?;
            let mut param = X509VerifyParam::new().map_err(|e| other("X509 verify param", e))?;
            param.set_time(time);
            Ok(param)
        })
        .transpose()?;
    let mut store_builder = X509StoreBuilder::new().map_err(|e| other("X509 store", e))?;
    if let Some(param) = param {
        store_builder
            .set_param(&param)
            .map_err(|e| other("set X509 verify param", e))?;
    }
    for root in roots {
        store_builder
            .add_cert(root.0.clone())
            .map_err(|e| other("add trusted root", e))?;
    }
    let store = store_builder.build();

    let mut chain = Stack::new().map_err(|e| other("cert stack", e))?;
    for cert in intermediates {
        chain
            .push(cert.0.clone())
            .map_err(|e| other("push intermediate", e))?;
    }

    let mut ctx = X509StoreContext::new().map_err(|e| other("store context", e))?;
    let verified = ctx
        .init(&store, &leaf.0, &chain, |c| c.verify_cert())
        .map_err(|e| other("chain verify", e))?;
    if verified {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "certificate chain validation failed: {}",
            ctx.error()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    /// Build a self-signed cert for `key` so `ecdsa_verify_raw` can read its
    /// public key.
    fn self_signed(key: &PKey<openssl::pkey::Private>) -> X509 {
        use openssl::x509::X509Builder;
        let mut b = X509Builder::new().unwrap();
        b.set_pubkey(key).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test").unwrap();
        let name = name.build();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(key, MessageDigest::sha384()).unwrap();
        b.build()
    }

    fn roundtrip(nid: Nid, digest: DigestAlg) {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec.clone()).unwrap();
        let cert = Cert(self_signed(&pkey));

        let msg = b"attestation report bytes";
        let dgst = hash(digest.message_digest(), msg).unwrap();
        let sig = EcdsaSig::sign(&dgst, &ec).unwrap();
        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        assert!(ecdsa_verify_raw(&cert, digest, msg, &r, &s).unwrap());
        // Tampered message must fail.
        assert!(!ecdsa_verify_raw(&cert, digest, b"tampered", &r, &s).unwrap());
    }

    #[test]
    fn ecdsa_p256_roundtrip() {
        roundtrip(Nid::X9_62_PRIME256V1, DigestAlg::Sha256);
    }

    #[test]
    fn ecdsa_p384_roundtrip() {
        roundtrip(Nid::SECP384R1, DigestAlg::Sha384);
    }

    fn cert_chain(not_before: Asn1Time, not_after: Asn1Time) -> (Cert, Cert) {
        // root (self-signed CA) -> leaf signed by root.
        use openssl::x509::extension::BasicConstraints;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let root_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let leaf_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

        let mut rn = X509NameBuilder::new().unwrap();
        rn.append_entry_by_text("CN", "root").unwrap();
        let rn = rn.build();

        let mut rb = X509Builder::new().unwrap();
        rb.set_pubkey(&root_key).unwrap();
        rb.set_subject_name(&rn).unwrap();
        rb.set_issuer_name(&rn).unwrap();
        rb.set_not_before(&not_before).unwrap();
        rb.set_not_after(&not_after).unwrap();
        rb.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        rb.sign(&root_key, MessageDigest::sha384()).unwrap();
        let root = Cert(rb.build());

        let mut ln = X509NameBuilder::new().unwrap();
        ln.append_entry_by_text("CN", "leaf").unwrap();
        let ln = ln.build();

        let mut lb = X509Builder::new().unwrap();
        lb.set_pubkey(&leaf_key).unwrap();
        lb.set_subject_name(&ln).unwrap();
        lb.set_issuer_name(&rn).unwrap();
        lb.set_not_before(&not_before).unwrap();
        lb.set_not_after(&not_after).unwrap();
        lb.sign(&root_key, MessageDigest::sha384()).unwrap();
        let leaf = Cert(lb.build());

        (leaf, root)
    }

    #[test]
    fn cert_chain_valid_and_invalid() {
        let (leaf, root) = cert_chain(
            Asn1Time::days_from_now(0).unwrap(),
            Asn1Time::days_from_now(1).unwrap(),
        );
        // Valid: leaf -> root.
        assert!(verify_cert_chain(&leaf, &[], std::slice::from_ref(&root)).is_ok());
        // Invalid: leaf with an untrusted (empty) root set.
        assert!(verify_cert_chain(&leaf, &[], &[]).is_err());
    }

    #[test]
    fn cert_chain_explicit_time_checks_validity_and_trust() {
        // Valid only during 2000, independent of the wall clock.
        let (leaf, root) = cert_chain(
            Asn1Time::from_unix(946_684_800).unwrap(),
            Asn1Time::from_unix(978_307_200).unwrap(),
        );
        let roots = std::slice::from_ref(&root);
        assert!(verify_cert_chain_at(&leaf, &[], roots, Some(962_409_600)).is_ok());
        let expired = verify_cert_chain_at(&leaf, &[], roots, Some(1_009_843_200)).unwrap_err();
        assert!(expired.to_string().contains("expired"), "{expired}");
        let not_yet_valid = verify_cert_chain_at(&leaf, &[], roots, Some(915_148_800)).unwrap_err();
        assert!(
            not_yet_valid.to_string().contains("not yet valid"),
            "{not_yet_valid}"
        );
        assert!(verify_cert_chain_at(&leaf, &[], &[], Some(962_409_600)).is_err());
        assert!(verify_cert_chain(&leaf, &[], roots).is_err());
        assert!(verify_cert_chain_at(&leaf, &[], roots, None).is_err());

        for time in [-1, i64::MIN, 910_692_730_086, i64::MAX] {
            assert_eq!(
                verify_cert_chain_at(&leaf, &[], roots, Some(time))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn cert_to_der_roundtrip() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let cert = Cert(self_signed(&key));
        let der = cert_to_der(&cert).unwrap();
        assert_eq!(der, cert.0.to_der().unwrap());
        let parsed = Cert(X509::from_der(&der).unwrap());
        assert_eq!(cert_to_der(&parsed).unwrap(), der);
    }
}
