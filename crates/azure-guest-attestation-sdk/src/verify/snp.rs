// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local verification of AMD SEV-SNP attestation reports.
//!
//! Validates the VCEK certificate chain to a pinned AMD ARK root and verifies
//! the report signature (ECDSA P-384 / SHA-384), supported report structure,
//! and the VCEK's processor-generation, reported-TCB, and hardware-ID bindings.
//! Nonce/measurement policy, minimum TCB policy, and revocation are not checked.

mod vcek;

use super::crypto::{self, Cert, DigestAlg};
use super::roots;
use crate::tee_report::snp::{SnpReport, SNP_REPORT_SIZE};
use std::io;

/// Number of leading report bytes covered by the signature (everything before
/// the 512-byte signature field).
const SNP_SIGNED_LEN: usize = 0x2A0;
/// Size of each ECDSA component (`r`, `s`) in the SNP signature field
/// (little-endian, zero-padded).
const SNP_SIG_COMPONENT_LEN: usize = 72;

/// Policy controls for [`verify_snp_report`]. Reserved for TCB/policy options
/// added in a later phase. Structural and VCEK-binding checks are mandatory;
/// minimum TCB levels and relying-party acceptance policy are not enforced.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SnpVerifyPolicy {}

/// Key measurements extracted from a verified SNP report.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SnpMeasurements {
    /// Launch measurement of the guest.
    pub measurement: [u8; 48],
    /// Report data (guest-provided).
    pub report_data: [u8; 64],
    /// Reported TCB version (AMD `TCB_VERSION`, little-endian u64).
    pub reported_tcb: u64,
    /// Chip identifier (0 if MaskChipId was set).
    pub chip_id: [u8; 64],
}

/// Outcome of verifying an SNP report.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SnpVerifyResult {
    /// The VCEK certificate chain validated to a pinned AMD ARK root.
    pub chain_valid: bool,
    /// The report signature verified under the VCEK public key.
    pub signature_valid: bool,
    /// The VCEK role, P-384 key, product family/model (when reported), reported
    /// TCB components and unmasked chip ID match the authenticated report.
    /// This does not establish minimum TCB levels, CPUID stepping equivalence,
    /// acceptable guest policy, or non-revocation.
    pub vcek_binding_valid: bool,
    /// The measurements extracted from the verified report.
    pub measurements: SnpMeasurements,
}

/// Verify an AMD SEV-SNP attestation report against a VCEK certificate chain.
///
/// - `report_bytes`: the raw `0x4a0`-byte SNP attestation report.
/// - `vcek_chain_pem`: the VCEK leaf followed by the ASK (and optionally the
///   ARK) in PEM form, as returned by Azure IMDS/THIM or AMD KDS.
///
/// The chain is validated to a **pinned** AMD ARK root and the report signature
/// (ECDSA P-384 / SHA-384 over `report_bytes[..0x2A0]`) is checked under the
/// VCEK public key. The input must be exactly 1,184 bytes, use report version
/// 2..=5, select VCEK (not VLEK), and expose an unmasked chip ID. Unsupported
/// or malformed encodings and mismatched VCEK TCB/HWID/product bindings fail.
///
/// Older v2 reports have no CPUID: generation is obtained from the authenticated
/// certificate. Product suffixes are not equated with report stepping values.
/// `parse::snp_report` remains available for permissive inspection. This function
/// does not check revocation, expected REPORTDATA, measurement policy, or TCB
/// minimums; callers must apply their own acceptance policy.
pub fn verify_snp_report(
    report_bytes: &[u8],
    vcek_chain_pem: &[u8],
    policy: &SnpVerifyPolicy,
) -> io::Result<SnpVerifyResult> {
    let roots = roots::amd_ark_roots()?;
    verify_snp_report_with_roots(report_bytes, vcek_chain_pem, &roots, policy)
}

/// [`verify_snp_report`] against an explicit set of trusted roots. Exposed for
/// testing with a synthetic ARK; production callers use [`verify_snp_report`].
pub(crate) fn verify_snp_report_with_roots(
    report_bytes: &[u8],
    vcek_chain_pem: &[u8],
    roots: &[Cert],
    _policy: &SnpVerifyPolicy,
) -> io::Result<SnpVerifyResult> {
    if report_bytes.len() != SNP_REPORT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SNP report size must be exactly {SNP_REPORT_SIZE}, got {}",
                report_bytes.len()
            ),
        ));
    }
    let report = crate::parse::snp_report(report_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SNP report layout"))?;
    validate_report_format(&report)?;

    // 1. Parse the VCEK chain: leaf = VCEK, remainder = intermediates.
    let chain = crypto::parse_pem_chain(vcek_chain_pem)?;
    let (vcek, rest) = chain.split_first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "empty VCEK certificate chain")
    })?;

    // 2. Validate VCEK -> ASK -> pinned ARK. Drop any self-signed cert from the
    //    supplied intermediates so trust is anchored only on the pinned roots.
    let intermediates: Vec<Cert> = rest
        .iter()
        .filter(|c| !crypto::cert_is_self_signed(c))
        .cloned()
        .collect();
    crypto::verify_cert_chain(vcek, &intermediates, roots)?;

    // 3. Verify the report signature (ECDSA P-384 / SHA-384).
    let signed = &report_bytes[..SNP_SIGNED_LEN];
    let sig = &report_bytes[SNP_SIGNED_LEN..SNP_SIGNED_LEN + 512];
    let r_be = le_to_be(&sig[..SNP_SIG_COMPONENT_LEN]);
    let s_be = le_to_be(&sig[SNP_SIG_COMPONENT_LEN..2 * SNP_SIG_COMPONENT_LEN]);
    let signature_valid = crypto::ecdsa_verify_raw(vcek, DigestAlg::Sha384, signed, &r_be, &s_be)?;
    if !signature_valid {
        return Err(io::Error::other("SNP report signature verification failed"));
    }

    // Use the exact leaf validated above, not separately supplied collateral.
    vcek::validate(&crypto::cert_to_der(vcek)?, &report)?;

    let measurements = SnpMeasurements {
        measurement: report.measurement,
        report_data: report.report_data,
        reported_tcb: report.reported_tcb,
        chip_id: report.chip_id,
    };

    Ok(SnpVerifyResult {
        chain_valid: true,
        signature_valid: true,
        vcek_binding_valid: true,
        measurements,
    })
}

/// Validate the supported report wire formats without applying acceptance policy.
fn validate_report_format(report: &SnpReport) -> io::Result<()> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    if !matches!(report.version, 2..=5) {
        return Err(invalid(
            "unsupported SNP report version (expected 2 through 5)",
        ));
    }
    if report.signature_algo != 1 {
        return Err(invalid("SNP signature algorithm must be ECDSA-P384-SHA384"));
    }
    if report.vmpl > 3 {
        return Err(invalid("SNP VMPL must be in 0..=3"));
    }
    if report.flags & !0x1f != 0 {
        return Err(invalid("nonzero reserved SNP signer-info bits"));
    }
    if (report.flags >> 2) & 7 != 0 {
        return Err(invalid("only VCEK-signed SNP reports are supported"));
    }
    if report.flags & 2 != 0 || report.chip_id.iter().all(|b| *b == 0) {
        return Err(invalid(
            "masked or zero SNP chip ID cannot establish VCEK binding",
        ));
    }
    // Format constraints only: these do not forbid DEBUG or require particular
    // SMT/migration/mitigation settings. Those remain relying-party policy.
    if report.policy & (1 << 17) == 0 || report.policy >> 26 != 0 {
        return Err(invalid("invalid reserved SNP guest-policy bits"));
    }
    // PLATFORM_INFO stays opaque: the signed Turin v5 fixture sets bit 6,
    // which older published layouts reserve. Do not infer its meaning or apply
    // an older platform mask here; posture policy is outside this verifier.
    let cpuid_reserved = if report.version >= 3 { 3 } else { 0 };
    if report.cpuid().is_some_and(|fms| fms[2] > 15) {
        return Err(invalid("SNP CPUID stepping exceeds four bits"));
    }
    let mitigation_reserved = if report.version == 5 { 16 } else { 0 };
    if report._reserved0 != 0
        || report._reserved2 != 0
        || report._reserved3 != 0
        || report._reserved1[cpuid_reserved..].iter().any(|b| *b != 0)
        || report._reserved4[mitigation_reserved..]
            .iter()
            .any(|b| *b != 0)
    {
        return Err(invalid("nonzero reserved SNP report bytes"));
    }
    if report.signature[48..72].iter().any(|b| *b != 0)
        || report.signature[120..].iter().any(|b| *b != 0)
    {
        return Err(invalid("nonzero SNP ECDSA signature padding"));
    }
    Ok(())
}

/// Reverse a little-endian integer buffer to the big-endian form the crypto
/// backends expect.
fn le_to_be(le: &[u8]) -> Vec<u8> {
    let mut v = le.to_vec();
    v.reverse();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real SEV-SNP evidence captured from Azure CVMs. Public measurements, no
    /// secrets — these are the ground truth for both crypto backends.
    const TURIN_REPORT: &[u8] = include_bytes!("testdata/snp_report_turin.bin");
    const TURIN_CHAIN: &[u8] = include_bytes!("testdata/snp_vcek_chain_turin.pem");
    const MILAN_REPORT: &[u8] = include_bytes!("testdata/snp_report_milan.bin");
    const MILAN_CHAIN: &[u8] = include_bytes!("testdata/snp_vcek_chain_milan.pem");
    const GENOA_REPORT: &[u8] = include_bytes!("testdata/snp_report_genoa.bin");
    const GENOA_CHAIN: &[u8] = include_bytes!("testdata/snp_vcek_chain_genoa.pem");

    pub(super) struct RealFixture {
        pub(super) name: &'static str,
        pub(super) report: &'static [u8],
        pub(super) chain: &'static [u8],
        pub(super) struct_version: u8,
        version: u32,
        cpuid: [u8; 3],
        reported_tcb: u64,
        measurement: &'static str,
        report_data_prefix: &'static str,
        chip_id_prefix: &'static str,
    }

    pub(super) const REAL_FIXTURES: [RealFixture; 3] = [
        RealFixture {
            name: "Milan", report: MILAN_REPORT, chain: MILAN_CHAIN, struct_version: 0,
            version: 3, cpuid: [0x19, 0x01, 1], reported_tcb: 0xdb18_0000_0000_0004,
            measurement: "5b0ce64ad1c1f6375dbda5f760b98526ca1bcf91b8195091afc28e7b024251d68fe32e05af34048d6607678cd23283ff",
            report_data_prefix: "758a38582cd731e63bc3d28d9b890ce82c8214afa0edab1196c5a7c7ff87396b",
            chip_id_prefix: "7dd2dd89d69087a1",
        },
        RealFixture {
            name: "Turin", report: TURIN_REPORT, chain: TURIN_CHAIN, struct_version: 1,
            version: 5, cpuid: [0x1a, 0x02, 1], reported_tcb: 0x5a00_0000_0502_0301,
            measurement: "12d40f252f43d99d78b15197400e266bd6b323c93d8fdfb61ccf2f30761d8708bc2f4b6dbcb8d3d769cd535c695938ab",
            report_data_prefix: "ab6a63f751fbf354f2bb6a3c12336e18caa1217c3d3b2cdcf57ffe2c21f69088",
            chip_id_prefix: "5b0f3945c57a2338",
        },
        RealFixture {
            name: "Genoa", report: GENOA_REPORT, chain: GENOA_CHAIN, struct_version: 0,
            version: 3, cpuid: [0x19, 0x11, 1], reported_tcb: 0x5417_0000_0000_000a,
            measurement: "aa7c9da55c1386e5b1653b125978beda7b3f95a85aeb0f9ddbbdb783ce056a28c9d021da239c34a58c3a657654270eef",
            report_data_prefix: "5425c3b2c2dc328920baca037dd6cce869d1297a8a63a70f111dd64f20d25951",
            chip_id_prefix: "fb05db7e1aedd703",
        },
    ];

    #[test]
    fn rejects_oversized_report_and_noncanonical_signature_padding() {
        for fixture in &REAL_FIXTURES {
            let mut oversized = fixture.report.to_vec();
            oversized.push(0);
            assert!(
                verify_snp_report(&oversized, fixture.chain, &SnpVerifyPolicy::default()).is_err(),
                "{}",
                fixture.name
            );
            for offset in [0x2a0 + 48, 0x2e8 + 48, 0x330, 0x49f] {
                let mut report = fixture.report.to_vec();
                report[offset] = 1;
                let error = verify_snp_report(&report, fixture.chain, &SnpVerifyPolicy::default())
                    .expect_err("unsigned signature padding must fail format validation");
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::InvalidData,
                    "{} at {offset:#x}",
                    fixture.name
                );
            }
        }
    }

    /// Synthetic ARK->ASK->VCEK fixtures. Key/cert generation is OpenSSL-only;
    /// the Windows backend's negative coverage comes from the real-evidence
    /// tamper tests below.
    #[cfg(target_os = "linux")]
    mod synthetic {
        use super::*;
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::ec::{EcGroup, EcKey};
        use openssl::ecdsa::EcdsaSig;
        use openssl::hash::{hash, MessageDigest};
        use openssl::nid::Nid;
        use openssl::pkey::{PKey, Private};
        use openssl::x509::extension::BasicConstraints;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509};

        fn p384_key() -> PKey<Private> {
            ec_key(Nid::SECP384R1)
        }

        fn ec_key(curve: Nid) -> PKey<Private> {
            let group = EcGroup::from_curve_name(curve).unwrap();
            PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
        }

        fn cert(
            cn: &str,
            subject_key: &PKey<Private>,
            issuer_cn: &str,
            issuer_key: &PKey<Private>,
            ca: bool,
            extensions: &[(&str, Vec<u8>)],
        ) -> X509 {
            let mut sn = X509NameBuilder::new().unwrap();
            sn.append_entry_by_text("CN", cn).unwrap();
            let sn = sn.build();
            let mut inb = X509NameBuilder::new().unwrap();
            inb.append_entry_by_text("CN", issuer_cn).unwrap();
            let inb = inb.build();
            let mut b = X509Builder::new().unwrap();
            b.set_version(2).unwrap();
            b.set_pubkey(subject_key).unwrap();
            b.set_subject_name(&sn).unwrap();
            b.set_issuer_name(&inb).unwrap();
            b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            if ca {
                b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                    .unwrap();
            }
            for (suffix, value) in extensions {
                let oid = Asn1Object::from_str(&format!("1.3.6.1.4.1.3704.{suffix}")).unwrap();
                let value = Asn1OctetString::new_from_bytes(value).unwrap();
                b.append_extension(X509Extension::new_from_der(&oid, false, &value).unwrap())
                    .unwrap();
            }
            b.sign(issuer_key, MessageDigest::sha384()).unwrap();
            b.build()
        }

        fn as_cert(x: &X509) -> Cert {
            crypto::cert_from_pem(&x.to_pem().unwrap()).unwrap()
        }

        /// Exact independent encodings, not the production extension decoder.
        fn amd_extensions() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                ("1.1", vec![2, 1, 0]), // structVersion
                ("1.2", b"\x16\x08Milan-B0".to_vec()),
                ("1.3.1", vec![2, 1, 4]),                     // boot loader
                ("1.3.2", vec![2, 1, 0]),                     // TEE
                ("1.3.3", vec![2, 1, 24]),                    // SNP
                ("1.3.8", vec![2, 2, 0, 219]),                // positive DER INTEGER
                ("1.4", MILAN_REPORT[0x1a0..0x1e0].to_vec()), // raw HWID
            ]
        }

        fn synthetic_case() -> (Vec<u8>, Vec<u8>, Cert, PKey<Private>) {
            synthetic_leaf("SEV-VCEK", Nid::SECP384R1, &amd_extensions())
        }

        /// Every variant has authentic certificate and report signatures.
        fn synthetic_leaf(
            cn: &str,
            curve: Nid,
            extensions: &[(&str, Vec<u8>)],
        ) -> (Vec<u8>, Vec<u8>, Cert, PKey<Private>) {
            let ark_key = p384_key();
            let ask_key = p384_key();
            let vcek_key = ec_key(curve);

            let ark = cert("ARK-Milan", &ark_key, "ARK-Milan", &ark_key, true, &[]);
            let ask = cert("SEV-Milan", &ask_key, "ARK-Milan", &ark_key, true, &[]);
            let vcek = cert(cn, &vcek_key, "SEV-Milan", &ask_key, false, extensions);

            // Chain PEM: VCEK then ASK (ARK is the pinned root, supplied separately).
            let mut chain_pem = vcek.to_pem().unwrap();
            chain_pem.extend_from_slice(&ask.to_pem().unwrap());

            let mut report = MILAN_REPORT.to_vec();
            sign_report(&mut report, &vcek_key);
            (report, chain_pem, as_cert(&ark), vcek_key)
        }

        fn sign_report(report: &mut [u8], key: &PKey<Private>) {
            report[SNP_SIGNED_LEN..].fill(0);
            let dgst = hash(MessageDigest::sha384(), &report[..SNP_SIGNED_LEN]).unwrap();
            let ec = key.ec_key().unwrap();
            let sig = EcdsaSig::sign(&dgst, &ec).unwrap();
            place_le(report, SNP_SIGNED_LEN, &sig.r().to_vec());
            place_le(
                report,
                SNP_SIGNED_LEN + SNP_SIG_COMPONENT_LEN,
                &sig.s().to_vec(),
            );
        }

        /// Store a big-endian integer as a 72-byte little-endian component at `off`.
        fn place_le(report: &mut [u8], off: usize, be: &[u8]) {
            let mut le = be.to_vec();
            le.reverse();
            le.resize(SNP_SIG_COMPONENT_LEN, 0);
            report[off..off + SNP_SIG_COMPONENT_LEN].copy_from_slice(&le);
        }

        #[test]
        fn verifies_valid_synthetic_report_and_chain() {
            let (report, chain_pem, ark, _) = synthetic_case();
            let res = verify_snp_report_with_roots(
                &report,
                &chain_pem,
                std::slice::from_ref(&ark),
                &SnpVerifyPolicy::default(),
            )
            .expect("verify ok");
            assert!(res.chain_valid && res.signature_valid);
        }

        #[test]
        fn rejects_tampered_report_body() {
            let (mut report, chain_pem, ark, _) = synthetic_case();
            report[0x90] ^= 1; // measurement: format stays valid, signature breaks
            let err = verify_snp_report_with_roots(
                &report,
                &chain_pem,
                std::slice::from_ref(&ark),
                &SnpVerifyPolicy::default(),
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert!(err.to_string().contains("signature"), "{err}");
        }

        #[test]
        fn rejects_untrusted_root() {
            let (report, chain_pem, _ark, _) = synthetic_case();
            // A different, unrelated ARK is not a trust anchor for this chain.
            let other = as_cert(&cert(
                "ARK-Other",
                &p384_key(),
                "ARK-Other",
                &p384_key(),
                true,
                &[],
            ));
            let err = verify_snp_report_with_roots(
                &report,
                &chain_pem,
                std::slice::from_ref(&other),
                &SnpVerifyPolicy::default(),
            );
            assert!(err.is_err());
        }

        fn verify(report: &[u8], chain: &[u8], root: &Cert) -> io::Result<SnpVerifyResult> {
            verify_snp_report_with_roots(
                report,
                chain,
                std::slice::from_ref(root),
                &SnpVerifyPolicy::default(),
            )
        }

        fn assert_invalid(report: &[u8], chain: &[u8], root: &Cert, message: &str) {
            // Rule out both chain and signature failures as accidental rejection causes.
            let certs = crypto::parse_pem_chain(chain).unwrap();
            crypto::verify_cert_chain(&certs[0], &certs[1..], std::slice::from_ref(root)).unwrap();
            let r = le_to_be(&report[0x2a0..0x2e8]);
            let s = le_to_be(&report[0x2e8..0x330]);
            assert!(crypto::ecdsa_verify_raw(
                &certs[0],
                DigestAlg::Sha384,
                &report[..SNP_SIGNED_LEN],
                &r,
                &s,
            )
            .unwrap());
            let err = verify(report, chain, root).expect_err(message);
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{message}: {err}");
            assert!(err.to_string().contains(message), "{message}: {err}");
        }

        #[test]
        fn rejects_freshly_signed_invalid_report_formats() {
            let (base, chain, root, key) = synthetic_case();
            let mut cases: Vec<(usize, Vec<u8>, &str)> = Vec::new();
            for (offset, values, message) in [
                (0, vec![0u32, 1, 6], "version"),
                (0x34, vec![0, 2], "algorithm"),
                (0x30, vec![4], "VMPL"),
                (0x48, vec![4, 8, 12, 16, 20, 24, 28], "VCEK"),
                (0x48, vec![32, 1 << 31], "signer-info"),
                (0x48, vec![2], "chip ID"),
            ] {
                for value in values {
                    cases.push((offset, value.to_le_bytes().to_vec(), message));
                }
            }
            let policy = u64::from_le_bytes(base[8..16].try_into().unwrap());
            cases.push((8, (policy & !(1 << 17)).to_le_bytes().to_vec(), "policy"));
            for bit in 26..64 {
                cases.push((8, (policy | (1 << bit)).to_le_bytes().to_vec(), "policy"));
            }
            for offset in (0x4c..0x50)
                .chain(0x18b..0x1a0)
                .chain([0x1eb, 0x1ef])
                .chain(0x1f8..0x2a0)
            {
                cases.push((offset, vec![1], "reserved"));
            }
            cases.push((0x1a0, vec![0; 64], "chip ID"));
            cases.push((0x18a, vec![16], "stepping"));
            for (offset, value, message) in cases {
                let mut report = base.clone();
                report[offset..offset + value.len()].copy_from_slice(&value);
                sign_report(&mut report, &key);
                assert_invalid(&report, &chain, &root, message);
            }
        }

        #[test]
        fn accepts_versioned_layouts_without_adding_policy_or_stepping_rules() {
            let (base, chain, root, key) = synthetic_case();
            assert_eq!(&base[0x188..0x18b], &[0x19, 1, 1]);
            for version in 2u32..=5 {
                let mut report = base.clone();
                report[..4].copy_from_slice(&version.to_le_bytes());
                if version == 2 {
                    report[0x188..0x1a0].fill(0);
                }
                if version == 5 {
                    report[0x1f8..0x208].fill(0xff); // opaque mitigation vectors
                }
                sign_report(&mut report, &key);
                let result = verify(&report, &chain, &root).unwrap();
                assert!(result.chain_valid && result.signature_valid);
                // v2 has no CPUID bytes; v5 still reserves bytes after the vectors.
                report[if version == 2 { 0x188 } else { 0x208 }] = 1;
                sign_report(&mut report, &key);
                assert_invalid(&report, &chain, &root, "reserved");
            }
            for step in [0, 2, 15] {
                let mut report = base.clone();
                report[0x18a] = step; // Milan-B0 does not prescribe CPUID stepping
                report[0x48] = 1; // author-key enable is not a signer selector
                report[0x40..0x48].fill(0xff); // PLATFORM_INFO remains opaque
                report[0x0a] |= 0x08; // DEBUG is acceptance policy, not wire format
                sign_report(&mut report, &key);
                verify(&report, &chain, &root).unwrap();
            }
        }

        #[test]
        fn rejects_freshly_signed_hwid_tcb_and_cpuid_mismatches() {
            let (base, chain, root, key) = synthetic_case();
            for (offset, message) in [
                (0x1a0, "HWID"),
                (0x1df, "HWID"),
                (0x180, "TCB"),
                (0x181, "TCB"),
                (0x186, "TCB"),
                (0x187, "TCB"),
                (0x182, "TCB"),
                (0x188, "CPUID"),
                (0x189, "CPUID"),
            ] {
                let mut report = base.clone();
                report[offset] ^= 1;
                sign_report(&mut report, &key);
                assert_invalid(&report, &chain, &root, message);
            }
        }

        #[test]
        fn rejects_chain_signed_missing_or_duplicate_amd_extensions() {
            let extensions = amd_extensions();
            for index in 0..extensions.len() {
                for duplicate in [false, true] {
                    let mut changed = extensions.clone();
                    let message = if duplicate {
                        changed.push(extensions[index].clone());
                        "duplicate"
                    } else {
                        changed.remove(index);
                        "missing"
                    };
                    let (report, chain, root, _) =
                        synthetic_leaf("SEV-VCEK", Nid::SECP384R1, &changed);
                    assert_invalid(&report, &chain, &root, message);
                }
            }
        }

        #[test]
        fn rejects_chain_signed_different_or_malformed_amd_extensions() {
            for (index, value, message) in [
                (0, vec![2, 1, 1], "structVersion"),
                (1, b"\x16\x08Genoa-B0".to_vec(), "CPUID"),
                (1, b"\x0c\x08Milan-B0".to_vec(), "IA5String"),
                (2, vec![2, 1, 5], "TCB"),
                (3, vec![2, 1, 1], "TCB"),
                (4, vec![2, 1, 25], "TCB"),
                (5, vec![2, 2, 0, 220], "TCB"),
                (5, vec![2, 1, 219], "INTEGER"), // negative, missing sign pad
                (2, vec![2, 2, 0, 4], "INTEGER"), // unnecessary sign pad
                (2, vec![2, 2, 4], "INTEGER"),   // truncated
                (6, vec![0; 64], "HWID"),
                (6, vec![0; 63], "HWID"),
            ] {
                let mut extensions = amd_extensions();
                extensions[index].1 = value;
                let (report, chain, root, _) =
                    synthetic_leaf("SEV-VCEK", Nid::SECP384R1, &extensions);
                assert_invalid(&report, &chain, &root, message);
            }
        }

        #[test]
        fn rejects_chain_signed_wrong_leaf_role_or_curve() {
            for (cn, curve, message) in [
                ("SEV-VLEK", Nid::SECP384R1, "subject"),
                ("SEV-OTHER", Nid::SECP384R1, "subject"),
                ("SEV-VCEK", Nid::X9_62_PRIME256V1, "secp384r1"),
            ] {
                let (report, chain, root, _) = synthetic_leaf(cn, curve, &amd_extensions());
                assert_invalid(&report, &chain, &root, message);
            }
        }
    }

    #[test]
    fn rejects_short_report() {
        for fixture in &REAL_FIXTURES {
            assert!(
                verify_snp_report(
                    &fixture.report[..16],
                    fixture.chain,
                    &SnpVerifyPolicy::default()
                )
                .is_err(),
                "{}",
                fixture.name
            );
        }
    }

    #[test]
    fn rejects_tampered_real_report_body() {
        for fixture in &REAL_FIXTURES {
            for offset in [0x10, 0x90, 0x180, 0x188, 0x1a0, 0x2a0] {
                let mut report = fixture.report.to_vec();
                report[offset] ^= 1;
                assert!(
                    verify_snp_report(&report, fixture.chain, &SnpVerifyPolicy::default()).is_err(),
                    "{} at {offset:#x}",
                    fixture.name
                );
            }
        }
    }

    #[test]
    fn rejects_real_chain_under_untrusted_root() {
        // The VCEK chain does not root at the Intel SGX Root CA.
        let intel = roots::intel_sgx_root().unwrap();
        for fixture in &REAL_FIXTURES {
            assert!(
                verify_snp_report_with_roots(
                    fixture.report,
                    fixture.chain,
                    std::slice::from_ref(&intel),
                    &SnpVerifyPolicy::default(),
                )
                .is_err(),
                "{}",
                fixture.name
            );
        }
    }

    #[test]
    fn rejects_mismatched_report_and_chain() {
        for report in &REAL_FIXTURES {
            for chain in &REAL_FIXTURES {
                if report.name != chain.name {
                    assert!(
                        verify_snp_report(report.report, chain.chain, &SnpVerifyPolicy::default())
                            .is_err(),
                        "{} report with {} chain",
                        report.name,
                        chain.name
                    );
                }
            }
        }
    }

    #[test]
    fn verifies_real_reports() {
        for fixture in &REAL_FIXTURES {
            let result =
                verify_snp_report(fixture.report, fixture.chain, &SnpVerifyPolicy::default())
                    .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
            assert!(
                result.chain_valid && result.signature_valid && result.vcek_binding_valid,
                "{}",
                fixture.name
            );
            let report = crate::parse::snp_report(fixture.report).unwrap();
            assert_eq!(report.version, fixture.version, "{}", fixture.name);
            assert_eq!(report.cpuid(), Some(fixture.cpuid), "{}", fixture.name);
            assert_eq!(
                result.measurements.reported_tcb, fixture.reported_tcb,
                "{}",
                fixture.name
            );
            assert_eq!(
                hex(&result.measurements.measurement),
                fixture.measurement,
                "{}",
                fixture.name
            );
            assert_eq!(
                hex(&result.measurements.report_data[..32]),
                fixture.report_data_prefix,
                "{}",
                fixture.name
            );
            assert_eq!(
                hex(&result.measurements.chip_id[..8]),
                fixture.chip_id_prefix,
                "{}",
                fixture.name
            );
            assert_eq!(
                result.measurements.report_data, report.report_data,
                "{}",
                fixture.name
            );
            assert_eq!(
                result.measurements.chip_id, report.chip_id,
                "{}",
                fixture.name
            );
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
