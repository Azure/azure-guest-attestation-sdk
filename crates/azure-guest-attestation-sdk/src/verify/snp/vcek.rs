// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VCEK leaf-role and report binding checks, not certificate-chain verification.

use crate::tee_report::snp::SnpReport;
use std::{collections::BTreeMap, io};
use x509_parser::{extensions::ParsedExtension, prelude::*};

const STRUCT_VERSION: &str = "1.3.6.1.4.1.3704.1.1";
const PRODUCT_NAME: &str = "1.3.6.1.4.1.3704.1.2";
const BOOT: &str = "1.3.6.1.4.1.3704.1.3.1";
const TEE: &str = "1.3.6.1.4.1.3704.1.3.2";
const SNP: &str = "1.3.6.1.4.1.3704.1.3.3";
const MICROCODE: &str = "1.3.6.1.4.1.3704.1.3.8";
const FMC: &str = "1.3.6.1.4.1.3704.1.3.9";
const HWID: &str = "1.3.6.1.4.1.3704.1.4";
const CSP_ID: &str = "1.3.6.1.4.1.3704.1.5";
const RESERVED_SPL: [&str; 4] = [
    "1.3.6.1.4.1.3704.1.3.4",
    "1.3.6.1.4.1.3704.1.3.5",
    "1.3.6.1.4.1.3704.1.3.6",
    "1.3.6.1.4.1.3704.1.3.7",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Generation {
    Milan,
    Genoa,
    Turin,
}

impl Generation {
    fn cpuid(self) -> [u8; 2] {
        // Match only these exact supported family/model pairs, not ranges.
        match self {
            Self::Milan => [0x19, 0x01],
            Self::Genoa => [0x19, 0x11],
            Self::Turin => [0x1a, 0x02],
        }
    }

    fn issuer_cn(self) -> &'static str {
        match self {
            Self::Milan => "SEV-Milan",
            Self::Genoa => "SEV-Genoa",
            Self::Turin => "SEV-Turin",
        }
    }
}

/// Check a chain-verified VCEK leaf's role and binding to an SNP report.
///
/// The caller MUST first verify this exact certificate's chain to trusted AMD
/// roots. Issuer CN and AMD extensions are authenticated only under that
/// precondition; this function does not establish trust in arbitrary DER.
/// The caller must also verify the report signature before accepting claims.
/// No revocation, minimum TCB, nonce, or guest-policy validation occurs here.
pub(super) fn validate(der: &[u8], report: &SnpReport) -> io::Result<()> {
    let (remaining, cert) =
        X509Certificate::from_der(der).map_err(|_| invalid_data("invalid VCEK certificate DER"))?;
    if !remaining.is_empty() {
        return Err(invalid_data("trailing bytes after VCEK certificate DER"));
    }
    if !common_name_is(cert.subject(), "SEV-VCEK") {
        return Err(invalid_data(
            "VCEK subject must have exactly one CN: SEV-VCEK",
        ));
    }
    let algorithm = &cert.public_key().algorithm;
    if algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || algorithm
            .parameters
            .as_ref()
            .filter(|parameters| parameters.tag() == x509_parser::der_parser::ber::Tag::Oid)
            .and_then(|parameters| parameters.as_oid().ok())
            .is_none_or(|oid| oid.to_id_string() != "1.3.132.0.34")
    {
        return Err(invalid_data(
            "VCEK public key must use EC with named curve secp384r1",
        ));
    }
    let generation = validate_extensions(cert.extensions(), report)?;
    // This is a role/product consistency check of the authenticated issuer
    // name, NOT a substitute for verifying the ASK chain to a pinned AMD root.
    if !common_name_is(cert.issuer(), generation.issuer_cn()) {
        return Err(invalid_data("VCEK issuer CN does not match ProductName"));
    }
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn common_name_is(name: &X509Name<'_>, expected: &str) -> bool {
    let mut names = name.iter_common_name();
    names.next().and_then(|name| name.as_str().ok()) == Some(expected) && names.next().is_none()
}

fn extension_values<'a>(
    extensions: &[X509Extension<'a>],
) -> io::Result<BTreeMap<String, &'a [u8]>> {
    let mut values = BTreeMap::new();
    for ext in extensions {
        match ext.parsed_extension() {
            ParsedExtension::ParseError { .. } => {
                return Err(invalid_data("malformed VCEK extension"));
            }
            ParsedExtension::BasicConstraints(constraints) if constraints.ca => {
                return Err(invalid_data("VCEK must be a leaf, not a CA"));
            }
            ParsedExtension::KeyUsage(usage)
                if !usage.digital_signature() || usage.key_cert_sign() =>
            {
                return Err(invalid_data(
                    "VCEK KeyUsage must allow digital signatures and forbid certificate signing",
                ));
            }
            _ => {}
        }
        if values.insert(ext.oid.to_id_string(), ext.value).is_some() {
            return Err(invalid_data("duplicate VCEK extension"));
        }
    }
    Ok(values)
}

fn required<'a>(values: &BTreeMap<String, &'a [u8]>, oid: &str) -> io::Result<&'a [u8]> {
    values
        .get(oid)
        .copied()
        .ok_or_else(|| invalid_data(&format!("missing VCEK extension {oid}")))
}

fn validate_extensions(
    extensions: &[X509Extension<'_>],
    report: &SnpReport,
) -> io::Result<Generation> {
    if !matches!(report.version, 2..=5) {
        return Err(invalid_data("unsupported SNP report version"));
    }
    if (report.flags >> 2) & 7 != 0 {
        return Err(invalid_data("report must select the VCEK signing key"));
    }
    if report.flags & (1 << 1) != 0 || report.chip_id.iter().all(|byte| *byte == 0) {
        return Err(invalid_data(
            "masked or zero chip ID cannot establish chip binding",
        ));
    }

    let values = extension_values(extensions)?;
    if values.contains_key(CSP_ID) {
        return Err(invalid_data("VLEK CSP_ID extension is forbidden in a VCEK"));
    }
    for (oid, value) in &values {
        if RESERVED_SPL.contains(&oid.as_str()) {
            // These are not required: real Turin VCEKs omit SPL4. If present,
            // reserved extensions must still be canonical INTEGER zero.
            if der_u8(value)? != 0 {
                return Err(invalid_data("nonzero reserved TCB extension"));
            }
        } else if oid.starts_with("1.3.6.1.4.1.3704.")
            && !matches!(
                oid.as_str(),
                STRUCT_VERSION | PRODUCT_NAME | BOOT | TEE | SNP | MICROCODE | FMC | HWID
            )
        {
            return Err(invalid_data("unsupported AMD VCEK extension"));
        }
    }
    let struct_version = der_u8(required(&values, STRUCT_VERSION)?)?;
    let generation = product(required(&values, PRODUCT_NAME)?)?;
    // Generation-specific versions, confirmed by the real AMD leaf fixtures:
    // Milan/Genoa use the original layout (0); Turin uses the FMC layout (1).
    let expected_version = u8::from(generation == Generation::Turin);
    if struct_version != expected_version {
        return Err(invalid_data(
            "VCEK structVersion does not match product generation",
        ));
    }
    if report.version >= 3 {
        // The preserved report layout stores CPUID family/model/stepping at
        // offsets 0x188..0x18b, the first three bytes of _reserved1.
        if report._reserved1[..2] != generation.cpuid() {
            return Err(invalid_data(
                "unsupported or mismatched report CPUID family/model",
            ));
        }
        // ProductName suffixes are not equated with report CPUID stepping.
        // The caller's structural validation enforces the stepping range.
    }

    let tcb = report.reported_tcb.to_le_bytes();
    let (boot, tee, snp, reserved, hwid_len) = match generation {
        Generation::Milan | Generation::Genoa => {
            if values.contains_key(FMC) {
                return Err(invalid_data("FMC extension is only supported for Turin"));
            }
            (tcb[0], tcb[1], tcb[6], &tcb[2..6], 64)
        }
        Generation::Turin => {
            if der_u8(required(&values, FMC)?)? != tcb[0] {
                return Err(invalid_data("VCEK FMC TCB mismatch"));
            }
            (tcb[1], tcb[2], tcb[3], &tcb[4..7], 8)
        }
    };
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(invalid_data("nonzero reserved reported TCB bytes"));
    }
    for (oid, expected) in [(BOOT, boot), (TEE, tee), (SNP, snp), (MICROCODE, tcb[7])] {
        if der_u8(required(&values, oid)?)? != expected {
            return Err(invalid_data(&format!(
                "VCEK TCB mismatch for extension {oid}"
            )));
        }
    }
    if !hwid_matches(required(&values, HWID)?, &report.chip_id, hwid_len) {
        return Err(invalid_data(
            "VCEK HWID mismatch or nonzero Turin chip ID padding",
        ));
    }
    Ok(generation)
}

/// Decode only canonical DER INTEGERs in 0..=255; reject bare bytes.
fn der_u8(value: &[u8]) -> io::Result<u8> {
    match value {
        [0x02, 0x01, byte] if *byte < 0x80 => Ok(*byte),
        [0x02, 0x02, 0x00, byte] if *byte >= 0x80 => Ok(*byte),
        _ => Err(invalid_data(
            "VCEK extension must be a canonical DER INTEGER in 0..=255",
        )),
    }
}

fn product(value: &[u8]) -> io::Result<Generation> {
    let [0x16, length, name @ ..] = value else {
        return Err(invalid_data("VCEK ProductName must be a DER IA5String"));
    };
    // All supported names fit short-form DER lengths; exact matching below
    // also rejects non-ASCII, embedded NULs, unknown products and suffixes.
    if *length >= 128 || usize::from(*length) != name.len() {
        return Err(invalid_data("noncanonical or truncated VCEK ProductName"));
    }
    // These exact ProductName spellings identify only the generation here.
    // No mapping from their suffixes to report CPUID stepping is assumed.
    match name {
        b"Milan-B0" | b"Milan-B1" => Ok(Generation::Milan),
        b"Genoa" | b"Genoa-B0" | b"Genoa-B1" | b"Genoa-B2" => Ok(Generation::Genoa),
        b"Turin" | b"Turin-B0" | b"Turin-B1" => Ok(Generation::Turin),
        _ => Err(invalid_data("unsupported VCEK ProductName")),
    }
}

fn hwid_matches(value: &[u8], chip: &[u8; 64], len: usize) -> bool {
    // Check raw length first, so a hardware ID beginning with 04 is never
    // misdecoded as an OCTET STRING wrapper.
    let hwid = if value.len() == len {
        value
    } else if value.len() == len + 2 && value[0] == 4 && usize::from(value[1]) == len {
        &value[2..]
    } else {
        return false;
    };
    hwid == &chip[..len] && chip[len..].iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::super::tests::REAL_FIXTURES as FIXTURES;
    use super::*;
    use crate::parse;
    use crate::verify::{crypto, roots};

    fn fixture(index: usize) -> (Vec<u8>, SnpReport) {
        let fixture = &FIXTURES[index];
        let chain = crypto::parse_pem_chain(fixture.chain).unwrap();
        (
            crypto::cert_to_der(&chain[0]).unwrap(),
            parse::snp_report(fixture.report).unwrap(),
        )
    }

    fn invalid<T: std::fmt::Debug>(result: io::Result<T>, message: &str) {
        let error = result.expect_err(message);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(message), "{error}");
    }

    fn extension<'a>(oid: &str, value: &'a [u8]) -> X509Extension<'a> {
        X509Extension::new(
            oid.parse().unwrap(),
            false,
            value,
            ParsedExtension::Unparsed,
        )
    }

    fn replace_extension<'a>(extensions: &mut [X509Extension<'a>], oid: &str, value: &'a [u8]) {
        let ext = extensions
            .iter_mut()
            .find(|ext| ext.oid.to_id_string() == oid)
            .unwrap();
        *ext = extension(oid, value);
    }

    // These mutations intentionally invalidate the certificate signature. They
    // exercise only this module's checks, never assert that the mutated DER is
    // trusted. Production must pass the original chain-verified leaf DER.
    fn replace_bytes(der: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        assert_eq!(old.len(), new.len());
        let positions: Vec<_> = der
            .windows(old.len())
            .enumerate()
            .filter_map(|(i, bytes)| (bytes == old).then_some(i))
            .collect();
        assert_eq!(positions.len(), 1);
        let mut changed = der.to_vec();
        changed[positions[0]..positions[0] + old.len()].copy_from_slice(new);
        changed
    }

    #[test]
    fn validates_chain_verified_platform_fixtures() {
        let trusted = roots::amd_ark_roots().unwrap();
        for fixture in &FIXTURES {
            let chain = crypto::parse_pem_chain(fixture.chain).unwrap();
            let intermediates: Vec<_> = chain[1..]
                .iter()
                .filter(|cert| !crypto::cert_is_self_signed(cert))
                .cloned()
                .collect();
            crypto::verify_cert_chain(&chain[0], &intermediates, &trusted).unwrap();
            validate(
                &crypto::cert_to_der(&chain[0]).unwrap(),
                &parse::snp_report(fixture.report).unwrap(),
            )
            .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
        }
    }

    #[test]
    fn version_two_infers_each_certificate_product_without_cpuid() {
        for index in 0..FIXTURES.len() {
            let (der, mut report) = fixture(index);
            report.version = 2;
            report._reserved1 = [0; 24];
            validate(&der, &report).unwrap();
        }
        let (der, mut report) = fixture(0);
        for version in [0, 1, 6, u32::MAX] {
            report.version = version;
            invalid(validate(&der, &report), "report version");
        }
    }

    #[test]
    fn rejects_every_reported_tcb_component_and_reserved_byte_mismatch() {
        for index in 0..FIXTURES.len() {
            let (der, report) = fixture(index);
            for byte in 0..8 {
                let mut changed = report;
                changed.reported_tcb ^= 1u64 << (8 * byte);
                invalid(validate(&der, &changed), "TCB");
            }
        }
    }

    #[test]
    fn only_reported_tcb_is_bound_here() {
        for index in 0..FIXTURES.len() {
            let (der, mut report) = fixture(index);
            report.current_tcb = u64::MAX;
            report.committed_tcb = u64::MAX;
            report.launch_tcb = u64::MAX;
            validate(&der, &report).unwrap();
        }
    }

    #[test]
    fn rejects_unknown_or_mismatched_cpuid_family_and_model() {
        for index in 0..FIXTURES.len() {
            let (der, report) = fixture(index);
            for cpuid in [[0x18, 1], [0x19, 2], [0x19, 0x12], [0x1a, 0x11]] {
                let mut changed = report;
                changed._reserved1[..2].copy_from_slice(&cpuid);
                invalid(validate(&der, &changed), "CPUID");
            }
            for cpuid in [[0x19, 1], [0x19, 0x11], [0x1a, 2]] {
                if report._reserved1[..2] == cpuid {
                    continue;
                }
                let mut changed = report;
                changed._reserved1[..2].copy_from_slice(&cpuid);
                invalid(validate(&der, &changed), "CPUID");
            }
        }
    }

    #[test]
    fn product_binding_does_not_equate_suffix_with_report_stepping() {
        for index in 0..FIXTURES.len() {
            let (der, report) = fixture(index);
            for step in [0, 2, 3, 15] {
                let mut changed = report;
                changed._reserved1[2] = step;
                validate(&der, &changed).unwrap();
            }
        }
    }

    #[test]
    fn rejects_chip_mismatch_masking_zero_id_and_turin_padding() {
        for index in 0..FIXTURES.len() {
            let (der, report) = fixture(index);
            for byte in 0..64 {
                let mut changed = report;
                changed.chip_id[byte] ^= 1;
                invalid(validate(&der, &changed), "HWID");
            }
            let mut changed = report;
            changed.chip_id.fill(0);
            invalid(validate(&der, &changed), "chip binding");
            changed = report;
            changed.flags |= 1 << 1;
            invalid(validate(&der, &changed), "chip binding");
        }
    }

    #[test]
    fn rejects_vlek_none_and_reserved_report_signers() {
        for index in 0..FIXTURES.len() {
            let (der, report) = fixture(index);
            for signer in 1..=7 {
                let mut changed = report;
                changed.flags = (changed.flags & !(7 << 2)) | (signer << 2);
                invalid(validate(&der, &changed), "VCEK signing key");
            }
        }
    }

    #[test]
    fn rejects_invalid_certificate_der_and_trailing_bytes() {
        for index in 0..FIXTURES.len() {
            let (der, report) = fixture(index);
            invalid(validate(&[], &report), "certificate DER");
            invalid(validate(&der[..der.len() - 1], &report), "certificate DER");
            let mut trailing = der;
            trailing.push(0);
            invalid(validate(&trailing, &report), "trailing");
        }
    }

    #[test]
    fn rejects_wrong_subject_issuer_algorithm_and_curve() {
        let (der, report) = fixture(0);
        for (old, new, message) in [
            (b"SEV-VCEK".as_slice(), b"SEV-VLEK".as_slice(), "subject"),
            (b"SEV-Milan".as_slice(), b"SEV-Genoa".as_slice(), "issuer"),
            (
                &[0x06, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1],
                &[0x06, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 2],
                "public key",
            ),
            (
                &[0x06, 5, 0x2b, 0x81, 4, 0, 0x22],
                &[0x06, 5, 0x2b, 0x81, 4, 0, 0x23],
                "public key",
            ),
            (
                &[0x06, 5, 0x2b, 0x81, 4, 0, 0x22],
                &[0x04, 5, 0x2b, 0x81, 4, 0, 0x22],
                "public key",
            ),
        ] {
            invalid(validate(&replace_bytes(&der, old, new), &report), message);
        }
    }

    #[test]
    fn requires_a_single_exact_common_name() {
        let name = b"\x30\x13\x31\x11\x30\x0f\x06\x03\x55\x04\x03\x0c\x08SEV-VCEK";
        let (_, parsed) = X509Name::from_der(name).unwrap();
        assert!(common_name_is(&parsed, "SEV-VCEK"));
        assert!(!common_name_is(&parsed, "SEV-VLEK"));
        let (_, empty) = X509Name::from_der(&[0x30, 0]).unwrap();
        assert!(!common_name_is(&empty, "SEV-VCEK"));
        let mut duplicate = vec![0x30, 38];
        duplicate.extend_from_slice(&name[2..]);
        duplicate.extend_from_slice(&name[2..]);
        let (_, parsed) = X509Name::from_der(&duplicate).unwrap();
        assert!(!common_name_is(&parsed, "SEV-VCEK"));
    }

    #[test]
    fn rejects_missing_required_and_duplicate_extensions() {
        for (index, data) in FIXTURES.iter().enumerate() {
            let (der, report) = fixture(index);
            let (_, cert) = X509Certificate::from_der(&der).unwrap();
            let mut required = vec![
                STRUCT_VERSION,
                PRODUCT_NAME,
                BOOT,
                TEE,
                SNP,
                MICROCODE,
                HWID,
            ];
            if data.struct_version == 1 {
                required.push(FMC);
            }
            for oid in required {
                let remaining: Vec<_> = cert
                    .extensions()
                    .iter()
                    .filter(|ext| ext.oid.to_id_string() != oid)
                    .cloned()
                    .collect();
                invalid(validate_extensions(&remaining, &report), "missing");
            }
            for ext in cert.extensions() {
                let mut duplicate = cert.extensions().to_vec();
                duplicate.push(ext.clone());
                invalid(validate_extensions(&duplicate, &report), "duplicate");
            }
        }
        let repeated = [
            extension("2.5.29.14", &[4, 0]),
            extension("2.5.29.14", &[4, 0]),
        ];
        invalid(extension_values(&repeated), "duplicate");
    }

    #[test]
    fn rejects_bad_struct_version_tcb_product_and_vlek_extensions() {
        let (der, report) = fixture(0);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        for value in [&[2, 1, 1][..], &[0], &[2, 2, 0, 0]] {
            let mut changed = cert.extensions().to_vec();
            replace_extension(&mut changed, STRUCT_VERSION, value);
            assert!(validate_extensions(&changed, &report).is_err());
        }
        for oid in [BOOT, TEE, SNP, MICROCODE] {
            let mut changed = cert.extensions().to_vec();
            replace_extension(&mut changed, oid, &[2, 1, 0x80]);
            invalid(validate_extensions(&changed, &report), "INTEGER");
        }
        for value in [b"\x16\x08Milan-B9".as_slice(), b"\x0c\x08Milan-B0"] {
            let mut changed = cert.extensions().to_vec();
            replace_extension(&mut changed, PRODUCT_NAME, value);
            invalid(validate_extensions(&changed, &report), "ProductName");
        }
        for (oid, value, message) in [
            (CSP_ID, b"\x16\x03csp".as_slice(), "VLEK"),
            (FMC, &[2, 1, 0], "FMC"),
            ("1.3.6.1.4.1.3704.1.99", &[2, 1, 0], "unsupported AMD"),
        ] {
            let mut changed = cert.extensions().to_vec();
            changed.push(extension(oid, value));
            invalid(validate_extensions(&changed, &report), message);
        }
        for oid in RESERVED_SPL {
            let mut changed = cert.extensions().to_vec();
            replace_extension(&mut changed, oid, &[2, 1, 1]);
            invalid(validate_extensions(&changed, &report), "reserved TCB");
        }
    }

    #[test]
    fn struct_version_must_match_generation_and_use_canonical_der() {
        for (index, data) in FIXTURES.iter().enumerate() {
            let (der, report) = fixture(index);
            let (_, cert) = X509Certificate::from_der(&der).unwrap();
            for version in [0, 1, 2, 255] {
                if version == data.struct_version {
                    continue;
                }
                let value = if version < 128 {
                    vec![2, 1, version]
                } else {
                    vec![2, 2, 0, version]
                };
                let mut changed = cert.extensions().to_vec();
                replace_extension(&mut changed, STRUCT_VERSION, &value);
                invalid(validate_extensions(&changed, &report), "structVersion");
            }
            let value = [2, 2, 0, data.struct_version];
            let mut changed = cert.extensions().to_vec();
            replace_extension(&mut changed, STRUCT_VERSION, &value);
            invalid(validate_extensions(&changed, &report), "INTEGER");
        }
    }

    #[test]
    fn rejects_ca_role_invalid_key_usage_and_malformed_standard_extensions() {
        // X.509 Extension SEQUENCEs for BasicConstraints, parsed using the
        // same parser as the certificate instead of synthesizing parsed state.
        let ca = b"\x30\x0f\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff";
        let malformed = b"\x30\x0a\x06\x03\x55\x1d\x13\x04\x03\x30\x01\xff";
        for (der, message) in [(ca.as_slice(), "leaf"), (malformed.as_slice(), "malformed")] {
            let (rest, ext) = X509Extension::from_der(der).unwrap();
            assert!(rest.is_empty());
            invalid(extension_values(&[ext]), message);
        }
        // KeyUsage BIT STRINGs: digitalSignature is required when present,
        // and keyCertSign is forbidden even alongside digitalSignature.
        for (bits, unused, valid) in [(0x80, 7, true), (0x08, 3, false), (0x84, 2, false)] {
            let der = [
                0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, unused, bits,
            ];
            let (rest, ext) = X509Extension::from_der(&der).unwrap();
            assert!(rest.is_empty());
            if valid {
                extension_values(&[ext]).unwrap();
            } else {
                invalid(extension_values(&[ext]), "KeyUsage");
            }
        }
    }

    #[test]
    fn integer_decoder_accepts_exactly_canonical_unsigned_bytes() {
        for value in 0..=255u8 {
            let der = if value < 128 {
                vec![2, 1, value]
            } else {
                vec![2, 2, 0, value]
            };
            assert_eq!(der_u8(&der).unwrap(), value);
        }
        for value in [
            &[][..],
            &[0],
            &[255],
            &[2, 0],
            &[2, 1],
            &[2, 1, 128],
            &[2, 1, 255],
            &[2, 2, 0, 127],
            &[2, 2, 1, 0],
            &[2, 2, 255, 255],
            &[2, 1, 0, 0],
            &[2, 0x81, 1, 0],
            &[2, 0x80, 0, 0],
            &[4, 1, 0],
        ] {
            invalid(der_u8(value), "INTEGER");
        }
    }

    #[test]
    fn product_names_map_to_generation_only() {
        for (name, generation) in [
            ("Milan-B0", Generation::Milan),
            ("Milan-B1", Generation::Milan),
            ("Genoa", Generation::Genoa),
            ("Genoa-B0", Generation::Genoa),
            ("Genoa-B1", Generation::Genoa),
            ("Genoa-B2", Generation::Genoa),
            ("Turin-B0", Generation::Turin),
            ("Turin-B1", Generation::Turin),
            ("Turin", Generation::Turin),
        ] {
            let mut der = vec![0x16, name.len() as u8];
            der.extend_from_slice(name.as_bytes());
            assert_eq!(product(&der).unwrap(), generation);
        }
        for value in [
            b"\x16\x05Milan".as_slice(),
            b"\x16\x08Genoa-B3",
            b"\x16\x08Turin-B2",
            b"\x16\x08milan-B0",
            b"\x16\x08Milan-B0\0",
            b"\x16\x09Milan-B0",
            b"\x0c\x08Milan-B0",
            b"\x16\x81\x08Milan-B0",
            b"\x16\x01\xff",
            b"",
        ] {
            invalid(product(value), "ProductName");
        }
    }

    #[test]
    fn binds_all_supported_product_generations_without_stepping_claims() {
        for (name, index, family, model) in [
            ("Milan-B0", 0, 0x19, 1),
            ("Milan-B1", 0, 0x19, 1),
            ("Genoa", 0, 0x19, 0x11),
            ("Genoa-B0", 0, 0x19, 0x11),
            ("Genoa-B1", 0, 0x19, 0x11),
            ("Genoa-B2", 0, 0x19, 0x11),
            ("Turin-B0", 1, 0x1a, 2),
            ("Turin-B1", 1, 0x1a, 2),
            ("Turin", 1, 0x1a, 2),
        ] {
            let (der, mut report) = fixture(index);
            let (_, cert) = X509Certificate::from_der(&der).unwrap();
            let mut value = vec![0x16, name.len() as u8];
            value.extend_from_slice(name.as_bytes());
            let mut changed = cert.extensions().to_vec();
            replace_extension(&mut changed, PRODUCT_NAME, &value);
            report._reserved1[..2].copy_from_slice(&[family, model]);
            for version in 3..=5 {
                report.version = version;
                for step in [1, 2] {
                    report._reserved1[2] = step;
                    validate_extensions(&changed, &report).unwrap();
                }
            }
            report.version = 2;
            report._reserved1 = [0; 24];
            validate_extensions(&changed, &report).unwrap();
        }
    }

    #[test]
    fn hwid_decoder_checks_raw_before_exact_octet_wrapper() {
        for len in [8, 64] {
            let mut chip = [0; 64];
            chip[..len].fill(0x42);
            chip[0] = 4;
            chip[1] = (len - 2) as u8;
            assert!(hwid_matches(&chip[..len], &chip, len));
            let mut wrapped = vec![4, len as u8];
            wrapped.extend_from_slice(&chip[..len]);
            assert!(hwid_matches(&wrapped, &chip, len));
            wrapped[1] -= 1;
            assert!(!hwid_matches(&wrapped, &chip, len));
            wrapped[1] += 1;
            wrapped.push(0);
            assert!(!hwid_matches(&wrapped, &chip, len));
            assert!(!hwid_matches(&chip[..len - 1], &chip, len));
            let mut long_length = vec![4, 0x81, len as u8];
            long_length.extend_from_slice(&chip[..len]);
            assert!(!hwid_matches(&long_length, &chip, len));
        }
    }
}
