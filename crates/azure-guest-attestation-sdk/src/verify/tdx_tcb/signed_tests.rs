// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509NameBuilder, X509,
    },
};
use serde_json::json;

const NOW: i64 = 1_790_294_400;
const SIGNER: &str = "Intel SGX TCB Signing";
const QUOTE: &[u8] = include_bytes!("../testdata/oe_tdx_v5_servtd_quote.bin");
const ENDORSEMENTS: &[u8] = include_bytes!("../testdata/oe_tdx_v5_servtd_endorsements.bin");

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn certificate(
    key: &PKey<Private>,
    cn: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    validity: (i64, i64),
) -> Result<X509, openssl::error::ErrorStack> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", cn)?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let serial = BigNum::from_u32(if issuer.is_some() { 2 } else { 1 })?.to_asn1_integer()?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(issuer.map_or(&name, |(ca, _)| ca.subject_name()))?;
    cert.set_pubkey(key)?;
    cert.set_not_before(Asn1Time::from_unix(validity.0)?.as_ref())?;
    cert.set_not_after(Asn1Time::from_unix(validity.1)?.as_ref())?;
    let mut constraints = BasicConstraints::new();
    let mut usage = KeyUsage::new();
    if issuer.is_none() {
        constraints.ca().pathlen(0);
        usage.key_cert_sign().crl_sign();
    } else {
        usage.digital_signature();
    }
    cert.append_extension(constraints.critical().build()?)?;
    cert.append_extension(usage.critical().build()?)?;
    cert.sign(issuer.map_or(key, |(_, key)| key), MessageDigest::sha256())?;
    Ok(cert.build())
}

struct Fixture {
    key: PKey<Private>,
    chain: Vec<u8>,
    roots: Vec<crypto::Cert>,
    info: Value,
}

impl Fixture {
    fn new(cn: &str, validity: (i64, i64)) -> Self {
        let ca_key = key();
        let ca = certificate(
            &ca_key,
            "Synthetic test root",
            None,
            (NOW - 86400, NOW + 86400),
        )
        .unwrap();
        let key = key();
        let leaf = certificate(&key, cn, Some((&ca, &ca_key)), validity).unwrap();
        let root_pem = ca.to_pem().unwrap();
        let chain = [leaf.to_pem().unwrap(), root_pem.clone()].concat();
        let roots = vec![
            roots::intel_sgx_root().unwrap(),
            crypto::cert_from_pem(&root_pem).unwrap(),
        ];
        let original = TdxCollateral::from_oe_endorsements(ENDORSEMENTS).unwrap();
        let raw = original.tcb_info.strip_suffix(&[0]).unwrap();
        let mut info = serde_json::from_slice::<Value>(raw).unwrap()["tcbInfo"].take();
        info["issueDate"] = json!("2026-09-24T00:00:00Z");
        info["nextUpdate"] = json!("2026-09-26T00:00:00Z");
        Self {
            key,
            chain,
            roots,
            info,
        }
    }

    fn valid() -> Self {
        Self::new(SIGNER, (NOW - 3600, NOW + 3600))
    }

    fn sign(&self, raw: &str) -> Vec<u8> {
        let digest = hash(MessageDigest::sha256(), raw.as_bytes()).unwrap();
        let sig = EcdsaSig::sign(&digest, &self.key.ec_key().unwrap()).unwrap();
        let signature = [
            sig.r().to_vec_padded(32).unwrap(),
            sig.s().to_vec_padded(32).unwrap(),
        ]
        .concat();
        format!(
            r#"{{"tcbInfo":{raw},"signature":"{}"}}"#,
            hex::encode(signature)
        )
        .into_bytes()
    }

    fn collateral<'a>(&'a self, signed: &'a [u8]) -> TdxCollateral<'a> {
        TdxCollateral {
            tcb_info: signed,
            tcb_issuer_chain: &self.chain,
        }
    }

    fn verify(
        &self,
        signed: &[u8],
        baseline_date: Option<i64>,
    ) -> io::Result<TdxCollateralVerifyResult> {
        verify_with_roots(
            QUOTE,
            &self.collateral(signed),
            &TdxTcbPolicy {
                verification_time: Some(NOW),
                baseline_date,
            },
            &self.roots,
        )
    }

    fn rejects(&self, signed: &[u8], expected: &str) {
        // A permissive baseline must never bypass authentication or freshness.
        for baseline in [None, Some(0)] {
            let error = self.verify(signed, baseline).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error:?}"
            );
        }
    }
}

fn assert_status(result: &TdxCollateralVerifyResult, expected: TcbStatus) {
    assert_eq!(result.verification_time, NOW);
    assert_eq!(result.tcb.aggregate_status, expected);
    assert_eq!(result.tcb.current.status, expected);
    assert_eq!(result.tcb.launch.status, expected);
    assert_eq!(result.tcb.initial.as_ref().unwrap().status, expected);
}

#[test]
fn full_verification_and_pinned_only_rejection() {
    let f = Fixture::valid();
    let signed = f.sign(&f.info.to_string());
    assert_status(&f.verify(&signed, None).unwrap(), TcbStatus::UpToDate);
    let error = verify_td_quote_with_collateral(
        QUOTE,
        &f.collateral(&signed),
        &TdxTcbPolicy {
            verification_time: Some(NOW),
            baseline_date: None,
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("certificate chain validation failed"),
        "{error}"
    );
}

#[test]
fn signed_whitespace_is_preserved_not_reserialized() {
    let f = Fixture::valid();
    let pretty = serde_json::to_string_pretty(&f.info).unwrap();
    let signed = f.sign(&pretty);
    assert_status(&f.verify(&signed, None).unwrap(), TcbStatus::UpToDate);
    let compacted = String::from_utf8(signed)
        .unwrap()
        .replace(&pretty, &f.info.to_string());
    f.rejects(compacted.as_bytes(), "TCB Info signature is invalid");
}

#[test]
fn tampered_json_and_corrupt_signature_fail_authentication() {
    let f = Fixture::valid();
    let signed = f.sign(&f.info.to_string());
    let tampered = String::from_utf8(signed.clone())
        .unwrap()
        .replacen("UpToDate", "Revoked", 1);
    f.rejects(tampered.as_bytes(), "TCB Info signature is invalid");
    let mut corrupt: Value = serde_json::from_slice(&signed).unwrap();
    // r = s = 0 is deterministically invalid, not a probabilistic bit flip.
    corrupt["signature"] = json!("00".repeat(64));
    f.rejects(
        corrupt.to_string().as_bytes(),
        "TCB Info signature is invalid",
    );
}

#[test]
fn pck_impersonation_and_invalid_certificate_dates_are_rejected() {
    for (cn, validity, expected) in [
        (
            "Intel SGX PCK Certificate",
            (NOW - 3600, NOW + 3600),
            "not Intel SGX TCB Signing",
        ),
        (SIGNER, (NOW - 7200, NOW - 1), "certificate has expired"),
        (
            SIGNER,
            (NOW + 1, NOW + 3600),
            "certificate is not yet valid",
        ),
    ] {
        let f = Fixture::new(cn, validity);
        f.rejects(&f.sign(&f.info.to_string()), expected);
    }
}

#[test]
fn signed_mismatches_headers_and_invalid_freshness_are_rejected() {
    let f = Fixture::valid();
    for (field, value, expected) in [
        ("fmspc", json!("000000000000"), "FMSPC does not match"),
        ("pceId", json!("ffff"), "PCE ID does not match"),
        ("id", json!("SGX"), "only Intel TDX TCB Info"),
        ("version", json!(2), "only Intel TDX TCB Info"),
        ("tcbType", json!(1), "only Intel TDX TCB Info"),
        ("nextUpdate", json!("2026-09-25T00:00:00Z"), "expired"),
        ("nextUpdate", json!("2026-09-24T12:00:00Z"), "expired"),
        ("issueDate", json!("2026-09-25T12:00:00Z"), "not yet valid"),
        ("issueDate", json!("2026-09-26T00:00:00Z"), "not yet valid"),
        ("issueDate", json!("2026-09-27T00:00:00Z"), "not yet valid"),
    ] {
        let mut info = f.info.clone();
        info[field] = value;
        f.rejects(&f.sign(&info.to_string()), expected);
    }
}

#[test]
fn missing_optional_module_identities_never_passes_module_one() {
    let mut f = Fixture::valid();
    f.info
        .as_object_mut()
        .unwrap()
        .remove("tdxModuleIdentities");
    let signed = f.sign(&f.info.to_string());
    for baseline in [None, Some(0)] {
        let result = f.verify(&signed, baseline).unwrap();
        assert_status(&result, TcbStatus::NotEvaluated);
        assert!(result
            .tcb
            .initial
            .unwrap()
            .reason
            .unwrap()
            .contains("TDX_01"));
    }
}

#[test]
fn lower_svn_levels_preserve_status_and_baseline_only_relaxes_outdated() {
    let f = Fixture::valid();
    // Keep the signed quote intact; make a higher level unreachable so its
    // actual SVN selects the lower signed level, for platform and module paths.
    for module in [false, true] {
        for (status, expected, relaxed) in [
            ("OutOfDate", TcbStatus::OutOfDate, TcbStatus::UpToDate),
            ("Revoked", TcbStatus::Revoked, TcbStatus::Revoked),
        ] {
            let mut info = f.info.clone();
            let levels: Vec<&mut Value> = if module {
                info["tdxModuleIdentities"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .map(|identity| &mut identity["tcbLevels"])
                    .collect()
            } else {
                vec![&mut info["tcbLevels"]]
            };
            for levels in levels {
                let mut higher = levels[0].clone();
                let mut lower = higher.clone();
                if module {
                    higher["tcb"]["isvsvn"] = json!(255);
                } else {
                    higher["tcb"]["sgxtcbcomponents"][0]["svn"] = json!(255);
                }
                lower["tcbStatus"] = json!(status);
                *levels = json!([higher, lower]);
            }
            let signed = f.sign(&info.to_string());
            assert_status(&f.verify(&signed, None).unwrap(), expected.clone());
            assert_status(&f.verify(&signed, Some(NOW)).unwrap(), expected);
            assert_status(&f.verify(&signed, Some(0)).unwrap(), relaxed);
        }
    }
}
