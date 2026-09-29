// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Authenticated Intel TDX TCB Info assessment, including Service-TD history.
//!
//! This supplements quote signature verification; it is **not full Intel QVL**.
//! CRLs and QE identity collateral are not evaluated. Initial PCESVN and initial
//! module signer/attributes are not recorded in the quote and cannot be checked.
//! A successful call authenticates the inputs; callers must inspect all component
//! statuses and apply their own measurement/migration policy.

mod evaluate;
#[cfg(all(test, target_os = "linux"))]
mod signed_tests;
pub use evaluate::{TcbAssessment, TcbStatus, TdxTcbResult};

use super::{crypto, roots, tdx};
use crate::tee_report::td_quote::{parse_td_quote, TdQuoteBody};
use serde::Deserialize;
use serde_json::{value::RawValue, Value};
use std::io;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Signed Intel TDX TCB Info JSON and its PEM signing-certificate chain.
/// Input is untrusted until [`verify_td_quote_with_collateral`] succeeds.
#[derive(Clone, Copy, Debug)]
pub struct TdxCollateral<'a> {
    /// Complete JSON object containing `tcbInfo` and its hex `signature`.
    pub tcb_info: &'a [u8],
    /// PEM chain for the Intel SGX TCB Signing certificate (leaf first).
    pub tcb_issuer_chain: &'a [u8],
}

impl<'a> TdxCollateral<'a> {
    /// Read the flattened **x64** `tdx_ql_qve_collateral_t` v4 encoding.
    /// Ignores pointer slots, uses checked lengths, and rejects trailing data.
    /// Only TCB Info and its issuer chain are used; this does not verify CRLs
    /// or QE identity included in the bundle.
    pub fn from_flattened_endorsements(bytes: &'a [u8]) -> io::Result<Self> {
        if bytes.len() < 120 || bytes.len() > 16 * 1024 * 1024 {
            return Err(invalid("invalid flattened x64 collateral size"));
        }
        let u32_at = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        if u32_at(0) != 4 || u32_at(4) != 0x81 {
            return Err(invalid("expected flattened x64 collateral v4 for TDX"));
        }
        let mut sections = [&[][..]; 7];
        let mut cursor = 120usize;
        for (i, section) in sections.iter_mut().enumerate() {
            let size = u32_at(16 + i * 16) as usize;
            let end = cursor
                .checked_add(size)
                .ok_or_else(|| invalid("collateral length overflow"))?;
            *section = bytes
                .get(cursor..end)
                .ok_or_else(|| invalid("truncated flattened collateral section"))?;
            cursor = end;
        }
        if cursor != bytes.len() || sections[3].is_empty() || sections[4].is_empty() {
            return Err(invalid(
                "missing TCB Info or trailing flattened collateral bytes",
            ));
        }
        Ok(Self {
            tcb_info: sections[4],
            tcb_issuer_chain: sections[3],
        })
    }
}

/// Policy for authenticated TCB Info assessment.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct TdxTcbPolicy {
    /// Explicit Unix time; `None` uses the current time for both certificates
    /// and TCB Info. Historical evaluation does not establish present freshness.
    pub verification_time: Option<i64>,
    /// Optional certification-date baseline. A matched TCB date
    /// at/after this timestamp relaxes OutOfDate to UpToDate (or OutOfDate-
    /// ConfigurationNeeded to ConfigurationNeeded). This is an explicit policy
    /// relaxation, never a bypass of signature or freshness checks.
    pub baseline_date: Option<i64>,
}

/// Signature-verified quote and authenticated TCB Info assessment.
#[derive(Debug)]
#[non_exhaustive]
pub struct TdxCollateralVerifyResult {
    /// Cryptographic quote verification and authenticated measurements.
    pub quote: tdx::TdxVerifyResult,
    /// TCB statuses. `NotEvaluated` must never be treated as UpToDate.
    pub tcb: TdxTcbResult,
    /// Effective certificate and collateral validation time, Unix seconds.
    pub verification_time: i64,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn date(text: &str) -> io::Result<i64> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map(|d| d.unix_timestamp())
        .map_err(|e| invalid(format!("invalid TCB date: {e}")))
}

fn hex_array<const N: usize>(value: &Value, key: &str) -> io::Result<[u8; N]> {
    let mut result = [0; N];
    hex::decode_to_slice(
        value[key]
            .as_str()
            .ok_or_else(|| invalid(format!("missing {key}")))?,
        &mut result,
    )
    .map_err(|e| invalid(format!("invalid {key}: {e}")))?;
    Ok(result)
}

#[derive(Deserialize)]
struct SignedTcbInfo {
    #[serde(rename = "tcbInfo")]
    tcb_info: Box<RawValue>,
    signature: String,
}

fn authenticate_signature(
    collateral: &TdxCollateral<'_>,
    now: i64,
    trusted_roots: &[crypto::Cert],
) -> io::Result<Value> {
    // Serialized sections include C-string terminators. Strip only the trailing NULs;
    // preserve the original signed tcbInfo bytes (including JSON whitespace).
    let json = collateral.tcb_info.trim_ascii_end();
    let json = json.strip_suffix(&[0]).map_or(json, |_| {
        &json[..json.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1)]
    });
    let signed: SignedTcbInfo =
        serde_json::from_slice(json).map_err(|e| invalid(format!("TCB Info JSON: {e}")))?;
    let signature =
        hex::decode(&signed.signature).map_err(|e| invalid(format!("TCB signature: {e}")))?;
    if signature.len() != 64 {
        return Err(invalid("TCB Info signature must be 64 bytes"));
    }
    let chain = crypto::parse_pem_chain(collateral.tcb_issuer_chain)?;
    let (signer, rest) = chain
        .split_first()
        .ok_or_else(|| invalid("missing TCB signer"))?;
    let intermediates: Vec<_> = rest
        .iter()
        .filter(|c| !crypto::cert_is_self_signed(c))
        .cloned()
        .collect();
    crypto::verify_cert_chain_at(signer, &intermediates, trusted_roots, Some(now))?;
    // A PCK certificate also chains to Intel, but is not a TCB Info signer.
    let der = crypto::cert_to_der(signer)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| invalid(format!("TCB signer X509: {e}")))?;
    let name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|n| n.as_str().ok());
    if name != Some("Intel SGX TCB Signing") {
        return Err(invalid("collateral leaf is not Intel SGX TCB Signing"));
    }
    if !crypto::ecdsa_verify_raw(
        signer,
        crypto::DigestAlg::Sha256,
        signed.tcb_info.get().as_bytes(),
        &signature[..32],
        &signature[32..],
    )? {
        return Err(invalid("TCB Info signature is invalid"));
    }
    let info: Value =
        serde_json::from_str(signed.tcb_info.get()).map_err(|e| invalid(e.to_string()))?;
    if info["id"] != "TDX" || info["version"] != 3 || info["tcbType"] != 0 {
        return Err(invalid(
            "only Intel TDX TCB Info v3, tcbType 0 is supported",
        ));
    }
    Ok(info)
}

fn validate_freshness(info: &Value, now: i64) -> io::Result<()> {
    let issued = date(
        info["issueDate"]
            .as_str()
            .ok_or_else(|| invalid("missing issueDate"))?,
    )?;
    let expires = date(
        info["nextUpdate"]
            .as_str()
            .ok_or_else(|| invalid("missing nextUpdate"))?,
    )?;
    if issued >= expires || now < issued || now >= expires {
        return Err(invalid(
            "TCB Info expired or not yet valid at verification time",
        ));
    }
    Ok(())
}

/// Verify quote signatures and authenticated TCB Info, including initial TCB
/// assessment when ATTRIBUTES.SERVTD_EXT is set.
///
/// Errors reject invalid signatures, chains, malformed collateral, FMSPC/PCE-ID
/// mismatch, or stale collateral. Unsupported initial model mappings yield
/// `NotEvaluated` (including aggregate status), never an implicit pass.
///
/// **Not full DCAP/QVL verification:** CRL revocation and QE identity assessment
/// are not performed. No Service-TD hash allowlist or migration continuity policy
/// is inferred. Baseline relaxation is opt-in; inspect all component results.
pub fn verify_td_quote_with_collateral(
    quote_bytes: &[u8],
    collateral: &TdxCollateral<'_>,
    policy: &TdxTcbPolicy,
) -> io::Result<TdxCollateralVerifyResult> {
    let root = roots::intel_sgx_root()?;
    verify_with_roots(quote_bytes, collateral, policy, std::slice::from_ref(&root))
}

fn verify_with_roots(
    quote_bytes: &[u8],
    collateral: &TdxCollateral<'_>,
    policy: &TdxTcbPolicy,
    trusted_roots: &[crypto::Cert],
) -> io::Result<TdxCollateralVerifyResult> {
    let now = policy
        .verification_time
        .unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
    if now < 0 || policy.baseline_date.is_some_and(|d| d < 0) {
        return Err(invalid(
            "verification and baseline times must be nonnegative Unix seconds",
        ));
    }
    let quote = tdx::verify_td_quote_with_roots(
        quote_bytes,
        trusted_roots,
        &tdx::TdxVerifyPolicy {
            verification_time: Some(now),
        },
    )?;
    let info = authenticate_signature(collateral, now, trusted_roots)?;
    validate_freshness(&info, now)?;
    assess_verified_quote(quote_bytes, quote, &info, policy, now)
}

fn assess_verified_quote(
    quote_bytes: &[u8],
    quote: tdx::TdxVerifyResult,
    info: &Value,
    policy: &TdxTcbPolicy,
    now: i64,
) -> io::Result<TdxCollateralVerifyResult> {
    let parsed = parse_td_quote(quote_bytes).map_err(|e| invalid(e.to_string()))?;
    let fmspc = parsed.fmspc().map_err(|e| invalid(e.to_string()))?;
    if fmspc != hex_array::<6>(info, "fmspc")? {
        return Err(invalid("TCB Info FMSPC does not match authenticated PCK"));
    }
    let chain = crypto::parse_pem_chain(
        parsed
            .pck_cert_chain()
            .ok_or_else(|| invalid("missing PCK chain"))?,
    )?;
    let pck = pck_tcb(&crypto::cert_to_der(&chain[0])?)?;
    if pck.pce_id != hex_array::<2>(info, "pceId")? {
        return Err(invalid("TCB Info PCE ID does not match authenticated PCK"));
    }
    let (base, current_svn) = match &parsed.body {
        TdQuoteBody::Tdx10(b) => (b, &b.tee_tcb_svn),
        TdQuoteBody::Tdx15(b) => (&b.base, &b.tee_tcb_svn_2),
        TdQuoteBody::Tdx15Ex(b) => (&b.base.base, &b.base.tee_tcb_svn_2),
        _ => return Err(invalid("unsupported TDX body")),
    };
    let binding = Some((&base.mr_signer_seam, &base.seam_attributes));
    let mut current = evaluate::assess(info, &pck.cpu, Some(pck.pce_svn), current_svn, binding)?;
    let mut launch = evaluate::assess(
        info,
        &pck.cpu,
        Some(pck.pce_svn),
        &base.tee_tcb_svn,
        binding,
    )?;
    let required = u64::from_le_bytes(base.td_attributes) & (1 << 17) != 0;
    let mut initial = if required {
        Some(match quote.service_td.as_ref() {
            Some(b) if evaluate::initial_model_matches(&b.init_tee_fmspc, &fmspc) => {
                evaluate::assess(info, &b.init_cpu_svn, None, &b.init_tee_tcb_svn, None)?
            }
            _ => TcbAssessment { status: TcbStatus::NotEvaluated, tcb_date: None,
                reason: Some("SERVTD_EXT requires type-4 evidence and a supported initial-model/current-FMSPC mapping".into()) },
        })
    } else {
        None
    };
    evaluate::apply_baseline(&mut current, policy.baseline_date)?;
    evaluate::apply_baseline(&mut launch, policy.baseline_date)?;
    if let Some(initial) = &mut initial {
        evaluate::apply_baseline(initial, policy.baseline_date)?;
    }
    let mut aggregate = evaluate::aggregate(&current, &launch);
    if let Some(initial) = &initial {
        aggregate = evaluate::aggregate(&aggregate, initial);
    }
    Ok(TdxCollateralVerifyResult {
        quote,
        verification_time: now,
        tcb: TdxTcbResult {
            current,
            launch,
            initial,
            aggregate_status: aggregate.status,
            aggregate_date: aggregate.tcb_date,
        },
    })
}

struct PckTcb {
    cpu: [u8; 16],
    pce_svn: u16,
    pce_id: [u8; 2],
}

// Minimal bounded DER walker for the Intel SGX extension (not all X509).
// The outer certificate is parsed by x509-parser and already authenticated.
fn tlv<'a>(bytes: &mut &'a [u8]) -> io::Result<(u8, &'a [u8])> {
    let (&tag, rest) = bytes
        .split_first()
        .ok_or_else(|| invalid("truncated DER"))?;
    let (&first, mut rest) = rest
        .split_first()
        .ok_or_else(|| invalid("missing DER length"))?;
    let mut length = first as usize;
    if first & 0x80 != 0 {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count || rest[0] == 0 {
            return Err(invalid("invalid DER length"));
        }
        length = 0;
        for b in &rest[..count] {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(*b as usize))
                .ok_or_else(|| invalid("DER length overflow"))?;
        }
        if length < 128 {
            return Err(invalid("noncanonical DER length"));
        }
        rest = &rest[count..];
    }
    let value = rest
        .get(..length)
        .ok_or_else(|| invalid("truncated DER value"))?;
    *bytes = &rest[length..];
    Ok((tag, value))
}

fn tagged<'a>(bytes: &mut &'a [u8], expected: u8) -> io::Result<&'a [u8]> {
    let (tag, value) = tlv(bytes)?;
    if tag != expected {
        return Err(invalid("unexpected SGX DER tag"));
    }
    Ok(value)
}

fn entry<'a>(sequence: &'a [u8], oid: &[u8], tag: u8) -> io::Result<&'a [u8]> {
    let mut sequence = sequence;
    let mut found = None;
    while !sequence.is_empty() {
        let mut item = tagged(&mut sequence, 0x30)?;
        let key = tagged(&mut item, 0x06)?;
        if key == oid {
            if found.is_some() {
                return Err(invalid("duplicate SGX extension entry"));
            }
            found = Some(tagged(&mut item, tag)?);
            if !item.is_empty() {
                return Err(invalid("trailing SGX entry bytes"));
            }
        }
    }
    found.ok_or_else(|| invalid("missing SGX TCB extension entry"))
}

fn integer(bytes: &[u8], max: u16) -> io::Result<u16> {
    if bytes.is_empty()
        || bytes.len() > 3
        || bytes[0] & 0x80 != 0
        || (bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0)
    {
        return Err(invalid("invalid SGX SVN integer"));
    }
    let n = bytes.iter().fold(0u32, |n, b| n * 256 + *b as u32);
    if n > max as u32 {
        return Err(invalid("SGX SVN out of range"));
    }
    Ok(n as u16)
}

fn pck_tcb(der: &[u8]) -> io::Result<PckTcb> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| invalid(e.to_string()))?;
    let ext = cert
        .get_extension_unique(
            &x509_parser::oid_registry::Oid::from(&[1, 2, 840, 113741, 1, 13, 1])
                .map_err(|e| invalid(format!("SGX OID: {e:?}")))?,
        )
        .map_err(|e| invalid(e.to_string()))?
        .ok_or_else(|| invalid("missing Intel SGX extension"))?;
    let mut bytes = ext.value;
    let sequence = tagged(&mut bytes, 0x30)?;
    if !bytes.is_empty() {
        return Err(invalid("trailing SGX extension bytes"));
    }
    let prefix: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 1, 0x0d, 1];
    let mut oid = prefix.to_vec();
    oid.push(2);
    let tcb = entry(sequence, &oid, 0x30)?;
    let mut cpu = [0; 16];
    oid.push(0);
    for (i, svn) in cpu.iter_mut().enumerate() {
        *oid.last_mut().unwrap() = i as u8 + 1;
        *svn = integer(entry(tcb, &oid, 0x02)?, 255)? as u8;
    }
    *oid.last_mut().unwrap() = 17;
    let pce_svn = integer(entry(tcb, &oid, 0x02)?, u16::MAX)?;
    let mut oid = prefix.to_vec();
    oid.push(3);
    let pce_id = entry(sequence, &oid, 0x04)?
        .try_into()
        .map_err(|_| invalid("invalid PCE ID length"))?;
    Ok(PckTcb {
        cpu,
        pce_svn,
        pce_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const QUOTE: &[u8] = include_bytes!("../testdata/servtd_tdx_v5_quote.bin");
    const COLLATERAL: &[u8] = include_bytes!("../testdata/servtd_tdx_v5_endorsements.bin");
    fn policy() -> TdxTcbPolicy {
        TdxTcbPolicy {
            verification_time: Some(1790294400),
            baseline_date: None,
        }
    }

    #[test]
    fn real_service_td_tcb_and_signed_fields() {
        let collateral = TdxCollateral::from_flattened_endorsements(COLLATERAL).unwrap();
        // This public fixture has incompatible certificate/collateral dates.
        // Test authenticated fields and matching separately, NOT as a full pass.
        let now = policy().verification_time.unwrap();
        let info =
            authenticate_signature(&collateral, now, &[roots::intel_sgx_root().unwrap()]).unwrap();
        assert!(validate_freshness(&info, now).is_err());
        let quote = tdx::verify_td_quote(
            QUOTE,
            &tdx::TdxVerifyPolicy {
                verification_time: Some(now),
            },
        )
        .unwrap();
        let result = assess_verified_quote(QUOTE, quote, &info, &policy(), now).unwrap();
        assert_eq!(result.tcb.aggregate_status, TcbStatus::UpToDate);
        assert_eq!(result.tcb.current.status, TcbStatus::UpToDate);
        assert_eq!(result.tcb.launch.status, TcbStatus::UpToDate);
        let initial = result.tcb.initial.unwrap();
        assert_eq!(initial.status, TcbStatus::UpToDate);
        assert_eq!(initial.tcb_date.as_deref(), Some("2023-08-09T00:00:00Z"));
        let body = result.quote.service_td.unwrap();
        assert!(body.servtd_ext());
        assert_eq!(hex::encode(body.init_tee_fmspc), "00000000f0060c0000000080");
        assert_eq!(
            hex::encode(body.init_cpu_svn),
            "0404191b04ff00060000000000000000"
        );
    }

    #[test]
    fn expired_collateral_is_not_a_current_pass() {
        let collateral = TdxCollateral::from_flattened_endorsements(COLLATERAL).unwrap();
        let mut policy = policy();
        policy.verification_time = Some(1790294400);
        assert!(verify_td_quote_with_collateral(QUOTE, &collateral, &policy)
            .unwrap_err()
            .to_string()
            .contains("expired"));
    }

    #[test]
    fn tampered_tcb_info_and_migration_fields_fail() {
        let original = TdxCollateral::from_flattened_endorsements(COLLATERAL).unwrap();
        let mut json = original.tcb_info.to_vec();
        let pos = json.windows(8).position(|s| s == b"UpToDate").unwrap();
        json[pos] = b'X';
        let modified = TdxCollateral {
            tcb_info: &json,
            ..original
        };
        assert!(verify_td_quote_with_collateral(QUOTE, &modified, &policy())
            .unwrap_err()
            .to_string()
            .contains("signature"));
        for offset in [648, 649, 681, 729, 777, 785, 801, 817, 829, 877] {
            let mut q = QUOTE.to_vec();
            q[54 + offset] ^= 1;
            assert!(verify_td_quote_with_collateral(&q, &original, &policy()).is_err());
        }
    }

    #[test]
    fn flattened_bundle_rejects_truncation_lengths_and_tail() {
        for n in [0, 119, 120, COLLATERAL.len() - 1] {
            assert!(TdxCollateral::from_flattened_endorsements(&COLLATERAL[..n]).is_err());
        }
        let mut bytes = COLLATERAL.to_vec();
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(TdxCollateral::from_flattened_endorsements(&bytes).is_err());
        let mut bytes = COLLATERAL.to_vec();
        bytes.push(0);
        assert!(TdxCollateral::from_flattened_endorsements(&bytes).is_err());
    }
}
