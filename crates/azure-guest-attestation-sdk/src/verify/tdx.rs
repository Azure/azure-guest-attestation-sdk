// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local verification of Intel TDX ECDSA attestation quotes.
//!
//! Validates the full DCAP signature chain: the quote body is signed by the
//! attestation key, which is bound (via the QE report's `report_data`) to a
//! Quoting Enclave report signed by the platform PCK, whose certificate chain
//! validates to the pinned Intel SGX Root CA.
//!
//! All ECDSA components in a TDX quote are big-endian (unlike SEV-SNP).

use super::crypto::{self, Cert, DigestAlg};
use super::roots;
use crate::tee_report::td_quote::{
    parse_td_quote, TdQuoteBody, TdQuoteBodyTdx15Ex, TdQuoteCertification,
    TdQuoteEcdsaNestedCertification, TD_QUOTE_HEADER_V4_SIZE, TD_QUOTE_HEADER_V5_SIZE,
};
use std::io;

/// Offset of `report_data` within a 384-byte SGX report body.
const QE_REPORT_DATA_OFFSET: usize = 320;

/// Strip a QGS `GET_QUOTE_RESP` envelope (as written by the TDX Quote
/// Generation Service / MigTD) if present, returning the inner quote bytes.
///
/// Self-contained so verification does not depend on the parser's own QGS
/// handling; both must agree on the inner bytes for the signed range to match.
fn strip_qgs_envelope(bytes: &[u8]) -> &[u8] {
    const QGS_GET_QUOTE_RESP_PREFIX: usize = 24;
    const QGS_TYPE_GET_QUOTE_RESP: u32 = 1;
    if bytes.len() < QGS_GET_QUOTE_RESP_PREFIX {
        return bytes;
    }
    let le32 = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    if le32(4) != QGS_TYPE_GET_QUOTE_RESP || le32(8) as usize != bytes.len() {
        return bytes;
    }
    let start = QGS_GET_QUOTE_RESP_PREFIX + le32(16) as usize;
    let Some(end) = start.checked_add(le32(20) as usize) else {
        return bytes;
    };
    if end > bytes.len() || end.saturating_sub(start) < 4 {
        return bytes;
    }
    let inner = &bytes[start..end];
    match u16::from_le_bytes([inner[0], inner[1]]) {
        4 | 5 => inner,
        _ => bytes,
    }
}

/// Policy controls for signature and certificate-chain verification.
/// TCB assessment additionally requires [`super::tdx_tcb::verify_td_quote_with_collateral`].
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct TdxVerifyPolicy {
    /// Explicit Unix time for historical certificate validation. `None` uses
    /// the current time. A historical result is not proof of current freshness.
    pub verification_time: Option<i64>,
}

/// Key TD measurements extracted from a verified quote body.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct TdxMeasurements {
    /// Measurement of the initial TD contents.
    pub mr_td: [u8; 48],
    /// Measurement of the TDX module (SEAM).
    pub mr_seam: [u8; 48],
    /// Runtime extendable measurement registers 0..3.
    pub rtmr: [[u8; 48]; 4],
    /// Report data (guest-provided).
    pub report_data: [u8; 64],
    /// TEE TCB SVN.
    pub tee_tcb_svn: [u8; 16],
    /// TD attributes.
    pub td_attributes: [u8; 8],
    /// TD XFAM.
    pub xfam: [u8; 8],
}

/// Outcome of verifying a TDX quote.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct TdxVerifyResult {
    /// The quote body signature verified under the attestation key.
    pub quote_signature_valid: bool,
    /// The QE report's `report_data` binds the attestation key.
    pub attestation_key_bound: bool,
    /// The QE report signature verified under the PCK leaf.
    pub qe_report_signature_valid: bool,
    /// The PCK certificate chain validated to the pinned Intel SGX Root CA.
    pub pck_chain_valid: bool,
    /// The verified TD measurements from the quote body.
    pub measurements: TdxMeasurements,
    /// Signed Service-TD extension fields for a type-4 body. Their semantic
    /// applicability is gated by ATTRIBUTES.SERVTD_EXT (bit 17); field presence
    /// alone is not a migration-policy or TCB approval.
    pub service_td: Option<TdQuoteBodyTdx15Ex>,
}

/// Verify an Intel TDX ECDSA attestation quote.
///
/// `quote_bytes` may be a bare quote or a QGS `GET_QUOTE_RESP` wrapper (as
/// produced by the TDX Quote Generation Service / MigTD); the envelope is
/// unwrapped transparently. The PCK chain is validated to the **pinned** Intel
/// SGX Root CA. Returns an error if any check fails.
pub fn verify_td_quote(
    quote_bytes: &[u8],
    policy: &TdxVerifyPolicy,
) -> io::Result<TdxVerifyResult> {
    let root = roots::intel_sgx_root()?;
    verify_td_quote_with_roots(quote_bytes, std::slice::from_ref(&root), policy)
}

/// [`verify_td_quote`] against an explicit set of trusted roots. Exposed for
/// testing; production callers use [`verify_td_quote`].
pub(crate) fn verify_td_quote_with_roots(
    quote_bytes: &[u8],
    roots: &[Cert],
    policy: &TdxVerifyPolicy,
) -> io::Result<TdxVerifyResult> {
    // Unwrap any QGS envelope so the signed byte range matches the parse.
    let inner = strip_qgs_envelope(quote_bytes);
    let parsed =
        parse_td_quote(inner).map_err(|e| io::Error::other(format!("parse TD quote: {e}")))?;
    if !matches!(parsed.header.version, 4 | 5) || parsed.header.tee_type != 0x81 {
        return Err(io::Error::other("expected a TDX v4/v5 quote"));
    }
    let sig = parsed
        .signature
        .as_ref()
        .ok_or_else(|| io::Error::other("TD quote has no signature block"))?;

    // 1. Quote body signature: the attestation key signs header || TD report.
    let header_len = if parsed.header.version >= 5 {
        TD_QUOTE_HEADER_V5_SIZE
    } else {
        TD_QUOTE_HEADER_V4_SIZE
    };
    let signed_len = header_len + parsed.body_header.size as usize;
    if inner.len() < signed_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TD quote shorter than its signed region",
        ));
    }
    let (r, s) = sig.signature.split_at(32);
    if !crypto::ecdsa_p256_verify_point(&sig.attestation_public_key, &inner[..signed_len], r, s)? {
        return Err(io::Error::other("TD quote body signature is invalid"));
    }

    // 2. ECDSA certification: QE report + PCK chain.
    let ecdsa = match sig.certification.as_ref() {
        Some(TdQuoteCertification::EcdsaSigAux(e)) => e,
        _ => {
            return Err(io::Error::other(
                "TD quote missing ECDSA certification data",
            ))
        }
    };

    // 2a. Attestation-key binding: qe_report.report_data[..32] ==
    //     SHA-256(attestation_public_key || qe_auth_data).
    let mut bound_input = Vec::with_capacity(64 + ecdsa.auth_data.len());
    bound_input.extend_from_slice(&sig.attestation_public_key);
    bound_input.extend_from_slice(ecdsa.auth_data);
    let expected = crypto::sha256(&bound_input)?;
    let report_data = &ecdsa.qe_report[QE_REPORT_DATA_OFFSET..QE_REPORT_DATA_OFFSET + 32];
    if report_data != expected.as_slice() {
        return Err(io::Error::other(
            "attestation key is not bound to the QE report (report_data mismatch)",
        ));
    }

    // 2b. PCK certificate chain -> pinned Intel SGX Root CA.
    let pck_chain = match ecdsa.nested_certification.as_ref() {
        Some(TdQuoteEcdsaNestedCertification::PckCertChain(c)) => c,
        _ => return Err(io::Error::other("TD quote missing PCK certificate chain")),
    };
    let chain = crypto::parse_pem_chain(pck_chain.cert_chain)?;
    let (pck_leaf, rest) = chain
        .split_first()
        .ok_or_else(|| io::Error::other("empty PCK certificate chain"))?;
    let intermediates: Vec<Cert> = rest
        .iter()
        .filter(|c| !crypto::cert_is_self_signed(c))
        .cloned()
        .collect();
    crypto::verify_cert_chain_at(pck_leaf, &intermediates, roots, policy.verification_time)?;

    // 2c. QE report signature by the PCK leaf.
    let (qr, qs) = ecdsa.qe_report_signature.split_at(32);
    if !crypto::ecdsa_verify_raw(pck_leaf, DigestAlg::Sha256, &ecdsa.qe_report, qr, qs)? {
        return Err(io::Error::other("QE report signature is invalid"));
    }

    // Extract the verified TD measurements from the quote body.
    let base = match &parsed.body {
        TdQuoteBody::Tdx10(b) => b,
        TdQuoteBody::Tdx15(b) => &b.base,
        TdQuoteBody::Tdx15Ex(b) => &b.base.base,
        TdQuoteBody::Unknown { body_type, .. } => {
            return Err(io::Error::other(format!(
                "unsupported TD quote body type 0x{body_type:04x}"
            )))
        }
    };
    let measurements = TdxMeasurements {
        mr_td: base.mr_td,
        mr_seam: base.mr_seam,
        rtmr: [base.rtmr0, base.rtmr1, base.rtmr2, base.rtmr3],
        report_data: base.report_data,
        tee_tcb_svn: base.tee_tcb_svn,
        td_attributes: base.td_attributes,
        xfam: base.xfam,
    };

    Ok(TdxVerifyResult {
        quote_signature_valid: true,
        attestation_key_bound: true,
        qe_report_signature_valid: true,
        pck_chain_valid: true,
        measurements,
        service_td: match &parsed.body {
            TdQuoteBody::Tdx15Ex(body) => Some(*body),
            _ => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real MigTD TDX v4 quote (QGS-wrapped) with an embedded PCK chain that
    /// roots at the Intel SGX Root CA. Public measurements, no secrets.
    const REAL_QUOTE: &[u8] = include_bytes!("testdata/migtd_tdx_quote.bin");

    /// A real TDX v4 quote in **raw** form (no QGS `GetQuoteResponse`
    /// envelope), from a different TD. Exercises the non-wrapped input path.
    const RAW_QUOTE: &[u8] = include_bytes!("testdata/tdx_raw_quote.bin");

    /// A real TDX **v5** quote carrying a TDX 1.5 Service-TD extended body
    /// (`body_type` 4). Regression guard: the verifier previously rejected
    /// this body type outright even though the parser understood it.
    const V5_SERVICETD_QUOTE: &[u8] = include_bytes!("testdata/tdx_v5_servicetd_quote.bin");

    #[test]
    fn verifies_real_v5_service_td_quote() {
        let res = verify_td_quote(V5_SERVICETD_QUOTE, &TdxVerifyPolicy::default())
            .expect("v5 Service-TD quote verifies against pinned Intel root");
        assert!(res.quote_signature_valid);
        assert!(res.attestation_key_bound);
        assert!(res.qe_report_signature_valid);
        assert!(res.pck_chain_valid);
        let m = &res.measurements;
        assert_eq!(
            hex::encode(m.mr_td),
            "6f3e84c54ac6377614d4c139473db575a83b5db41bd845eecb4eedaf2788ea881309a410c4ceae9641406411f3f639b8"
        );
        assert_eq!(
            hex::encode(m.mr_seam),
            "55b58ef6b7ba987cceb6cf09c54e333d8d281702e2ca960711b109daf7d26f83309828763d5b403fd22ff8008e3e92d4"
        );
        assert_eq!(
            hex::encode(m.tee_tcb_svn),
            "0f010400000000000000000000000000"
        );
        // `migratable` (bit 29) is set on this TD.
        assert_eq!(hex::encode(m.td_attributes), "0000023000000000");
    }

    #[test]
    fn verifies_real_raw_tdx_quote() {
        let res = verify_td_quote(RAW_QUOTE, &TdxVerifyPolicy::default())
            .expect("raw (non-QGS) TDX quote verifies against pinned Intel root");
        assert!(res.quote_signature_valid);
        assert!(res.attestation_key_bound);
        assert!(res.qe_report_signature_valid);
        assert!(res.pck_chain_valid);
        let m = &res.measurements;
        assert_eq!(
            hex::encode(m.mr_td),
            "a2e61f1316e9e367e9c1f7a0adc98c48eb13875c399c85d286cee5ea2b05e57f2df9f61d903b0ae7ac5607d843dfffc1"
        );
        assert_eq!(
            hex::encode(m.mr_seam),
            "489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72"
        );
        // Distinct from the MigTD fixture: non-zero report_data and td_attributes.
        assert_eq!(
            hex::encode(&m.report_data[..32]),
            "2fff2283e9c2aa6772880ce7a5f7080c3e25d77d976c6128ee43a61c35d6ffa1"
        );
        assert_eq!(hex::encode(m.td_attributes), "0000001000000000");
    }

    #[test]
    fn verifies_real_tdx_quote_end_to_end() {
        let res = verify_td_quote(REAL_QUOTE, &TdxVerifyPolicy::default())
            .expect("real TDX quote verifies against pinned Intel root");
        assert!(res.quote_signature_valid);
        assert!(res.attestation_key_bound);
        assert!(res.qe_report_signature_valid);
        assert!(res.pck_chain_valid);
        // Verified measurements match the known values for this quote.
        assert_eq!(
            hex::encode(res.measurements.mr_td),
            "7ba9693cccf58775a97d78d21d06a33c29da53cb37773cffcc585c82deb00ed875246c661f26e673da1ebbcd683e9b36"
        );
        assert_eq!(hex::encode(res.measurements.xfam), "e718060000000000");
    }

    #[test]
    fn rejects_tampered_quote_body() {
        let mut q = REAL_QUOTE.to_vec();
        // Flip a byte inside the signed TD report body (past the 24-byte QGS
        // envelope + 48-byte header).
        q[24 + 48 + 16] ^= 0xff;
        assert!(verify_td_quote(&q, &TdxVerifyPolicy::default()).is_err());
    }

    #[test]
    fn rejects_untrusted_root() {
        // The real chain does not root at the AMD ARK, so verification fails.
        let ark = roots::amd_ark_roots().unwrap();
        let inner = strip_qgs_envelope(REAL_QUOTE);
        assert!(verify_td_quote_with_roots(inner, &ark, &TdxVerifyPolicy::default()).is_err());
    }
}
