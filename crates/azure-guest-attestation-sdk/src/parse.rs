// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless parsing functions for attestation artifacts.
//!
//! These functions require no TPM or network access — they operate purely on
//! byte slices and strings. Use them to inspect hardware reports, quotes,
//! endorsements, and attestation tokens offline.
//!
//! # Example
//!
//! ```no_run
//! use azure_guest_attestation_sdk::parse;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let raw_bytes = vec![0u8; 1184];
//! # let quote_bytes = vec![0u8; 100];
//! let snp = parse::snp_report(&raw_bytes)?;
//! println!("SNP policy: 0x{:016x}", snp.policy);
//!
//! let quote = parse::td_quote(&quote_bytes)?;
//! println!("TDX quote version: {}", quote.header.version);
//! # Ok(())
//! # }
//! ```

use std::io;

use crate::report::{CvmAttestationReport, RuntimeClaims};
use crate::tee_report::snp::SnpReport;
use crate::tee_report::td_quote::{ParsedTdQuote, TdQuoteParseError};
use crate::tee_report::tdx::TdReport;
use crate::tee_report::vbs::VbsReport;

/// Parse raw bytes into an AMD SEV-SNP attestation report.
///
/// The input must be at least [`SNP_REPORT_SIZE`](crate::tee_report::snp::SNP_REPORT_SIZE)
/// bytes (0x4a0 = 1184 bytes).
pub fn snp_report(bytes: &[u8]) -> io::Result<SnpReport> {
    use crate::tee_report::snp::SNP_REPORT_SIZE;
    if bytes.len() < SNP_REPORT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "SNP report buffer too small: have {} need {}",
                bytes.len(),
                SNP_REPORT_SIZE,
            ),
        ));
    }
    // Safety: SnpReport is repr(C) with no padding invariants beyond alignment,
    // and we have verified the buffer is large enough.
    let report: SnpReport = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
    Ok(report)
}

/// Pretty-print an SNP report to a human-readable string.
pub fn snp_report_pretty(report: &SnpReport) -> String {
    crate::tee_report::pretty_snp(report)
}

/// Parse raw bytes into an Intel TDX report (TDREPORT_STRUCT).
///
/// The input must be at least [`TDX_REPORT_SIZE`](crate::tee_report::tdx::TDX_REPORT_SIZE)
/// bytes (0x400 = 1024 bytes).
pub fn tdx_report(bytes: &[u8]) -> io::Result<TdReport> {
    use crate::tee_report::tdx::TDX_REPORT_SIZE;
    if bytes.len() < TDX_REPORT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TDX report buffer too small: have {} need {}",
                bytes.len(),
                TDX_REPORT_SIZE,
            ),
        ));
    }
    let report: TdReport = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
    Ok(report)
}

/// Pretty-print a TDX report to a human-readable string.
pub fn tdx_report_pretty(report: &TdReport) -> String {
    crate::tee_report::pretty_tdx(report)
}

/// Parse raw bytes into an Intel TDX quote (v4 or v5).
///
/// Supports all body types (TDX 1.0, TDX 1.5, legacy).
/// Returns the fully parsed quote structure including header, body,
/// signature, and certification data.
pub fn td_quote(bytes: &[u8]) -> Result<ParsedTdQuote<'_>, TdQuoteParseError> {
    crate::tee_report::td_quote::parse_td_quote(bytes)
}

/// Pretty-print a parsed TDX quote to a human-readable string.
pub fn td_quote_pretty(quote: &ParsedTdQuote) -> String {
    format!("{quote:#?}")
}

/// Parse raw bytes into a VBS (Virtualization-Based Security) report.
///
/// The input must be at least [`VBS_REPORT_SIZE`](crate::tee_report::vbs::VBS_REPORT_SIZE)
/// bytes (0x230 = 560 bytes).
pub fn vbs_report(bytes: &[u8]) -> io::Result<VbsReport> {
    use crate::tee_report::vbs::VBS_REPORT_SIZE;
    if bytes.len() < VBS_REPORT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "VBS report buffer too small: have {} need {}",
                bytes.len(),
                VBS_REPORT_SIZE,
            ),
        ));
    }
    let report: VbsReport = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
    Ok(report)
}

/// Pretty-print a VBS report to a human-readable string.
pub fn vbs_report_pretty(report: &VbsReport) -> String {
    crate::tee_report::pretty_vbs(report)
}

/// Parse the full CVM attestation report (NV blob) including optional runtime claims.
///
/// The input is the raw blob read from the CVM report NV index. It contains:
/// - Fixed-size [`CvmAttestationReport`] header + TEE report
/// - Optional variable-length JSON [`RuntimeClaims`] tail
pub fn cvm_report(bytes: &[u8]) -> io::Result<(CvmAttestationReport, Option<RuntimeClaims>)> {
    CvmAttestationReport::parse_with_runtime_claims(bytes)
}

/// Decoded claims from a JWT attestation token (header + payload).
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// Raw JWT header JSON.
    pub header: serde_json::Value,
    /// Raw JWT payload JSON (the claims).
    pub payload: serde_json::Value,
}

/// Parse a JWT attestation token (base64url-encoded, dot-separated).
///
/// This performs **no signature verification** — it only decodes and parses
/// the header and payload. Use this to inspect MAA token claims offline.
///
/// Returns `Ok(TokenClaims)` with the decoded header and payload JSON.
pub fn attestation_token(token: &str) -> io::Result<TokenClaims> {
    use base64::Engine;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "JWT must have at least header.payload parts",
        ));
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header_bytes = b64
        .decode(parts[0].as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("header json: {e}")))?;

    let payload_bytes = b64
        .decode(parts[1].as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("payload base64: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("payload json: {e}")))?;

    Ok(TokenClaims { header, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // attestation_token tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_attestation_token_roundtrip() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let payload = serde_json::json!({"sub": "test", "iss": "maa", "exp": 9999999999u64});
        let sig = "fakesig";

        let token = format!(
            "{}.{}.{}",
            b64.encode(serde_json::to_vec(&header).unwrap()),
            b64.encode(serde_json::to_vec(&payload).unwrap()),
            sig,
        );

        let claims = attestation_token(&token).expect("parse token");
        assert_eq!(claims.header["alg"], "RS256");
        assert_eq!(claims.payload["iss"], "maa");
    }

    #[test]
    fn parse_token_too_few_parts() {
        assert!(attestation_token("notajwt").is_err());
    }

    #[test]
    fn parse_token_two_parts_no_signature() {
        // header.payload without a signature component is valid (2 parts ≥ 2).
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header = serde_json::json!({"alg": "none"});
        let payload = serde_json::json!({"aud": "test"});
        let token = format!(
            "{}.{}",
            b64.encode(serde_json::to_vec(&header).unwrap()),
            b64.encode(serde_json::to_vec(&payload).unwrap()),
        );
        let claims = attestation_token(&token).expect("two parts should parse");
        assert_eq!(claims.header["alg"], "none");
        assert_eq!(claims.payload["aud"], "test");
    }

    #[test]
    fn parse_token_invalid_base64_header() {
        let token = "!!!.eyJ0ZXN0IjoxfQ.sig";
        let err = attestation_token(token).unwrap_err();
        assert!(err.to_string().contains("header base64"), "{err}");
    }

    #[test]
    fn parse_token_invalid_base64_payload() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let good_header = b64.encode(b"{\"alg\":\"RS256\"}");
        let token = format!("{good_header}.!!!.sig");
        let err = attestation_token(&token).unwrap_err();
        assert!(err.to_string().contains("payload base64"), "{err}");
    }

    #[test]
    fn parse_token_invalid_json_header() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let token = format!(
            "{}.{}.sig",
            b64.encode(b"not json"),
            b64.encode(b"{\"a\":1}"),
        );
        let err = attestation_token(&token).unwrap_err();
        assert!(err.to_string().contains("header json"), "{err}");
    }

    // -----------------------------------------------------------------------
    // snp_report tests
    // -----------------------------------------------------------------------

    #[test]
    fn snp_report_too_small() {
        let buf = vec![0u8; 100]; // much smaller than 1184
        let err = snp_report(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("SNP report buffer too small"));
    }

    #[test]
    fn snp_report_valid_zeroed() {
        use crate::tee_report::snp::SNP_REPORT_SIZE;
        let buf = vec![0u8; SNP_REPORT_SIZE];
        let report = snp_report(&buf).expect("zeroed buffer should parse");
        assert_eq!(report.version, 0);
        assert_eq!(report.report_data, [0u8; 64]);
    }

    #[test]
    fn snp_report_oversized_succeeds() {
        use crate::tee_report::snp::SNP_REPORT_SIZE;
        // Extra bytes after the report should be ignored.
        let buf = vec![0u8; SNP_REPORT_SIZE + 256];
        snp_report(&buf).expect("oversized buffer should parse fine");
    }

    // -----------------------------------------------------------------------
    // tdx_report tests
    // -----------------------------------------------------------------------

    #[test]
    fn tdx_report_too_small() {
        let buf = vec![0u8; 100];
        let err = tdx_report(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("TDX report buffer too small"));
    }

    #[test]
    fn tdx_report_valid_zeroed() {
        use crate::tee_report::tdx::TDX_REPORT_SIZE;
        let buf = vec![0u8; TDX_REPORT_SIZE];
        let report = tdx_report(&buf).expect("zeroed buffer should parse");
        // TdReport is all-zero; just confirm no panic.
        assert_eq!(report.td_info.td_info_base.mr_td, [0u8; 48]);
    }

    // -----------------------------------------------------------------------
    // vbs_report tests
    // -----------------------------------------------------------------------

    #[test]
    fn vbs_report_too_small() {
        let buf = vec![0u8; 100];
        let err = vbs_report(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("VBS report buffer too small"));
    }

    #[test]
    fn vbs_report_valid_zeroed() {
        use crate::tee_report::vbs::VBS_REPORT_SIZE;
        let buf = vec![0u8; VBS_REPORT_SIZE];
        let report = vbs_report(&buf).expect("zeroed buffer should parse");
        assert_eq!(report.report_data, [0u8; 64]);
    }

    // -----------------------------------------------------------------------
    // cvm_report tests
    // -----------------------------------------------------------------------

    #[test]
    fn cvm_report_too_short() {
        let buf = vec![0u8; 10]; // much too short
        let err = cvm_report(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn cvm_report_no_runtime_claims() {
        // Fixed-size report with variable_data_size = 0 → no claims
        let buf = vec![0u8; core::mem::size_of::<CvmAttestationReport>()];
        let (rep, claims) = cvm_report(&buf).expect("parse minimal");
        assert_eq!(
            rep.tee_report.len(),
            crate::tee_report::snp::SNP_REPORT_SIZE
        );
        assert!(claims.is_none());
    }

    // -----------------------------------------------------------------------
    // pretty-print smoke tests
    // -----------------------------------------------------------------------

    #[test]
    fn snp_report_pretty_smoke() {
        use crate::tee_report::snp::SNP_REPORT_SIZE;
        let buf = vec![0u8; SNP_REPORT_SIZE];
        let report = snp_report(&buf).unwrap();
        let s = snp_report_pretty(&report);
        assert!(!s.is_empty());
    }

    #[test]
    fn tdx_report_pretty_smoke() {
        use crate::tee_report::tdx::TDX_REPORT_SIZE;
        let buf = vec![0u8; TDX_REPORT_SIZE];
        let report = tdx_report(&buf).unwrap();
        let s = tdx_report_pretty(&report);
        assert!(!s.is_empty());
    }

    #[test]
    fn vbs_report_pretty_smoke() {
        use crate::tee_report::vbs::VBS_REPORT_SIZE;
        let buf = vec![0u8; VBS_REPORT_SIZE];
        let report = vbs_report(&buf).unwrap();
        let s = vbs_report_pretty(&report);
        assert!(!s.is_empty());
    }
}
