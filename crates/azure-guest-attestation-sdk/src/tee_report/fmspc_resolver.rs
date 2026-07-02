// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HTTP resolver that fetches Intel TCB info for an FMSPC.
//!
//! Wraps the Azure THIM (Trusted Hardware Identity Management) public mirror
//! of the Intel Provisioning Certification Service (PCS), so a caller holding
//! an FMSPC extracted from a TD Quote (see
//! [`ParsedTdQuote::fmspc`](crate::tee_report::td_quote::ParsedTdQuote::fmspc))
//! can look up the TCB level history and (for TDX) the TDX module identities
//! that apply to that platform.
//!
//! # Endpoints
//!
//! - SGX: `{base}/sgx/certification/v4/tcb?fmspc=<hex>`
//! - TDX: `{base}/tdx/certification/v4/tcb?fmspc=<hex>`
//!
//! The default base URL is the globally reachable Azure THIM mirror at
//! `https://global.acccache.azure.net` (does not require running inside an
//! Azure VM). Use [`FmspcResolver::with_base_url`] to point at Intel PCS
//! directly, the IMDS-local THIM endpoint, or a private PCCS.
//!
//! # Limitations
//!
//! Neither Intel PCS nor THIM exposes a field that maps an FMSPC to a CPU
//! marketing generation (e.g. `SPR`, `EMR`, `GNR`). The public Intel PCS
//! `/sgx/certification/v4/fmspcs` catalogue only classifies FMSPCs into the
//! coarse buckets `client`, `E3` and `E5`. Distinguishing silicon generations
//! requires a caller-maintained lookup table keyed on FMSPC or decoding the
//! CPUID Family/Model/Stepping bytes embedded in the first four bytes of the
//! FMSPC value.

use crate::tee_report::td_quote::FMSPC_LEN;
use reqwest::blocking::Client;
use std::io;

/// Default base URL: the globally reachable Azure THIM mirror.
pub const AZURE_THIM_GLOBAL_BASE_URL: &str = "https://global.acccache.azure.net";

/// Intel PCS v4 base URL. Useful as a fallback when THIM is unavailable.
pub const INTEL_PCS_V4_BASE_URL: &str = "https://api.trustedservices.intel.com";

/// Selects the TEE namespace for an FMSPC lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeeKind {
    /// `/sgx/certification/v4/tcb` — SGX TCB info.
    Sgx,
    /// `/tdx/certification/v4/tcb` — TDX TCB info; response includes
    /// `tdxModule` / `tdxModuleIdentities` blocks.
    Tdx,
}

impl TeeKind {
    fn path_segment(self) -> &'static str {
        match self {
            TeeKind::Sgx => "sgx",
            TeeKind::Tdx => "tdx",
        }
    }
}

/// TCB info document returned by `/{tee}/certification/v4/tcb`.
///
/// The `tcb_info` body is held as a [`serde_json::Value`] rather than a typed
/// struct because Intel adds fields between TCB info versions; callers that
/// want strongly-typed access should deserialise the embedded block
/// themselves.
#[derive(Debug, Clone)]
pub struct TcbInfoResponse {
    /// FMSPC echoed back by the service, uppercase hex.
    pub fmspc: String,
    /// Decoded `tcbInfo` JSON object.
    pub tcb_info: serde_json::Value,
    /// Signature over `tcbInfo` produced by the Intel TCB signing key
    /// (hex-encoded, ECDSA P-256 over SHA-256).
    pub signature: String,
    /// Issuer certificate chain from the `TCB-Info-Issuer-Chain` (or
    /// `SGX-TCB-Info-Issuer-Chain`) response header, percent-decoded into
    /// concatenated PEM bytes.
    pub issuer_chain: Option<Vec<u8>>,
}

/// HTTP client that resolves an FMSPC to TCB info via THIM or Intel PCS.
pub struct FmspcResolver {
    http: Client,
    base_url: String,
}

impl FmspcResolver {
    /// Construct a resolver pointed at the public Azure THIM mirror.
    pub fn new() -> Self {
        Self::with_base_url(AZURE_THIM_GLOBAL_BASE_URL)
    }

    /// Construct a resolver pointed at a custom base URL.
    ///
    /// `base_url` is the scheme + host (e.g. `https://api.trustedservices.intel.com`).
    /// Paths of the form `/{tee}/certification/v4/tcb?fmspc=<hex>` are appended.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Fetch TCB info for an FMSPC under the chosen TEE namespace.
    pub fn tcb_info(&self, tee: TeeKind, fmspc: [u8; FMSPC_LEN]) -> io::Result<TcbInfoResponse> {
        let hex_fmspc = hex_encode_upper(&fmspc);
        let base = self.base_url.trim_end_matches('/');
        let url = format!(
            "{base}/{tee_path}/certification/v4/tcb?fmspc={hex_fmspc}",
            tee_path = tee.path_segment(),
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| io::Error::other(format!("TCB info request failed ({url}): {e}")))?;
        let status = resp.status();
        let issuer_chain = resp
            .headers()
            .get("TCB-Info-Issuer-Chain")
            .or_else(|| resp.headers().get("SGX-TCB-Info-Issuer-Chain"))
            .and_then(|v| v.to_str().ok())
            .map(percent_decode);
        let body = resp
            .text()
            .map_err(|e| io::Error::other(format!("TCB info read failed: {e}")))?;
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "TCB info returned status {status}: {body}"
            )));
        }
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| io::Error::other(format!("TCB info body is not JSON: {e}: {body}")))?;
        let tcb_info = parsed
            .get("tcbInfo")
            .cloned()
            .ok_or_else(|| io::Error::other("TCB info response missing `tcbInfo`"))?;
        let signature = parsed
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let fmspc_echo = tcb_info
            .get("fmspc")
            .and_then(|v| v.as_str())
            .unwrap_or(&hex_fmspc)
            .to_string();
        Ok(TcbInfoResponse {
            fmspc: fmspc_echo,
            tcb_info,
            signature,
            issuer_chain,
        })
    }

    /// Convenience wrapper for SGX TCB info.
    pub fn sgx_tcb_info(&self, fmspc: [u8; FMSPC_LEN]) -> io::Result<TcbInfoResponse> {
        self.tcb_info(TeeKind::Sgx, fmspc)
    }

    /// Convenience wrapper for TDX TCB info (includes TDX module identities).
    pub fn tdx_tcb_info(&self, fmspc: [u8; FMSPC_LEN]) -> io::Result<TcbInfoResponse> {
        self.tcb_info(TeeKind::Tdx, fmspc)
    }
}

impl Default for FmspcResolver {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_upper_uses_uppercase() {
        assert_eq!(
            hex_encode_upper(&[0x00, 0x80, 0x6F, 0x05, 0x00, 0x00]),
            "00806F050000"
        );
    }

    #[test]
    fn percent_decode_handles_pem_header() {
        let encoded = "-----BEGIN%20CERTIFICATE-----%0AAAAA%0A-----END%20CERTIFICATE-----%0A";
        let decoded = percent_decode(encoded);
        assert_eq!(
            std::str::from_utf8(&decoded).unwrap(),
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn percent_decode_passes_unencoded_bytes_through() {
        assert_eq!(percent_decode("abc-123"), b"abc-123");
    }

    #[test]
    fn percent_decode_handles_lowercase_hex() {
        assert_eq!(percent_decode("%2f%2b"), b"/+");
    }

    #[test]
    fn percent_decode_leaves_malformed_escape_alone() {
        assert_eq!(percent_decode("%ZZ"), b"%ZZ");
    }

    #[test]
    fn tee_kind_path_segments() {
        assert_eq!(TeeKind::Sgx.path_segment(), "sgx");
        assert_eq!(TeeKind::Tdx.path_segment(), "tdx");
    }

    /// Live network test against the Azure THIM mirror. Ignored by default so
    /// CI does not depend on external connectivity; run with
    /// `cargo test -p azure-guest-attestation-sdk -- --ignored thim_live`.
    #[test]
    #[ignore = "live network call to Azure THIM"]
    fn thim_live_tdx_lookup() {
        let resolver = FmspcResolver::new();
        let fmspc = [0x00, 0x80, 0x6F, 0x05, 0x00, 0x00];
        let resp = resolver.tdx_tcb_info(fmspc).expect("tdx tcb info");
        assert_eq!(resp.fmspc.to_ascii_uppercase(), "00806F050000");
        assert_eq!(
            resp.tcb_info.get("id").and_then(|v| v.as_str()),
            Some("TDX")
        );
        assert!(resp.tcb_info.get("tdxModuleIdentities").is_some());
        let chain = resp.issuer_chain.expect("issuer chain header");
        assert!(chain
            .windows(27)
            .any(|w| w == b"-----BEGIN CERTIFICATE-----"));
    }
}
