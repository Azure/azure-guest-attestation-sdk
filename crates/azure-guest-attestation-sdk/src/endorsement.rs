// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TDX endorsement retrieval from Azure Trusted Hardware Identity Management (THIM).
//!
//! The THIM service at `https://{region}.thim.azure.net` provides endorsement
//! data for Intel TDX trust domains.  This module exposes a blocking HTTP
//! client (`ThimClient`) that wraps the following REST endpoints:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/endorsement/tdx/mrtds` | List known MRTD hex values |
//! | GET | `/endorsement/tdx/{mrtd}` | Fetch endorsement (COSE/CoRIM) for a specific MRTD |
//!
//! # Example
//!
//! ```no_run
//! use azure_guest_attestation_sdk::endorsement::ThimClient;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ThimClient::new("westus");
//!
//! // List all endorsed MRTDs
//! let mrtds = client.list_mrtds()?;
//! for m in &mrtds {
//!     println!("{m}");
//! }
//!
//! // Fetch endorsement for the first MRTD
//! if let Some(first) = mrtds.first() {
//!     let endorsement = client.get_endorsement(first)?;
//!     println!("endorsement: {} bytes", endorsement.data.len());
//! }
//! # Ok(())
//! # }
//! ```

use reqwest::blocking::Client;
use std::io;

/// Default Azure region for the THIM endpoint.
pub const DEFAULT_REGION: &str = "westus";

/// Response from the `/endorsement/tdx/mrtds` endpoint.
#[derive(Debug, Clone, serde::Deserialize)]
struct MrtdListResponse {
    mrtds: Vec<String>,
}

/// Result of [`ThimClient::get_endorsement`] or
/// [`ThimClient::get_endorsement_for_report`].
#[derive(Debug, Clone)]
pub struct EndorsementResponse {
    /// The MRTD (hex, uppercase) this endorsement belongs to.
    pub mrtd: String,
    /// Raw endorsement payload (COSE / CoRIM binary).
    pub data: Vec<u8>,
    /// Content-Type header returned by THIM (typically `application/cose`).
    pub content_type: String,
}

impl EndorsementResponse {
    /// Extract the JSON payload from the COSE_Sign1 envelope.
    ///
    /// Returns the parsed JSON value, or an error if the data is not a valid
    /// COSE_Sign1 structure or the payload is not valid JSON.
    pub fn payload_json(&self) -> io::Result<serde_json::Value> {
        let bytes = crate::cose::parse_cose_sign1_payload(&self.data)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::other(format!("payload is not valid JSON: {e}")))
    }
}

/// Blocking HTTP client for the Azure THIM endorsement service.
///
/// Create with [`ThimClient::new`] (uses [`DEFAULT_REGION`]) or
/// [`ThimClient::with_base_url`] for a custom endpoint.
pub struct ThimClient {
    http: Client,
    base_url: String,
}

impl ThimClient {
    /// Create a client targeting `https://{region}.thim.azure.net`.
    pub fn new(region: &str) -> Self {
        crate::ensure_crypto_provider();
        Self {
            http: Client::new(),
            base_url: format!("https://{region}.thim.azure.net"),
        }
    }

    /// Create a client with a fully custom base URL (no trailing slash).
    pub fn with_base_url(base_url: &str) -> Self {
        crate::ensure_crypto_provider();
        Self {
            http: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// List all known TDX MRTDs from THIM.
    ///
    /// Returns uppercase hex strings (96 chars = SHA-384).
    pub fn list_mrtds(&self) -> io::Result<Vec<String>> {
        let url = format!("{}/endorsement/tdx/mrtds", self.base_url);
        tracing::debug!(url = %url, "fetching MRTD list");

        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| io::Error::other(format!("THIM request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "THIM returned HTTP {status} for {url}"
            )));
        }

        let body: MrtdListResponse = resp
            .json()
            .map_err(|e| io::Error::other(format!("failed to parse MRTD list JSON: {e}")))?;

        tracing::info!(count = body.mrtds.len(), "retrieved MRTD list");
        Ok(body.mrtds)
    }

    /// Fetch endorsement data for a specific MRTD.
    ///
    /// `mrtd_hex` should be the uppercase hex representation of the SHA-384
    /// measurement (96 characters).  The returned [`EndorsementResponse`]
    /// contains the raw COSE/CoRIM binary.
    pub fn get_endorsement(&self, mrtd_hex: &str) -> io::Result<EndorsementResponse> {
        let url = format!("{}/endorsement/tdx/{}", self.base_url, mrtd_hex);
        tracing::debug!(url = %url, "fetching TDX endorsement");

        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| io::Error::other(format!("THIM request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "THIM returned HTTP {status} for MRTD {mrtd_hex}"
            )));
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let data = resp
            .bytes()
            .map_err(|e| io::Error::other(format!("failed to read endorsement body: {e}")))?
            .to_vec();

        tracing::info!(
            mrtd = %mrtd_hex,
            content_type = %content_type,
            size = data.len(),
            "retrieved TDX endorsement"
        );

        Ok(EndorsementResponse {
            mrtd: mrtd_hex.to_uppercase(),
            data,
            content_type,
        })
    }

    /// Extract the MRTD from a raw TDX report and fetch its endorsement.
    ///
    /// The `td_report_bytes` must be at least
    /// [`TDX_REPORT_SIZE`](crate::tee_report::tdx::TDX_REPORT_SIZE) bytes.
    /// The `mr_td` field (SHA-384, 48 bytes) is read from the parsed
    /// [`TdReport`](crate::tee_report::tdx::TdReport) and converted to
    /// uppercase hex for the THIM lookup.
    pub fn get_endorsement_for_report(
        &self,
        td_report_bytes: &[u8],
    ) -> io::Result<EndorsementResponse> {
        let report = crate::parse::tdx_report(td_report_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to parse TDX report: {e}"),
            )
        })?;

        let mr_td = &report.td_info.td_info_base.mr_td;
        let mrtd_hex = hex::encode_upper(mr_td);
        tracing::info!(mr_td = %mrtd_hex, "extracted MRTD from TD report");

        self.get_endorsement(&mrtd_hex)
    }
}

impl Default for ThimClient {
    fn default() -> Self {
        Self::new(DEFAULT_REGION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_westus() {
        let c = ThimClient::default();
        assert_eq!(c.base_url, "https://westus.thim.azure.net");
    }

    #[test]
    fn new_builds_url_from_region() {
        let c = ThimClient::new("eastus");
        assert_eq!(c.base_url, "https://eastus.thim.azure.net");
    }

    #[test]
    fn with_base_url_trims_trailing_slash() {
        let c = ThimClient::with_base_url("https://custom.example.com/");
        assert_eq!(c.base_url, "https://custom.example.com");
    }

    #[test]
    fn endorsement_response_clone() {
        let r = EndorsementResponse {
            mrtd: "AABB".into(),
            data: vec![1, 2, 3],
            content_type: "application/cose".into(),
        };
        let r2 = r.clone();
        assert_eq!(r2.mrtd, "AABB");
        assert_eq!(r2.data, vec![1, 2, 3]);
    }

    #[test]
    fn extract_mrtd_from_report_too_short() {
        let c = ThimClient::default();
        let result = c.get_endorsement_for_report(&[0u8; 10]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too small") || msg.contains("parse"), "{msg}");
    }

    #[test]
    fn payload_json_via_endorsement_response() {
        use crate::cose::{COSE_SIGN1_ARRAY_BYTE, COSE_SIGN1_TAG_BYTE};

        let payload_json = br#"{"hello":"ok"}"#;
        let mut buf = vec![COSE_SIGN1_TAG_BYTE, COSE_SIGN1_ARRAY_BYTE];
        // protected: bstr(3)
        buf.push(0x43);
        buf.extend_from_slice(b"abc");
        // unprotected: map(0)
        buf.push(0xa0);
        // payload: bstr(14)
        buf.push(0x4e);
        buf.extend_from_slice(payload_json);
        // signature: bstr(2)
        buf.push(0x42);
        buf.extend_from_slice(b"xx");

        let resp = EndorsementResponse {
            mrtd: "TEST".into(),
            data: buf,
            content_type: "application/cose".into(),
        };
        let json = resp.payload_json().unwrap();
        assert_eq!(json["hello"], "ok");
    }
}
