// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest attestation types, provider abstractions, and submission helpers.
//!
//! This module provides the building blocks for guest attestation on Azure VMs
//! (both CVM and TrustedLaunch):
//!
//! - **Types**: `GuestAttestationParameters`, `TpmInfo`, `IsolationInfo`, etc.
//! - **Providers**: `AttestationProvider` trait, `MaaProvider`, `LoopbackProvider`
//! - **Submission**: `submit_to_provider()` (with retry), `submit_tee_only()`
//! - **Payload builders**: `build_tee_only_payload_from_evidence()`
//! - **Convenience**: `attest_guest()` — one-shot orchestration (auto-detects
//!   TrustedLaunch vs CVM)
//! - **Utilities**: `collect_tcg_logs()`, `base64_url_encode/decode()`
//!
//! Most callers should use [`crate::client::AttestationClient`] which composes
//! these primitives into a clean layered API.

use crate::tpm::attestation::{
    get_ak_cert, get_ak_pub, get_ephemeral_key, get_pcr_quote, get_pcr_values,
};
use crate::tpm::device::Tpm;
use base64::Engine; // for encode/decode methods
use reqwest::blocking::Client;
use serde::ser::SerializeMap;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::time::Duration;
use std::time::Instant;
use std::{io, thread};

#[derive(Debug)]
pub(crate) struct StageTimer {
    start: Instant,
    last: Instant,
}
impl StageTimer {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last: now,
        }
    }
    pub(crate) fn mark(&mut self, label: &str) {
        let now = Instant::now();
        let stage_ms = (now - self.last).as_millis();
        let total_ms = (now - self.start).as_millis();
        self.last = now;
        tracing::info!(target: "guest_attest", stage = label, stage_ms, total_ms, "attestation timing");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_type: String,
    pub distro: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub build: String,
    pub pcr_list: Vec<u32>,
}

impl OsInfo {
    pub fn detect() -> io::Result<Self> {
        let os = std::env::consts::OS;
        match os {
            "windows" => Ok(Self {
                os_type: "Windows".into(),
                distro: "Windows".into(),
                version_major: 10,
                version_minor: 0,
                build: "NotApplication".into(),
                pcr_list: vec![0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14],
            }),
            "linux" => {
                // Parse /etc/os-release best effort.
                let mut name = String::new();
                let mut version = String::new();
                if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
                    for line in text.lines() {
                        if let Some(rest) = line.strip_prefix("NAME=") {
                            name = rest.trim_matches('"').to_string();
                        }
                        if let Some(rest) = line.strip_prefix("VERSION_ID=") {
                            version = rest.trim_matches('"').to_string();
                        }
                    }
                }
                let (maj, min) = parse_version_pair(&version);
                Ok(Self {
                    os_type: "Linux".into(),
                    distro: name,
                    version_major: maj,
                    version_minor: min,
                    build: "NotApplication".into(),
                    pcr_list: vec![0, 1, 2, 3, 4, 5, 6, 7],
                })
            }
            _ => Err(io::Error::other("unsupported OS")),
        }
    }
}

fn parse_version_pair(v: &str) -> (u32, u32) {
    let mut maj = 0;
    let mut min = 0;
    let parts: Vec<&str> = v.split('.').collect();
    if let Some(p) = parts.first() {
        maj = p.parse().unwrap_or(0);
    }
    if let Some(p) = parts.get(1) {
        min = p.parse().unwrap_or(0);
    }
    (maj, min)
}

#[derive(Debug, Clone, Serialize)]
pub enum IsolationType {
    SevSnp,
    Tdx,
    TrustedLaunch,
}

#[derive(Debug, Clone, Serialize)]
pub struct IsolationInfo {
    #[serde(rename = "Type")]
    pub vm_type: IsolationType,
    #[serde(rename = "Evidence", skip_serializing_if = "Option::is_none")]
    pub evidence: Option<IsolationEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IsolationEvidence {
    #[serde(rename = "Proof")]
    pub tee_proof: TeeProof,
    #[serde(rename = "RunTimeData", serialize_with = "as_b64")]
    pub runtime_data: Vec<u8>,
}

// Tee proof types (subset for SNP + TDX)
#[derive(Debug, Clone)]
pub enum TeeProof {
    Snp {
        snp_report: Vec<u8>,
        vcek_chain: Vec<u8>,
    },
    Tdx {
        td_quote: Vec<u8>,
    },
}

impl Serialize for TeeProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TeeProof::Snp {
                snp_report,
                vcek_chain,
            } => {
                let mut state = serializer.serialize_struct("Snp", 2)?;
                let snp_report_b64 = base64::engine::general_purpose::STANDARD.encode(snp_report);
                state.serialize_field("SnpReport", &snp_report_b64)?;
                let vcek_chain_b64 = base64::engine::general_purpose::STANDARD.encode(vcek_chain);
                state.serialize_field("VcekCertChain", &vcek_chain_b64)?;
                state.end()
            }
            TeeProof::Tdx { td_quote } => {
                // Just serialize as raw byte array
                let td_quote_b64 = base64::engine::general_purpose::STANDARD.encode(td_quote);
                td_quote_b64.serialize(serializer)
            }
        }
    }
}

// Helper base64 (standard) serializer for binary fields.
fn as_b64<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = base64::engine::general_purpose::STANDARD.encode(data);
    serializer.serialize_str(&s)
}

// Helper base64 (standard) serializer for String fields.
fn str_as_b64<S>(str: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = base64::engine::general_purpose::STANDARD.encode(str.as_bytes());
    serializer.serialize_str(&s)
}

/// Client payload stored as raw JSON string (object). At serialization we parse and base64 encode each value.
fn client_payload_b64<S>(raw: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Empty or whitespace -> empty object
    if raw.trim().is_empty() {
        let map = serializer.serialize_map(Some(0))?;
        return map.end();
    }
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(val) => val,
        Err(_) => serde_json::Value::Object(serde_json::Map::new()),
    };
    if !v.is_object() {
        let map = serializer.serialize_map(Some(0))?;
        return map.end();
    }
    let obj = v.as_object().unwrap();
    let mut m = serializer.serialize_map(Some(obj.len()))?;
    for (k, v) in obj.iter() {
        // Convert any JSON value to string then base64 encode bytes of that string (consistent approach)
        let val_str = if v.is_string() {
            v.as_str().unwrap().to_string()
        } else {
            v.to_string()
        };
        let enc = base64::engine::general_purpose::STANDARD.encode(val_str.as_bytes());
        m.serialize_entry(k, &enc)?;
    }
    m.end()
}

#[derive(Debug, Clone, Serialize)]
pub struct PcrEntry {
    #[serde(rename = "Index")]
    pub index: u32,
    #[serde(rename = "Digest", serialize_with = "as_b64")]
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TpmInfo {
    #[serde(rename = "AikCert", serialize_with = "as_b64")]
    pub ak_cert: Vec<u8>,
    #[serde(rename = "AikPub", serialize_with = "as_b64")]
    pub ak_pub: Vec<u8>,
    #[serde(rename = "PcrQuote", serialize_with = "as_b64")]
    pub pcr_quote: Vec<u8>,
    #[serde(rename = "PcrSignature", serialize_with = "as_b64")]
    pub pcr_sig: Vec<u8>,
    // Set of PCR indices included in quote
    #[serde(rename = "PcrSet")]
    pub pcr_set: Vec<u32>,
    // Structured list of PCR index + digest pairs
    #[serde(rename = "PCRs")]
    pub pcrs: Vec<PcrEntry>,
    #[serde(rename = "EncKeyPub", serialize_with = "as_b64")]
    pub enc_key_pub: Vec<u8>,
    #[serde(rename = "EncKeyCertifyInfo", serialize_with = "as_b64")]
    pub enc_key_certify_info: Vec<u8>,
    #[serde(rename = "EncKeyCertifyInfoSignature", serialize_with = "as_b64")]
    pub enc_key_certify_info_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuestAttestationParameters {
    #[serde(rename = "AttestationProtocolVersion")]
    pub protocol_version: String,
    #[serde(rename = "OSType", serialize_with = "str_as_b64")]
    pub os_type: String,
    #[serde(rename = "OSDistro", serialize_with = "str_as_b64")]
    pub os_distro: String,
    #[serde(rename = "OSVersionMajor")]
    pub os_version_major: u32,
    #[serde(rename = "OSVersionMinor")]
    pub os_version_minor: u32,
    #[serde(rename = "OSBuild", serialize_with = "str_as_b64")]
    pub os_build: String,
    #[serde(rename = "TcgLogs", serialize_with = "as_b64")]
    pub tcg_logs: Vec<u8>,
    #[serde(rename = "ClientPayload", serialize_with = "client_payload_b64")]
    pub client_payload: String,
    #[serde(rename = "TpmInfo")]
    pub tpm_info: TpmInfo,
    #[serde(rename = "IsolationInfo")]
    pub isolation: IsolationInfo,
}

impl GuestAttestationParameters {
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Attestation provider abstraction (placeholder)
pub trait AttestationProvider {
    fn attest_guest(&self, encoded_request: &str) -> io::Result<Option<String>>; // returns base64url encoded token
}

/// Dummy provider that echoes back the request embedded in a JSON token.
pub struct LoopbackProvider;
impl AttestationProvider for LoopbackProvider {
    fn attest_guest(&self, encoded_request: &str) -> io::Result<Option<String>> {
        let token = serde_json::json!({"loopback": true, "request": encoded_request});
        Ok(Some(base64_url_encode(token.to_string().as_bytes())))
    }
}

/// Microsoft Azure Attestation (MAA) provider implementation.
/// Posts the base64url encoded request as JSON to a supplied endpoint and expects
/// a JWT token string (MAA) in response under field "token" OR raw body if JSON parse fails.
pub struct MaaProvider {
    client: Client,
    endpoint: String,
}

impl MaaProvider {
    pub fn new(endpoint: impl Into<String>) -> Self {
        // Build a blocking client with extended timeout (5 minutes) to accommodate
        // potentially slow MAA attestation responses.
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(target: "guest_attest", error=%e, "MAA Client builder failed, falling back to default client");
                Client::new()
            });
        Self {
            client,
            endpoint: endpoint.into(),
        }
    }
}

impl AttestationProvider for MaaProvider {
    fn attest_guest(&self, encoded_request: &str) -> io::Result<Option<String>> {
        let body = serde_json::json!({"AttestationInfo": encoded_request});
        // Build the request first so we can log headers before sending.
        let req = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .build()
            .map_err(|e| io::Error::other(format!("maa build request: {e}")))?;
        // Trace request headers (redact Authorization if ever present).
        for (k, v) in req.headers().iter() {
            if k.as_str().eq_ignore_ascii_case("authorization") {
                tracing::info!(target = "guest_attest", provider = "MAA", endpoint = %self.endpoint, header = %k.as_str(), value = "<redacted>");
            } else {
                let val = v.to_str().unwrap_or("<non-utf8>");
                tracing::info!(target = "guest_attest", provider = "MAA", endpoint = %self.endpoint, header = %k.as_str(), value = %val);
            }
        }
        let resp = self
            .client
            .execute(req)
            .map_err(|e| io::Error::other(format!("maa http error: {e}")))?;
        let status = resp.status();
        // Trace response headers before consuming body (redact sensitive values)
        for (k, v) in resp.headers().iter() {
            let name = k.as_str();
            if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("set-cookie")
            {
                tracing::info!(target = "guest_attest", provider = "MAA", endpoint = %self.endpoint, response_header = %name, value = "<redacted>");
            } else {
                let val = v.to_str().unwrap_or("<non-utf8>");
                tracing::info!(target = "guest_attest", provider = "MAA", endpoint = %self.endpoint, response_header = %name, value = %val);
            }
        }
        let text = resp
            .text()
            .map_err(|e| io::Error::other(format!("maa read body: {e}")))?;
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "MAA status {status} body: {text}"
            )));
        }

        // Try to parse JSON {"token":"..."}
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(tok) = v.get("token").and_then(|t| t.as_str()) {
                return Ok(Some(tok.to_string()));
            }
        }
        // Fallback: assume body is already a token.
        Ok(Some(text))
    }
}

/// Subset IMDS client (SNP VCEK chain + TDX quote). Network errors -> io::Error.
pub struct ImdsClient {
    http: Client,
}
impl ImdsClient {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
        }
    }
    fn get_json(&self, url: &str) -> io::Result<serde_json::Value> {
        let resp = self
            .http
            .get(url)
            .header("Metadata", "true")
            .send()
            .map_err(|e| io::Error::other(format!("http error: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(io::Error::other(format!("status {status}")));
        }
        let v = resp
            .json::<serde_json::Value>()
            .map_err(|e| io::Error::other(format!("json error: {e}")))?;
        Ok(v)
    }
    pub fn get_vcek_chain(&self) -> io::Result<Vec<u8>> {
        const THIM_ENDPOINT: &str = "http://169.254.169.254/metadata/THIM/amd/certification";
        let v = self.get_json(THIM_ENDPOINT)?;
        let vcek = v.get("vcekCert").and_then(|x| x.as_str()).unwrap_or("");
        let chain = v
            .get("certificateChain")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        Ok(format!("{vcek}{chain}").into_bytes())
    }
    pub fn get_td_quote(&self, report: &[u8]) -> io::Result<Vec<u8>> {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        const TDQUOTE_ENDPOINT: &str = "http://169.254.169.254/acc/tdquote";
        // Trim to canonical TDX report size expected by IMDS
        let needed = crate::report::TDX_VM_REPORT_SIZE;
        if report.len() < needed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tdx report buffer too small: have {} need {}",
                    report.len(),
                    needed
                ),
            ));
        }
        let rep = &report[..needed];

        // First attempt: standard base64 with padding
        let std_b64 = STANDARD.encode(rep);
        let body_std = serde_json::json!({"report": std_b64});
        let resp_std = self
            .http
            .post(TDQUOTE_ENDPOINT)
            .header("Metadata", "true")
            .json(&body_std)
            .send()
            .map_err(|e| io::Error::other(format!("tdquote http (std b64) error: {e}")))?;
        let status_std = resp_std.status();
        let text_std = resp_std.text().unwrap_or_default();
        if status_std.is_success() {
            // Parse JSON and decode quote
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text_std) {
                if let Some(quote_enc) = v.get("quote").and_then(|x| x.as_str()) {
                    // Decode quote (standard first then URL safe fallback)
                    if let Ok(bytes) = STANDARD.decode(quote_enc.as_bytes()) {
                        return Ok(bytes);
                    }
                    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(quote_enc.as_bytes()) {
                        return Ok(bytes);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unable to base64 decode returned quote",
                    ));
                }
            }
            return Err(io::Error::other(format!(
                "tdquote success status but missing/invalid JSON: {text_std}"
            )));
        }

        // Fallback attempt: URL safe no pad (some older docs/examples)
        let url_b64 = URL_SAFE_NO_PAD.encode(rep);
        let body_url = serde_json::json!({"report": url_b64});
        let resp_url = self
            .http
            .post(TDQUOTE_ENDPOINT)
            .header("Metadata", "true")
            .json(&body_url)
            .send()
            .map_err(|e| io::Error::other(format!("tdquote http (url b64) error: {e}")))?;
        let status_url = resp_url.status();
        let text_url = resp_url.text().unwrap_or_default();
        if status_url.is_success() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text_url) {
                if let Some(quote_enc) = v.get("quote").and_then(|x| x.as_str()) {
                    if let Ok(bytes) = STANDARD.decode(quote_enc.as_bytes()) {
                        return Ok(bytes);
                    }
                    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(quote_enc.as_bytes()) {
                        return Ok(bytes);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unable to base64 decode returned quote (fallback)",
                    ));
                }
            }
            return Err(io::Error::other(format!(
                "tdquote fallback success status but missing/invalid JSON: {text_url}"
            )));
        }

        Err(io::Error::other(format!("tdquote failed (std status {status_std}, fallback status {status_url}) std_body='{text_std}' fallback_body='{text_url}'")))
    }
}

impl Default for ImdsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Base64url (no padding) encode.
pub fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64url (no padding) decode.
pub fn base64_url_decode(s: &str) -> io::Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("b64 decode: {e}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestCvmResult {
    pub request_json: String,
    pub encoded_request_b64url: String,
    pub token_b64url: Option<String>,
    pub ephemeral_key_handle: Option<u32>,
    pub pcrs: Vec<u32>,
}

/// Lightweight TEE-only evidence structure (no TPM / PCR data) for platform attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeOnlyRequest {
    /// Either 'quote' (TDX) or 'report' (SNP)
    pub evidence_field: String,
    /// Base64 (standard) encoded evidence body (TD quote or JSON-wrapped SNP report+VCEK)
    pub evidence_b64: String,
    /// Base64 (standard) encoded runtime data (currently empty or future use)
    pub runtime_b64: String,
    /// Original report type
    pub report_type: String,
}

/// Build a TEE-only JSON payload from pre-collected [`CvmEvidence`](crate::client::CvmEvidence)
/// and an optional endorsement.
///
/// Returns `(payload_json_string, report_type)`. The caller is responsible for
/// submitting this payload to the appropriate MAA platform endpoint.
pub fn build_tee_only_payload_from_evidence(
    evidence: &crate::client::CvmEvidence,
    endorsement: Option<&crate::client::Endorsement>,
) -> io::Result<(String, crate::report::CvmReportType)> {
    use base64::engine::general_purpose::STANDARD;
    let rtype = evidence.report_type;
    let runtime_data = Vec::new(); // placeholder for future runtime claims extraction
    let (evidence_field, evidence_bytes) = match rtype {
        crate::report::CvmReportType::SnpVmReport => {
            let vcek_chain = match endorsement {
                Some(e) if e.kind == crate::client::EndorsementKind::Vcek => e.data.clone(),
                _ => {
                    let imds = ImdsClient::new();
                    imds.get_vcek_chain()?
                }
            };
            let snp_report_json = serde_json::json!({
                "SnpReport": STANDARD.encode(&evidence.tee_report),
                "VcekCertChain": STANDARD.encode(&vcek_chain)
            });
            let snp_bytes = serde_json::to_vec(&snp_report_json).unwrap_or_default();
            ("report".to_string(), snp_bytes)
        }
        crate::report::CvmReportType::TdxVmReport => {
            let td_quote = if !evidence.platform_quote.is_empty() {
                evidence.platform_quote.clone()
            } else {
                let imds = ImdsClient::new();
                imds.get_td_quote(&evidence.tee_report)?
            };
            ("quote".to_string(), td_quote)
        }
        _ => {
            return Err(io::Error::other(format!(
                "Unsupported report type for tee-only attestation: {rtype:?}"
            )))
        }
    };
    let payload = serde_json::json!({
        evidence_field: STANDARD.encode(evidence_bytes),
        "runtimeData": {"data": STANDARD.encode(&runtime_data), "dataType": "JSON"}
    });
    Ok((payload.to_string(), rtype))
}

/// Submit a TEE-only JSON payload to a MAA platform endpoint.
///
/// Returns `(token_string, request_json)`. If the response body is not JSON
/// with a `"token"` field the raw body is returned as the token string.
pub fn submit_tee_only(
    payload: &str,
    endpoint: &str,
    report_type: crate::report::CvmReportType,
) -> io::Result<String> {
    let mut timer = StageTimer::new();
    // Best-effort endpoint / type sanity warnings
    if report_type == crate::report::CvmReportType::SnpVmReport && !endpoint.contains("SevSnpVm") {
        tracing::warn!(target: "guest_attest", endpoint, "SNP evidence but endpoint name lacks 'SevSnpVm'");
    }
    if report_type == crate::report::CvmReportType::TdxVmReport && !endpoint.contains("TdxVm") {
        tracing::warn!(target: "guest_attest", endpoint, "TDX evidence but endpoint name lacks 'TdxVm'");
    }
    let client = reqwest::blocking::Client::new();
    tracing::info!(target: "guest_attest", endpoint, "POST tee-only attestation request");
    let resp = client
        .post(endpoint)
        .json(
            &serde_json::from_str::<serde_json::Value>(payload)
                .unwrap_or_else(|_| serde_json::json!({})),
        )
        .send()
        .map_err(|e| io::Error::other(format!("http error: {e}")))?;
    timer.mark("http_post");
    let status = resp.status();
    tracing::info!(target: "guest_attest", %status, "tee-only response status");
    let text = resp.text().unwrap_or_default();
    timer.mark("read_body");
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "MAA status {status} body: {text}"
        )));
    }
    tracing::info!(target: "guest_attest", body_len = text.len(), "tee-only response body received");
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(tok) = v.get("token").and_then(|x| x.as_str()) {
            tracing::info!(target: "guest_attest", token_len = tok.len(), "tee-only token extracted");
            return Ok(tok.to_string());
        }
    }
    tracing::info!(target: "guest_attest", "tee-only raw body treated as token");
    Ok(text)
}

/// Perform a TEE-only attestation against a MAA platform endpoint.
///
/// **Convenience wrapper** that collects evidence from the TPM, builds the
/// payload, and submits it. Prefer using the decomposed helpers
/// ([`build_tee_only_payload_from_evidence`] + [`submit_tee_only`]) when you
/// already have pre-collected evidence.
///
/// Returns `(token_string, request_json)`.
pub fn tee_only_attest_platform(
    tpm: &Tpm,
    endpoint: &str,
    force_override: Option<crate::report::CvmReportType>,
) -> io::Result<(String, String)> {
    let mut timer = StageTimer::new();
    tracing::info!(target: "guest_attest", endpoint, "tee-only attestation start");
    let (payload, detected_type) = build_tee_only_payload(tpm)?;
    timer.mark("build_payload");
    let eff_type = force_override.unwrap_or(detected_type);
    tracing::info!(target: "guest_attest", detected = ?detected_type, effective = ?eff_type, payload_len = payload.len(), "tee-only payload built");
    let token = submit_tee_only(&payload, endpoint, eff_type)?;
    Ok((token, payload))
}

/// Gather raw TEE evidence from the TPM. Returns serialized JSON payload
/// expected by MAA platform endpoints and the underlying report type.
///
/// **Note:** prefer [`build_tee_only_payload_from_evidence`] which works from
/// pre-collected [`CvmEvidence`](crate::client::CvmEvidence) and avoids
/// duplicating evidence collection.
pub fn build_tee_only_payload(tpm: &Tpm) -> io::Result<(String, crate::report::CvmReportType)> {
    use base64::engine::general_purpose::STANDARD;
    let raw = crate::tpm::attestation::get_cvm_report_raw(tpm, None)?;
    let (parsed, _claims) = crate::report::CvmAttestationReport::parse_with_runtime_claims(&raw)?;
    let rtype = parsed.runtime_claims_header.report_type;
    let runtime_data = Vec::new();
    let (evidence_field, evidence_bytes) = match rtype {
        crate::report::CvmReportType::SnpVmReport => {
            let snp_slice = &parsed.tee_report[..crate::report::SNP_VM_REPORT_SIZE];
            let imds = ImdsClient::new();
            let vcek_chain = imds.get_vcek_chain()?;
            let snp_report_json = serde_json::json!({
                "SnpReport": STANDARD.encode(snp_slice),
                "VcekCertChain": STANDARD.encode(&vcek_chain)
            });
            let snp_bytes = serde_json::to_vec(&snp_report_json).unwrap_or_default();
            ("report".to_string(), snp_bytes)
        }
        crate::report::CvmReportType::TdxVmReport => {
            let tdx_slice = &parsed.tee_report[..crate::report::TDX_VM_REPORT_SIZE];
            let imds = ImdsClient::new();
            let td_quote = imds.get_td_quote(tdx_slice)?;
            ("quote".to_string(), td_quote)
        }
        _ => {
            return Err(io::Error::other(format!(
                "Unsupported report type for tee-only attestation: {rtype:?}"
            )))
        }
    };
    let payload = serde_json::json!({
        evidence_field: STANDARD.encode(evidence_bytes),
        "runtimeData": {"data": STANDARD.encode(&runtime_data), "dataType": "JSON"}
    });
    Ok((payload.to_string(), rtype))
}

/// Submit a base64url-encoded guest attestation request to a provider with
/// exponential-backoff retry (up to 3 attempts).
///
/// Returns the raw base64url-encoded token string (if any) on success.
pub fn submit_to_provider(
    encoded_request: &str,
    provider: &dyn AttestationProvider,
) -> io::Result<Option<String>> {
    let max_retries = 3;
    let mut attempt = 0;
    let mut last_err: Option<io::Error> = None;
    let token = loop {
        match provider.attest_guest(encoded_request) {
            Ok(t) => break t,
            Err(e) => {
                tracing::warn!(target: "guest_attest", attempt = attempt + 1, error = %e, "Provider attest_guest failed; will retry if below max");
                attempt += 1;
                if attempt >= max_retries {
                    last_err = Some(e);
                    break None;
                }
                let delay = 1u64 << (attempt - 1);
                tracing::info!(target: "guest_attest", attempt, delay_secs = delay, "Retrying provider after backoff");
                thread::sleep(Duration::from_secs(delay));
            }
        }
    };
    if token.is_none() {
        if let Some(e) = last_err {
            return Err(e);
        }
    }
    Ok(token)
}

/// High-level guest attestation orchestration.
///
/// Collects *all* evidence (TPM artifacts, TCG logs, and — when available —
/// CVM isolation evidence) and submits the request.
///
/// **TrustedLaunch** VMs are automatically detected: when the TPM's CVM
/// report NV index is absent the function falls back to
/// [`IsolationType::TrustedLaunch`] with no TEE evidence.
///
/// For more control, prefer using [`crate::client::AttestationClient`] which
/// decomposes evidence collection, report building, and submission into
/// separate steps.
pub fn attest_guest(
    tpm: &Tpm,
    provider: Option<&dyn AttestationProvider>,
    client_payload: Option<&str>,
) -> io::Result<AttestCvmResult> {
    tracing::info!(target: "guest_attest", "attest-guest start");
    let mut timer = StageTimer::new();
    let os = OsInfo::detect()?;
    tracing::info!(target: "guest_attest", os_type = %os.os_type, distro = %os.distro, maj = os.version_major, min = os.version_minor, "os info detected");
    timer.mark("os_detect");

    // Collect TCG logs (best-effort) similar to Python get_measurements
    let tcg_logs: Vec<u8> = collect_tcg_logs(&os);

    // Collect TPM artifacts
    let ak_cert = get_ak_cert(tpm)?;
    tracing::info!(target: "guest_attest", ak_cert_len = ak_cert.len(), "AK cert fetched");
    let ak_pub = get_ak_pub(tpm)?;
    tracing::info!(target: "guest_attest", ak_pub_len = ak_pub.len(), "AK public fetched");
    let pcrs = os.pcr_list.clone();
    tracing::info!(target: "guest_attest", pcr_count = pcrs.len(), pcrs = ?pcrs, "PCR list prepared");
    let (quote, sig) = get_pcr_quote(tpm, &pcrs)?;
    tracing::info!(target: "guest_attest", quote_len = quote.len(), sig_len = sig.len(), "PCR quote acquired");
    tracing::debug!(target: "guest_attest", quote_hex = %hex::encode(&quote), "PCR quote raw hex");
    let pcr_values = get_pcr_values(tpm, &pcrs)?;
    tracing::info!(target: "guest_attest", pcr_values = pcr_values.len(), "PCR values read");
    let (enc_key_pub, handle_bytes, enc_key_certify_info, enc_key_certify_info_sig) =
        get_ephemeral_key(tpm, &pcrs)?;
    let eph_handle = if handle_bytes.len() >= 4 {
        Some(u32::from_be_bytes([
            handle_bytes[0],
            handle_bytes[1],
            handle_bytes[2],
            handle_bytes[3],
        ]))
    } else {
        None
    };
    tracing::info!(target: "guest_attest", enc_key_pub_len = enc_key_pub.len(), certify_info_len = enc_key_certify_info.len(), certify_sig_len = enc_key_certify_info_sig.len(), "Ephemeral key created and certified");
    timer.mark("tpm_artifacts");
    let pcr_set: Vec<u32> = pcr_values.iter().map(|(i, _)| *i).collect();
    let pcrs_struct: Vec<PcrEntry> = pcr_values
        .iter()
        .map(|(i, d)| PcrEntry {
            index: *i,
            digest: d.clone(),
        })
        .collect();

    // Hardware evidence — try reading the CVM report.
    // TrustedLaunch VMs don't have a CVM report NV index; we fall back to
    // IsolationType::TrustedLaunch with no TEE evidence in that case.
    let isolation = match crate::tpm::attestation::get_cvm_report_raw(tpm, None) {
        Ok(raw_report) => {
            tracing::info!(target: "guest_attest", report_len = raw_report.len(), "CVM report fetched");
            let (parsed, _claims) =
                crate::report::CvmAttestationReport::parse_with_runtime_claims(&raw_report)?;
            tracing::info!(target: "guest_attest", report_type = ?parsed.runtime_claims_header.report_type, tee_report_len = parsed.tee_report.len(), "CVM report parsed");
            timer.mark("cvm_report");
            let runtime_data = parsed.get_runtime_claims_raw_bytes(&raw_report)?;
            let report_type = parsed.runtime_claims_header.report_type;
            match report_type {
                crate::report::CvmReportType::SnpVmReport => {
                    let snp_slice = &parsed.tee_report[..crate::report::SNP_VM_REPORT_SIZE];
                    let imds = ImdsClient::new();
                    let vcek_chain = imds.get_vcek_chain()?;
                    tracing::info!(target: "guest_attest", snp_report_len = snp_slice.len(), vcek_chain_len = vcek_chain.len(), "SNP evidence collected (report + VCEK chain)");

                    IsolationInfo {
                        vm_type: IsolationType::SevSnp,
                        evidence: Some(IsolationEvidence {
                            tee_proof: TeeProof::Snp {
                                snp_report: snp_slice.to_vec(),
                                vcek_chain,
                            },
                            runtime_data,
                        }),
                    }
                }
                crate::report::CvmReportType::TdxVmReport => {
                    let tdx_slice = &parsed.tee_report[..crate::report::TDX_VM_REPORT_SIZE];
                    let imds = ImdsClient::new();
                    let td_quote = imds.get_td_quote(tdx_slice)?;
                    tracing::info!(target: "guest_attest", tdx_report_len = tdx_slice.len(), td_quote_len = td_quote.len(), "TDX evidence collected (report + quote)");

                    IsolationInfo {
                        vm_type: IsolationType::Tdx,
                        evidence: Some(IsolationEvidence {
                            tee_proof: TeeProof::Tdx { td_quote },
                            runtime_data,
                        }),
                    }
                }
                rtype => {
                    return Err(io::Error::other(format!(
                        "Unsupported CVM report type: {rtype:?}"
                    )));
                }
            }
        }
        Err(e) => {
            // No CVM report NV index → TrustedLaunch VM
            tracing::info!(target: "guest_attest", error = %e, "No CVM report available, treating as TrustedLaunch");
            timer.mark("cvm_report_skip");
            IsolationInfo {
                vm_type: IsolationType::TrustedLaunch,
                evidence: None,
            }
        }
    };

    let tpm_info = TpmInfo {
        ak_cert,
        ak_pub,
        pcr_quote: quote,
        pcr_sig: sig,
        pcr_set,
        pcrs: pcrs_struct,
        enc_key_pub,
        enc_key_certify_info,
        enc_key_certify_info_sig,
    };

    let params = GuestAttestationParameters {
        protocol_version: "2.0".into(),
        os_type: os.os_type,
        os_distro: os.distro,
        os_version_major: os.version_major,
        os_version_minor: os.version_minor,
        os_build: os.build,
        tcg_logs,
        client_payload: client_payload.unwrap_or("").to_string(),
        tpm_info,
        isolation,
    };
    let request_json = params.to_json_string();
    tracing::info!(target: "guest_attest", request_len = request_json.len(), "Guest attestation request JSON built");

    let encoded = base64_url_encode(request_json.as_bytes());
    tracing::info!(target: "guest_attest", encoded_len = encoded.len(), "Guest attestation request base64url encoded");
    timer.mark("build_request");

    let provider: &dyn AttestationProvider = provider.unwrap_or(&LoopbackProvider);
    let token = submit_to_provider(&encoded, provider)?;
    timer.mark("provider");
    tracing::info!(target: "guest_attest", token_present = token.is_some(), token_len = token.as_ref().map(|t| t.len()).unwrap_or(0), "attest-guest complete");
    Ok(AttestCvmResult {
        request_json,
        encoded_request_b64url: encoded,
        token_b64url: token,
        ephemeral_key_handle: eph_handle,
        pcrs,
    })
}

/// Deprecated alias for [`attest_guest`].
#[deprecated(
    since = "0.2.0",
    note = "renamed to `attest_guest` to reflect TrustedLaunch support"
)]
pub fn attest_cvm(
    tpm: &Tpm,
    provider: Option<&dyn AttestationProvider>,
    client_payload: Option<&str>,
) -> io::Result<AttestCvmResult> {
    attest_guest(tpm, provider, client_payload)
}

/// Collect TCG event logs (best-effort, platform-specific).
pub fn collect_tcg_logs(os: &OsInfo) -> Vec<u8> {
    match os.os_type.as_str() {
        "Linux" => {
            const LINUX_TCG_LOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
            std::fs::read(LINUX_TCG_LOG_PATH).unwrap_or_default()
        }
        "Windows" => {
            #[cfg(target_os = "windows")]
            {
                read_windows_wbcl()
            }
            #[cfg(not(target_os = "windows"))]
            {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn read_windows_wbcl() -> Vec<u8> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    const KEY_PATH: &str = r"SYSTEM\CurrentControlSet\Control\IntegrityServices";
    unsafe {
        let mut hkey: isize = 0;
        let key_wide: Vec<u16> = KEY_PATH.encode_utf16().chain([0]).collect();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        ) != 0
        {
            return Vec::new();
        }
        let value_name: Vec<u16> = "WBCL".encode_utf16().chain([0]).collect();
        let mut data_len: u32 = 0;
        if RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut data_len,
        ) != 0
            || data_len == 0
        {
            RegCloseKey(hkey);
            return Vec::new();
        }
        let mut buf = vec![0u8; data_len as usize];
        if RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut data_len,
        ) != 0
        {
            RegCloseKey(hkey);
            return Vec::new();
        }
        RegCloseKey(hkey);
        buf.truncate(data_len as usize);
        buf
    }
}

/// Attempt to parse and decrypt a guest attestation token envelope returned by provider.
/// The token is expected to be a base64url encoded JSON object containing fields:
///   EncryptedInnerKey (base64 std)
///   EncryptionParams { Iv (base64 std) }
///   AuthenticationData (base64 std, 16-byte GCM tag)
///   Jwt (base64 std, ciphertext portion)
/// The EncryptedInnerKey is decrypted with the ephemeral TPM RSA key bound to PCRs.
/// Returns Ok(Some(jwt_string)) on success, Ok(None) if format not recognized.
pub fn parse_token(
    tpm: &Tpm,
    ephemeral_key_handle: u32,
    pcrs: &[u32],
    token_b64url: &str,
) -> io::Result<Option<String>> {
    // Base64url decode outer envelope
    let raw = match base64_url_decode(token_b64url) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let raw_str = match String::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let v: serde_json::Value = match serde_json::from_str(&raw_str) {
        Ok(j) => j,
        Err(_) => return Ok(None), // Not an envelope JSON
    };
    // Required fields
    let enc_inner = match v.get("EncryptedInnerKey").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let enc_params = match v.get("EncryptionParams") {
        Some(p) => p,
        None => return Ok(None),
    };
    let iv_b64 = match enc_params.get("Iv").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let auth_tag_b64 = match v.get("AuthenticationData").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let jwt_ct_b64 = match v.get("Jwt").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };

    // Helper base64 (standard first, then url-safe) decode
    fn b64_any(s: &str) -> io::Result<Vec<u8>> {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        STANDARD
            .decode(s.as_bytes())
            .or_else(|_| URL_SAFE_NO_PAD.decode(s.as_bytes()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode: {e}")))
    }
    let encrypted_inner_key = b64_any(enc_inner)?;
    let iv = b64_any(iv_b64)?;
    let auth_tag = b64_any(auth_tag_b64)?;
    let jwt_ct = b64_any(jwt_ct_b64)?;
    if iv.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected 12-byte IV",
        ));
    }
    if auth_tag.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected 16-byte GCM tag",
        ));
    }

    // Decrypt inner key via TPM
    let inner_key = crate::tpm::attestation::decrypt_with_ephemeral_key(
        tpm,
        ephemeral_key_handle,
        pcrs,
        &encrypted_inner_key,
    )?;
    if !(inner_key.len() == 16 || inner_key.len() == 24 || inner_key.len() == 32) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected inner key length {}", inner_key.len()),
        ));
    }

    // AES-GCM decrypt
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
    // Support key sizes <32 by zero-extending into 32 for Aes256Gcm (spec unclear). If shorter, right-pad zeros.
    let mut key_bytes = [0u8; 32];
    for (i, b) in inner_key.iter().enumerate().take(32) {
        key_bytes[i] = *b;
    }
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| io::Error::other(format!("aes key init: {e}")))?;
    let mut ct_and_tag = Vec::with_capacity(jwt_ct.len() + auth_tag.len());
    ct_and_tag.extend_from_slice(&jwt_ct);
    ct_and_tag.extend_from_slice(&auth_tag);
    let nonce = Nonce::from_slice(&iv);
    let aad = b"Transport Key"; // constant associated data per reference implementation
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ct_and_tag,
                aad,
            },
        )
        .map_err(|e| io::Error::other(format!("aes-gcm decrypt: {e}")))?;
    let jwt_str = String::from_utf8(plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("jwt utf8: {e}")))?;
    Ok(Some(jwt_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_version_pair tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_version_pair_major_minor() {
        assert_eq!(parse_version_pair("10.0"), (10, 0));
        assert_eq!(parse_version_pair("22.04"), (22, 4));
        assert_eq!(parse_version_pair("1.2"), (1, 2));
    }

    #[test]
    fn parse_version_pair_major_only() {
        assert_eq!(parse_version_pair("10"), (10, 0));
    }

    #[test]
    fn parse_version_pair_empty() {
        assert_eq!(parse_version_pair(""), (0, 0));
    }

    #[test]
    fn parse_version_pair_triple() {
        // Only first two parts used
        assert_eq!(parse_version_pair("1.2.3"), (1, 2));
    }

    #[test]
    fn parse_version_pair_non_numeric() {
        assert_eq!(parse_version_pair("abc.def"), (0, 0));
    }

    // -----------------------------------------------------------------------
    // base64_url_encode / base64_url_decode tests
    // -----------------------------------------------------------------------

    #[test]
    fn base64_url_roundtrip_empty() {
        let encoded = base64_url_encode(&[]);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, Vec::<u8>::new());
    }

    #[test]
    fn base64_url_roundtrip_simple() {
        let data = b"Hello, World!";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_url_roundtrip_binary() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64_url_encode(&data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_url_no_padding() {
        let encoded = base64_url_encode(b"test");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn base64_url_uses_url_safe_chars() {
        // Binary data that would produce + and / in standard base64
        let data = vec![0xFF; 16];
        let encoded = base64_url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn base64_url_decode_invalid() {
        let result = base64_url_decode("!!!invalid!!!");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    // -----------------------------------------------------------------------
    // OsInfo tests
    // -----------------------------------------------------------------------

    #[test]
    fn os_info_detect() {
        // This test will detect the current OS
        let result = OsInfo::detect();
        #[cfg(target_os = "linux")]
        {
            let info = result.expect("should detect Linux");
            assert_eq!(info.os_type, "Linux");
            assert_eq!(info.pcr_list, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        }
        #[cfg(target_os = "windows")]
        {
            let info = result.expect("should detect Windows");
            assert_eq!(info.os_type, "Windows");
            assert_eq!(info.pcr_list, vec![0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14]);
        }
    }

    #[test]
    fn os_info_serialization() {
        let info = OsInfo {
            os_type: "Linux".into(),
            distro: "Ubuntu".into(),
            version_major: 22,
            version_minor: 4,
            build: "NotApplication".into(),
            pcr_list: vec![0, 1, 2, 3],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"os_type\":\"Linux\""));
        assert!(json.contains("\"distro\":\"Ubuntu\""));
        assert!(json.contains("\"version_major\":22"));
    }

    #[test]
    fn os_info_deserialization_roundtrip() {
        let info = OsInfo {
            os_type: "Windows".into(),
            distro: "Windows".into(),
            version_major: 10,
            version_minor: 0,
            build: "NotApplication".into(),
            pcr_list: vec![0, 1, 2, 3, 4, 5, 6, 7],
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: OsInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.os_type, info.os_type);
        assert_eq!(deserialized.distro, info.distro);
        assert_eq!(deserialized.version_major, info.version_major);
        assert_eq!(deserialized.pcr_list, info.pcr_list);
    }

    // -----------------------------------------------------------------------
    // IsolationType serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn isolation_type_serialization() {
        let json = serde_json::to_string(&IsolationType::SevSnp).unwrap();
        assert_eq!(json, "\"SevSnp\"");

        let json = serde_json::to_string(&IsolationType::Tdx).unwrap();
        assert_eq!(json, "\"Tdx\"");

        let json = serde_json::to_string(&IsolationType::TrustedLaunch).unwrap();
        assert_eq!(json, "\"TrustedLaunch\"");
    }

    // -----------------------------------------------------------------------
    // IsolationInfo serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn isolation_info_without_evidence() {
        let info = IsolationInfo {
            vm_type: IsolationType::TrustedLaunch,
            evidence: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Type\":\"TrustedLaunch\""));
        assert!(!json.contains("Evidence"));
    }

    #[test]
    fn isolation_info_with_snp_evidence() {
        let info = IsolationInfo {
            vm_type: IsolationType::SevSnp,
            evidence: Some(IsolationEvidence {
                tee_proof: TeeProof::Snp {
                    snp_report: vec![0xAA; 32],
                    vcek_chain: vec![0xBB; 16],
                },
                runtime_data: vec![0xCC; 8],
            }),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Type\":\"SevSnp\""));
        assert!(json.contains("SnpReport"));
        assert!(json.contains("VcekCertChain"));
        assert!(json.contains("RunTimeData"));
    }

    #[test]
    fn isolation_info_with_tdx_evidence() {
        let info = IsolationInfo {
            vm_type: IsolationType::Tdx,
            evidence: Some(IsolationEvidence {
                tee_proof: TeeProof::Tdx {
                    td_quote: vec![0xDD; 64],
                },
                runtime_data: vec![],
            }),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Type\":\"Tdx\""));
    }

    // -----------------------------------------------------------------------
    // TeeProof serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn tee_proof_snp_serialization() {
        let proof = TeeProof::Snp {
            snp_report: vec![1, 2, 3],
            vcek_chain: vec![4, 5, 6],
        };
        let json = serde_json::to_string(&proof).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("SnpReport").is_some());
        assert!(v.get("VcekCertChain").is_some());
    }

    #[test]
    fn tee_proof_tdx_serialization() {
        let proof = TeeProof::Tdx {
            td_quote: vec![7, 8, 9],
        };
        let json = serde_json::to_string(&proof).unwrap();
        // TDX serializes as a plain base64 string
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_string());
    }

    // -----------------------------------------------------------------------
    // LoopbackProvider tests
    // -----------------------------------------------------------------------

    #[test]
    fn loopback_provider_returns_token() {
        let provider = LoopbackProvider;
        let result = provider.attest_guest("test_request").unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        // Token should be base64url encoded
        let decoded = base64_url_decode(&token).unwrap();
        let json_str = String::from_utf8(decoded).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["loopback"], true);
        assert_eq!(v["request"], "test_request");
    }

    // -----------------------------------------------------------------------
    // PcrEntry serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn pcr_entry_serialization() {
        let entry = PcrEntry {
            index: 7,
            digest: vec![0xAA; 32],
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"Index\":7"));
        assert!(json.contains("\"Digest\":"));
    }

    // -----------------------------------------------------------------------
    // TpmInfo serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn tpm_info_serialization() {
        let info = TpmInfo {
            ak_cert: vec![1],
            ak_pub: vec![2],
            pcr_quote: vec![3],
            pcr_sig: vec![4],
            pcr_set: vec![0, 1, 7],
            pcrs: vec![PcrEntry {
                index: 0,
                digest: vec![0; 32],
            }],
            enc_key_pub: vec![5],
            enc_key_certify_info: vec![6],
            enc_key_certify_info_sig: vec![7],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"AikCert\":"));
        assert!(json.contains("\"AikPub\":"));
        assert!(json.contains("\"PcrQuote\":"));
        assert!(json.contains("\"PcrSignature\":"));
        assert!(json.contains("\"PcrSet\":[0,1,7]"));
        assert!(json.contains("\"EncKeyPub\":"));
    }

    // -----------------------------------------------------------------------
    // GuestAttestationParameters serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn guest_attestation_parameters_to_json() {
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Ubuntu".into(),
            os_version_major: 22,
            os_version_minor: 4,
            os_build: "NotApplication".into(),
            tcg_logs: vec![0xAA],
            client_payload: r#"{"key":"value"}"#.into(),
            tpm_info: TpmInfo {
                ak_cert: vec![1],
                ak_pub: vec![2],
                pcr_quote: vec![3],
                pcr_sig: vec![4],
                pcr_set: vec![0],
                pcrs: vec![],
                enc_key_pub: vec![5],
                enc_key_certify_info: vec![6],
                enc_key_certify_info_sig: vec![7],
            },
            isolation: IsolationInfo {
                vm_type: IsolationType::TrustedLaunch,
                evidence: None,
            },
        };
        let json = params.to_json_string();
        assert!(!json.is_empty());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["AttestationProtocolVersion"], "2.0");
        assert!(v["TcgLogs"].is_string()); // base64 encoded
        assert!(v["ClientPayload"].is_object()); // client_payload_b64 serializer
    }

    #[test]
    fn guest_attestation_params_empty_client_payload() {
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Test".into(),
            os_version_major: 0,
            os_version_minor: 0,
            os_build: "".into(),
            tcg_logs: vec![],
            client_payload: "".into(),
            tpm_info: TpmInfo {
                ak_cert: vec![],
                ak_pub: vec![],
                pcr_quote: vec![],
                pcr_sig: vec![],
                pcr_set: vec![],
                pcrs: vec![],
                enc_key_pub: vec![],
                enc_key_certify_info: vec![],
                enc_key_certify_info_sig: vec![],
            },
            isolation: IsolationInfo {
                vm_type: IsolationType::TrustedLaunch,
                evidence: None,
            },
        };
        let json = params.to_json_string();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Empty client payload should serialize as empty object
        assert!(v["ClientPayload"].is_object());
        assert_eq!(v["ClientPayload"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn guest_attestation_params_invalid_json_client_payload() {
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Test".into(),
            os_version_major: 0,
            os_version_minor: 0,
            os_build: "".into(),
            tcg_logs: vec![],
            client_payload: "not valid json".into(),
            tpm_info: TpmInfo {
                ak_cert: vec![],
                ak_pub: vec![],
                pcr_quote: vec![],
                pcr_sig: vec![],
                pcr_set: vec![],
                pcrs: vec![],
                enc_key_pub: vec![],
                enc_key_certify_info: vec![],
                enc_key_certify_info_sig: vec![],
            },
            isolation: IsolationInfo {
                vm_type: IsolationType::TrustedLaunch,
                evidence: None,
            },
        };
        let json = params.to_json_string();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Invalid JSON client payload should be treated as empty object
        assert!(v["ClientPayload"].is_object());
        assert_eq!(v["ClientPayload"].as_object().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // StageTimer tests
    // -----------------------------------------------------------------------

    #[test]
    fn stage_timer_basic() {
        let mut timer = StageTimer::new();
        // Just verify it doesn't panic
        timer.mark("test_stage");
        timer.mark("another_stage");
    }

    // -----------------------------------------------------------------------
    // collect_tcg_logs tests
    // -----------------------------------------------------------------------

    #[test]
    fn collect_tcg_logs_unknown_os() {
        let os = OsInfo {
            os_type: "UnknownOS".into(),
            distro: "".into(),
            version_major: 0,
            version_minor: 0,
            build: "".into(),
            pcr_list: vec![],
        };
        let logs = collect_tcg_logs(&os);
        assert!(logs.is_empty());
    }

    // -----------------------------------------------------------------------
    // AttestCvmResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn attest_cvm_result_serialization() {
        let result = AttestCvmResult {
            request_json: "{}".into(),
            encoded_request_b64url: "abc".into(),
            token_b64url: Some("token".into()),
            ephemeral_key_handle: Some(0x81000001),
            pcrs: vec![0, 1, 7],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AttestCvmResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_json, "{}");
        assert_eq!(deserialized.token_b64url, Some("token".into()));
        assert_eq!(deserialized.pcrs, vec![0, 1, 7]);
    }

    // -----------------------------------------------------------------------
    // TeeOnlyRequest tests
    // -----------------------------------------------------------------------

    #[test]
    fn tee_only_request_serialization() {
        let req = TeeOnlyRequest {
            evidence_field: "quote".into(),
            evidence_b64: "abc123".into(),
            runtime_b64: "def456".into(),
            report_type: "TdxVmReport".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: TeeOnlyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.evidence_field, "quote");
        assert_eq!(deserialized.report_type, "TdxVmReport");
    }
}
