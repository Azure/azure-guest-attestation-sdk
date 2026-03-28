// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest attestation payload types, serialization, and helpers.
//!
//! This module provides the building blocks for guest attestation on Azure VMs
//! (both CVM and TrustedLaunch):
//!
//! - **Types**: `GuestAttestationParameters`, `TpmInfo`, `IsolationInfo`, etc.
//! - **Payload builders**: `build_tee_only_payload_from_evidence()`
//! - **Utilities**: `collect_tcg_logs()`, `base64_url_encode/decode()`, `parse_token()`
//!
//! ## Sub-modules
//!
//! - [`provider`] — `AttestationProvider` trait, `MaaProvider`, `LoopbackProvider`
//! - [`imds`] — `ImdsClient` for platform endorsements (VCEK chain, TD Quote)
//!
//! Most callers should use [`crate::client::AttestationClient`] which composes
//! these primitives into a clean layered API.

pub mod imds;
pub mod provider;

// Re-export commonly used items at this module level for convenience.
pub use imds::ImdsClient;
pub use provider::{
    submit_tee_only, submit_to_provider, AttestationProvider, LoopbackProvider, MaaProvider,
};

use base64::Engine;
use serde::ser::SerializeMap;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::io;
use std::time::Instant;

use crate::tpm::device::Tpm;

// ---------------------------------------------------------------------------
// StageTimer (internal)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// OS information
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Isolation / TEE types
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone)]
pub struct IsolationEvidence {
    pub tee_proof: TeeProof,
    pub runtime_data: Vec<u8>,
}

impl Serialize for IsolationEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        let mut state = serializer.serialize_struct("IsolationEvidence", 2)?;

        // The encoding varies by TEE type to match the MAA service expectations:
        //   SNP → base64url (no padding) for Proof and RunTimeData
        //   TDX → standard base64 for Proof and RunTimeData
        match &self.tee_proof {
            TeeProof::Snp {
                snp_report,
                vcek_chain,
            } => {
                // SNP Proof is a base64url-encoded JSON string containing
                // base64url-encoded SnpReport and VcekCertChain.
                let inner_json = serde_json::json!({
                    "SnpReport": URL_SAFE_NO_PAD.encode(snp_report),
                    "VcekCertChain": URL_SAFE_NO_PAD.encode(vcek_chain),
                });
                let inner_bytes = inner_json.to_string().into_bytes();
                let proof_str = URL_SAFE_NO_PAD.encode(&inner_bytes);
                state.serialize_field("Proof", &proof_str)?;
                state
                    .serialize_field("RunTimeData", &URL_SAFE_NO_PAD.encode(&self.runtime_data))?;
            }
            TeeProof::Tdx { td_quote } => {
                state.serialize_field("Proof", &STANDARD.encode(td_quote))?;
                state.serialize_field("RunTimeData", &STANDARD.encode(&self.runtime_data))?;
            }
        }
        state.end()
    }
}

/// TEE proof types (subset for SNP + TDX).
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

// ---------------------------------------------------------------------------
// Serde helpers
// ---------------------------------------------------------------------------

fn as_b64<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = base64::engine::general_purpose::STANDARD.encode(data);
    serializer.serialize_str(&s)
}

fn str_as_b64<S>(str: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = base64::engine::general_purpose::STANDARD.encode(str.as_bytes());
    serializer.serialize_str(&s)
}

/// Client payload stored as raw JSON string (object). At serialization we
/// parse and base64 encode each value.
fn client_payload_b64<S>(raw: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
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
    // SAFETY: v.is_object() was checked above, so as_object() is infallible.
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            let map = serializer.serialize_map(Some(0))?;
            return map.end();
        }
    };
    let mut m = serializer.serialize_map(Some(obj.len()))?;
    for (k, v) in obj.iter() {
        let val_str = if v.is_string() {
            v.as_str().unwrap_or_default().to_string()
        } else {
            v.to_string()
        };
        let enc = base64::engine::general_purpose::STANDARD.encode(val_str.as_bytes());
        m.serialize_entry(k, &enc)?;
    }
    m.end()
}

// ---------------------------------------------------------------------------
// TPM / attestation parameter types
// ---------------------------------------------------------------------------

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
    #[serde(rename = "PcrSet")]
    pub pcr_set: Vec<u32>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestCvmResult {
    pub request_json: String,
    pub encoded_request_b64url: String,
    pub token_b64url: Option<String>,
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

// ---------------------------------------------------------------------------
// TEE-only payload builders
// ---------------------------------------------------------------------------

/// Build a TEE-only JSON payload from pre-collected
/// [`CvmEvidence`](crate::client::CvmEvidence) and an optional endorsement.
///
/// Returns `(payload_json_string, report_type)`. The caller is responsible for
/// submitting this payload to the appropriate MAA platform endpoint.
pub fn build_tee_only_payload_from_evidence(
    evidence: &crate::client::CvmEvidence,
    endorsement: Option<&crate::client::Endorsement>,
) -> io::Result<(String, crate::report::CvmReportType)> {
    use base64::engine::general_purpose::STANDARD;
    let rtype = evidence.report_type;
    let runtime_data = Vec::new();
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

/// Perform a TEE-only attestation against a MAA platform endpoint.
///
/// **Convenience wrapper** that collects evidence from the TPM, builds the
/// payload, and submits it.
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

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// TCG log collection
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Token parsing / decryption
// ---------------------------------------------------------------------------

/// Attempt to parse and decrypt a guest attestation token envelope.
///
/// The token is expected to be a base64url encoded JSON object containing:
///   - `EncryptedInnerKey` (base64 std)
///   - `EncryptionParams.Iv` (base64 std)
///   - `AuthenticationData` (base64 std, 16-byte GCM tag)
///   - `Jwt` (base64 std, ciphertext portion)
///
/// The `EncryptedInnerKey` is decrypted with the ephemeral TPM RSA key bound
/// to the specified PCRs.
///
/// Returns `Ok(Some(jwt_string))` on success, `Ok(None)` if format not recognized.
pub fn parse_token(
    tpm: &Tpm,
    ephemeral_key_handle: u32,
    pcrs: &[u32],
    token_b64url: &str,
) -> io::Result<Option<String>> {
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
        Err(_) => return Ok(None),
    };
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

    let inner_key = crate::tpm::attestation::decrypt_with_ephemeral_key(
        tpm,
        ephemeral_key_handle,
        pcrs,
        &encrypted_inner_key,
    )?;
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes128Gcm, Aes256Gcm, Nonce};
    let mut ct_and_tag = Vec::with_capacity(jwt_ct.len() + auth_tag.len());
    ct_and_tag.extend_from_slice(&jwt_ct);
    ct_and_tag.extend_from_slice(&auth_tag);
    let nonce = Nonce::from_slice(&iv);
    let aad = b"Transport Key";
    let plaintext = match inner_key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(&inner_key)
                .map_err(|e| io::Error::other(format!("aes-128 key init: {e}")))?;
            cipher.decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &ct_and_tag,
                    aad,
                },
            )
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(&inner_key)
                .map_err(|e| io::Error::other(format!("aes-256 key init: {e}")))?;
            cipher.decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &ct_and_tag,
                    aad,
                },
            )
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported AES key length: {other} (expected 16 or 32)"),
            ));
        }
    }
    .map_err(|e| io::Error::other(format!("aes-gcm decrypt: {e}")))?;
    let jwt_str = String::from_utf8(plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("jwt utf8: {e}")))?;
    Ok(Some(jwt_str))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // parse_version_pair
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
        assert_eq!(parse_version_pair("1.2.3"), (1, 2));
    }

    #[test]
    fn parse_version_pair_non_numeric() {
        assert_eq!(parse_version_pair("abc.def"), (0, 0));
    }

    // base64_url_encode / decode
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

    // OsInfo
    #[test]
    fn os_info_detect() {
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

    // IsolationType
    #[test]
    fn isolation_type_serialization() {
        assert_eq!(
            serde_json::to_string(&IsolationType::SevSnp).unwrap(),
            "\"SevSnp\""
        );
        assert_eq!(
            serde_json::to_string(&IsolationType::Tdx).unwrap(),
            "\"Tdx\""
        );
        assert_eq!(
            serde_json::to_string(&IsolationType::TrustedLaunch).unwrap(),
            "\"TrustedLaunch\""
        );
    }

    // IsolationInfo
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
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let snp_report = vec![0xAA; 32];
        let vcek_chain = vec![0xBB; 16];
        let runtime_data = vec![0xCC; 8];

        let info = IsolationInfo {
            vm_type: IsolationType::SevSnp,
            evidence: Some(IsolationEvidence {
                tee_proof: TeeProof::Snp {
                    snp_report: snp_report.clone(),
                    vcek_chain: vcek_chain.clone(),
                },
                runtime_data: runtime_data.clone(),
            }),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Type\":\"SevSnp\""));
        assert!(json.contains("\"RunTimeData\":"));

        // The Proof field should be a base64url string, not a nested object.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let evidence = v["Evidence"].as_object().unwrap();
        let proof_str = evidence["Proof"].as_str().expect("Proof must be a string");

        // Decode the outer base64url to recover the inner JSON.
        let inner_bytes = URL_SAFE_NO_PAD.decode(proof_str).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&inner_bytes).unwrap();
        assert!(inner.get("SnpReport").is_some());
        assert!(inner.get("VcekCertChain").is_some());

        // Verify the inner values round-trip back to the original bytes.
        let decoded_report = URL_SAFE_NO_PAD
            .decode(inner["SnpReport"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded_report, snp_report);
        let decoded_vcek = URL_SAFE_NO_PAD
            .decode(inner["VcekCertChain"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded_vcek, vcek_chain);

        // RunTimeData should also be base64url-encoded.
        let rt_str = evidence["RunTimeData"].as_str().unwrap();
        let decoded_rt = URL_SAFE_NO_PAD.decode(rt_str).unwrap();
        assert_eq!(decoded_rt, runtime_data);
    }

    #[test]
    fn isolation_info_with_tdx_evidence() {
        use base64::engine::general_purpose::STANDARD;

        let td_quote = vec![0xDD; 64];
        let runtime_data = vec![0xEE; 16];

        let info = IsolationInfo {
            vm_type: IsolationType::Tdx,
            evidence: Some(IsolationEvidence {
                tee_proof: TeeProof::Tdx {
                    td_quote: td_quote.clone(),
                },
                runtime_data: runtime_data.clone(),
            }),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"Type\":\"Tdx\""));

        // TDX uses standard base64 (with padding) for both Proof and RunTimeData.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let evidence = v["Evidence"].as_object().unwrap();
        let proof_str = evidence["Proof"].as_str().unwrap();
        assert_eq!(STANDARD.decode(proof_str).unwrap(), td_quote);

        let rt_str = evidence["RunTimeData"].as_str().unwrap();
        assert_eq!(STANDARD.decode(rt_str).unwrap(), runtime_data);
    }

    // TeeProof (via IsolationEvidence)
    #[test]
    fn tee_proof_snp_double_encodes_as_base64url_string() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let evidence = IsolationEvidence {
            tee_proof: TeeProof::Snp {
                snp_report: vec![1, 2, 3],
                vcek_chain: vec![4, 5, 6],
            },
            runtime_data: vec![],
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Proof must be a flat string (not a nested object).
        let proof_str = v["Proof"].as_str().expect("Proof must be a string");

        // Decode outer → inner JSON → verify fields exist.
        let inner_bytes = URL_SAFE_NO_PAD.decode(proof_str).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&inner_bytes).unwrap();
        assert!(inner.get("SnpReport").is_some());
        assert!(inner.get("VcekCertChain").is_some());
    }

    #[test]
    fn tee_proof_tdx_serializes_as_base64_string() {
        let evidence = IsolationEvidence {
            tee_proof: TeeProof::Tdx {
                td_quote: vec![7, 8, 9],
            },
            runtime_data: vec![],
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["Proof"].is_string());
    }

    // PcrEntry
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

    // TpmInfo
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

    // GuestAttestationParameters
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
        assert!(v["TcgLogs"].is_string());
        assert!(v["ClientPayload"].is_object());
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
        assert!(v["ClientPayload"].is_object());
        assert_eq!(v["ClientPayload"].as_object().unwrap().len(), 0);
    }

    // StageTimer
    #[test]
    fn stage_timer_basic() {
        let mut timer = StageTimer::new();
        timer.mark("test_stage");
        timer.mark("another_stage");
    }

    // collect_tcg_logs
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

    // AttestCvmResult
    #[test]
    fn attest_cvm_result_serialization() {
        let result = AttestCvmResult {
            request_json: "{}".into(),
            encoded_request_b64url: "abc".into(),
            token_b64url: Some("token".into()),
            pcrs: vec![0, 1, 7],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: AttestCvmResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_json, "{}");
        assert_eq!(deserialized.token_b64url, Some("token".into()));
        assert_eq!(deserialized.pcrs, vec![0, 1, 7]);
    }

    // TeeOnlyRequest
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

    // -----------------------------------------------------------------------
    // parse_token — early-return / validation paths
    // -----------------------------------------------------------------------
    // These tests exercise the format-validation branches that return Ok(None)
    // or Err before the TPM decrypt call is reached.
    // Gated behind vtpm-tests because `Tpm::open_reference_for_tests()` is
    // only available with that feature.

    #[cfg(feature = "vtpm-tests")]
    fn dummy_tpm_for_parse_token() -> crate::tpm::device::Tpm {
        crate::tpm::device::Tpm::open_reference_for_tests()
            .expect("reference TPM for parse_token tests")
    }

    #[cfg(feature = "vtpm-tests")]
    fn json_to_b64url(v: &serde_json::Value) -> String {
        base64_url_encode(v.to_string().as_bytes())
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_invalid_base64_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let result = parse_token(&tpm, 0, &[], "!!!not-base64!!!").unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_non_utf8_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let bad_bytes: Vec<u8> = vec![0xFF, 0xFE, 0xFD];
        let encoded = base64_url_encode(&bad_bytes);
        let result = parse_token(&tpm, 0, &[], &encoded).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_non_json_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let encoded = base64_url_encode(b"this is not json");
        let result = parse_token(&tpm, 0, &[], &encoded).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_missing_encrypted_inner_key_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({
            "EncryptionParams": {"Iv": "AAAA"},
            "AuthenticationData": "BBBB",
            "Jwt": "CCCC"
        });
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_missing_encryption_params_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({
            "EncryptedInnerKey": "AAAA",
            "AuthenticationData": "BBBB",
            "Jwt": "CCCC"
        });
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_missing_iv_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({
            "EncryptedInnerKey": "AAAA",
            "EncryptionParams": {},
            "AuthenticationData": "BBBB",
            "Jwt": "CCCC"
        });
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_missing_auth_data_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({
            "EncryptedInnerKey": "AAAA",
            "EncryptionParams": {"Iv": "AAAA"},
            "Jwt": "CCCC"
        });
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_missing_jwt_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({
            "EncryptedInnerKey": "AAAA",
            "EncryptionParams": {"Iv": "AAAA"},
            "AuthenticationData": "BBBB"
        });
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_bad_iv_length_returns_error() {
        use base64::engine::general_purpose::STANDARD;
        let tpm = dummy_tpm_for_parse_token();
        let iv = STANDARD.encode(vec![0u8; 8]);
        let auth_tag = STANDARD.encode(vec![0u8; 16]);
        let v = serde_json::json!({
            "EncryptedInnerKey": STANDARD.encode(vec![0u8; 32]),
            "EncryptionParams": {"Iv": iv},
            "AuthenticationData": auth_tag,
            "Jwt": STANDARD.encode(vec![0u8; 64])
        });
        let err = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("12-byte IV"),
            "error message should mention IV: {err}"
        );
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_bad_auth_tag_length_returns_error() {
        use base64::engine::general_purpose::STANDARD;
        let tpm = dummy_tpm_for_parse_token();
        let iv = STANDARD.encode(vec![0u8; 12]);
        let auth_tag = STANDARD.encode(vec![0u8; 8]);
        let v = serde_json::json!({
            "EncryptedInnerKey": STANDARD.encode(vec![0u8; 32]),
            "EncryptionParams": {"Iv": iv},
            "AuthenticationData": auth_tag,
            "Jwt": STANDARD.encode(vec![0u8; 64])
        });
        let err = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("16-byte GCM tag"),
            "error message should mention GCM tag: {err}"
        );
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_empty_json_object_returns_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({});
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "vtpm-tests")]
    #[test]
    fn parse_token_non_string_fields_return_none() {
        let tpm = dummy_tpm_for_parse_token();
        let v = serde_json::json!({
            "EncryptedInnerKey": 12345,
            "EncryptionParams": {"Iv": "AAAA"},
            "AuthenticationData": "BBBB",
            "Jwt": "CCCC"
        });
        let result = parse_token(&tpm, 0, &[], &json_to_b64url(&v)).unwrap();
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // client_payload_b64 edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn client_payload_non_object_json_produces_empty_map() {
        // Array payload should produce empty ClientPayload
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Test".into(),
            os_version_major: 0,
            os_version_minor: 0,
            os_build: "".into(),
            tcg_logs: vec![],
            client_payload: "[1, 2, 3]".into(),
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
        assert!(v["ClientPayload"].is_object());
        assert_eq!(v["ClientPayload"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn client_payload_numeric_values_encoded_as_string() {
        use base64::engine::general_purpose::STANDARD;
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Test".into(),
            os_version_major: 0,
            os_version_minor: 0,
            os_build: "".into(),
            tcg_logs: vec![],
            client_payload: r#"{"count":42,"flag":true}"#.into(),
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
        let cp = v["ClientPayload"].as_object().unwrap();
        assert_eq!(cp.len(), 2);
        // Values should be base64-encoded strings
        let count_b64 = cp["count"].as_str().unwrap();
        let decoded = STANDARD.decode(count_b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "42");
        let flag_b64 = cp["flag"].as_str().unwrap();
        let decoded = STANDARD.decode(flag_b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "true");
    }

    #[test]
    fn client_payload_nested_object_value_serialized() {
        use base64::engine::general_purpose::STANDARD;
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Test".into(),
            os_version_major: 0,
            os_version_minor: 0,
            os_build: "".into(),
            tcg_logs: vec![],
            client_payload: r#"{"nested":{"a":1}}"#.into(),
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
        let cp = v["ClientPayload"].as_object().unwrap();
        let nested_b64 = cp["nested"].as_str().unwrap();
        let decoded = STANDARD.decode(nested_b64).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        let inner: serde_json::Value = serde_json::from_str(&decoded_str).unwrap();
        assert_eq!(inner["a"], 1);
    }

    #[test]
    fn client_payload_whitespace_only_produces_empty_map() {
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Test".into(),
            os_version_major: 0,
            os_version_minor: 0,
            os_build: "".into(),
            tcg_logs: vec![],
            client_payload: "   \t\n  ".into(),
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
        assert!(v["ClientPayload"].is_object());
        assert_eq!(v["ClientPayload"].as_object().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // collect_tcg_logs
    // -----------------------------------------------------------------------

    #[test]
    fn collect_tcg_logs_linux_returns_bytes_or_empty() {
        let os = OsInfo {
            os_type: "Linux".into(),
            distro: "Test".into(),
            version_major: 0,
            version_minor: 0,
            build: "".into(),
            pcr_list: vec![],
        };
        // On a test machine without TPM this returns empty; on a real CVM it returns data.
        // Either way it should not panic.
        let _logs = collect_tcg_logs(&os);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn collect_tcg_logs_windows_on_linux_returns_empty() {
        let os = OsInfo {
            os_type: "Windows".into(),
            distro: "".into(),
            version_major: 0,
            version_minor: 0,
            build: "".into(),
            pcr_list: vec![],
        };
        // Running on Linux, the Windows path should return empty
        assert!(collect_tcg_logs(&os).is_empty());
    }

    // -----------------------------------------------------------------------
    // str_as_b64 / as_b64 via GuestAttestationParameters serialization
    // -----------------------------------------------------------------------

    #[test]
    fn os_type_and_distro_are_base64_encoded() {
        use base64::engine::general_purpose::STANDARD;
        let params = GuestAttestationParameters {
            protocol_version: "2.0".into(),
            os_type: "Linux".into(),
            os_distro: "Ubuntu".into(),
            os_version_major: 22,
            os_version_minor: 4,
            os_build: "NotApplication".into(),
            tcg_logs: vec![0xDE, 0xAD],
            client_payload: "".into(),
            tpm_info: TpmInfo {
                ak_cert: vec![1, 2, 3],
                ak_pub: vec![4, 5, 6],
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
        // OSType is base64(str) encoded
        let os_type_b64 = v["OSType"].as_str().unwrap();
        let decoded = STANDARD.decode(os_type_b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Linux");
        // OSDistro is base64(str) encoded
        let os_distro_b64 = v["OSDistro"].as_str().unwrap();
        let decoded = STANDARD.decode(os_distro_b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Ubuntu");
        // TcgLogs is base64(bytes) encoded
        let tcg_b64 = v["TcgLogs"].as_str().unwrap();
        let decoded = STANDARD.decode(tcg_b64).unwrap();
        assert_eq!(decoded, vec![0xDE, 0xAD]);
    }

    // -----------------------------------------------------------------------
    // build_tee_only_payload_from_evidence
    // -----------------------------------------------------------------------

    #[test]
    fn build_tee_only_payload_unsupported_type_returns_error() {
        use crate::client::CvmEvidence;
        use crate::report::CvmReportType;
        let evidence = CvmEvidence {
            report_type: CvmReportType::VbsVmReport,
            tee_report: vec![],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: vec![],
        };
        let result = build_tee_only_payload_from_evidence(&evidence, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Unsupported"),
            "should mention unsupported: {err}"
        );
    }

    #[test]
    fn build_tee_only_payload_tdx_with_platform_quote() {
        use crate::client::CvmEvidence;
        use crate::report::CvmReportType;
        use base64::engine::general_purpose::STANDARD;
        let td_quote = vec![0xAA; 100];
        let evidence = CvmEvidence {
            report_type: CvmReportType::TdxVmReport,
            tee_report: vec![0xBB; 64],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: td_quote.clone(),
        };
        let (payload, rtype) = build_tee_only_payload_from_evidence(&evidence, None).unwrap();
        assert_eq!(rtype, CvmReportType::TdxVmReport);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        // TDX evidence uses "quote" field
        assert!(v.get("quote").is_some());
        let quote_b64 = v["quote"].as_str().unwrap();
        let decoded = STANDARD.decode(quote_b64).unwrap();
        assert_eq!(decoded, td_quote);
    }

    // -----------------------------------------------------------------------
    // build_tee_only_payload_from_evidence — injectorpp-mocked auto-fetch
    // -----------------------------------------------------------------------

    fn fake_get_vcek_chain_for_payload(_self: &ImdsClient) -> io::Result<Vec<u8>> {
        Ok(b"mocked-vcek-chain-for-payload".to_vec())
    }

    fn fake_get_td_quote_for_payload(_self: &ImdsClient, _report: &[u8]) -> io::Result<Vec<u8>> {
        Ok(vec![0xCC; 128])
    }

    #[test]
    fn build_tee_only_payload_snp_with_endorsement() {
        use crate::client::{CvmEvidence, Endorsement, EndorsementKind};
        use crate::report::CvmReportType;
        use base64::engine::general_purpose::STANDARD;
        let evidence = CvmEvidence {
            report_type: CvmReportType::SnpVmReport,
            tee_report: vec![0xAA; crate::report::SNP_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: vec![],
        };
        let endorsement = Endorsement {
            kind: EndorsementKind::Vcek,
            data: b"provided-vcek-chain".to_vec(),
        };
        let (payload, rtype) =
            build_tee_only_payload_from_evidence(&evidence, Some(&endorsement)).unwrap();
        assert_eq!(rtype, CvmReportType::SnpVmReport);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("report").is_some());
        // Decode the report field → inner JSON → VcekCertChain should match
        let report_b64 = v["report"].as_str().unwrap();
        let report_bytes = STANDARD.decode(report_b64).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&report_bytes).unwrap();
        let vcek_b64 = inner["VcekCertChain"].as_str().unwrap();
        let vcek_decoded = STANDARD.decode(vcek_b64).unwrap();
        assert_eq!(vcek_decoded, b"provided-vcek-chain");
    }

    #[test]
    fn build_tee_only_payload_snp_auto_fetch_vcek() {
        use crate::client::CvmEvidence;
        use crate::report::CvmReportType;
        use injectorpp::interface::injector::*;
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_vcek_chain))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(
                    fake_get_vcek_chain_for_payload
                ));
        }

        let evidence = CvmEvidence {
            report_type: CvmReportType::SnpVmReport,
            tee_report: vec![0xAA; crate::report::SNP_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: vec![],
        };
        // No endorsement → triggers auto-fetch
        let (payload, rtype) = build_tee_only_payload_from_evidence(&evidence, None).unwrap();
        assert_eq!(rtype, CvmReportType::SnpVmReport);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("report").is_some());
    }

    #[test]
    fn build_tee_only_payload_tdx_auto_fetch_td_quote() {
        use crate::client::CvmEvidence;
        use crate::report::CvmReportType;
        use base64::engine::general_purpose::STANDARD;
        use injectorpp::interface::injector::*;
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_td_quote))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(
                    fake_get_td_quote_for_payload
                ));
        }

        let evidence = CvmEvidence {
            report_type: CvmReportType::TdxVmReport,
            tee_report: vec![0xBB; crate::report::TDX_VM_REPORT_SIZE],
            runtime_claims: None,
            runtime_data: vec![],
            platform_quote: vec![], // empty → triggers auto-fetch
        };
        let (payload, rtype) = build_tee_only_payload_from_evidence(&evidence, None).unwrap();
        assert_eq!(rtype, CvmReportType::TdxVmReport);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(v.get("quote").is_some());
        let quote_b64 = v["quote"].as_str().unwrap();
        let decoded = STANDARD.decode(quote_b64).unwrap();
        assert_eq!(decoded, vec![0xCC; 128]);
    }
}
