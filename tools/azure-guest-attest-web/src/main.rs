// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Web-based interactive tool for Azure Guest Attestation.
//!
//! Runs a local HTTP server that exposes the SDK's attestation features
//! through a REST API and serves a browser-based UI for interactive testing.
//!
//! # Usage
//!
//! ```bash
//! # HTTP (default)
//! cargo run -p azure-guest-attest-web
//! # Open http://127.0.0.1:8080 in a browser
//!
//! # HTTPS with auto-generated self-signed certificate
//! cargo run -p azure-guest-attest-web -- --tls-self-signed
//!
//! # HTTPS with your own certificate
//! cargo run -p azure-guest-attest-web -- \
//!     --bind 0.0.0.0:443 --tls-cert cert.pem --tls-key key.pem
//! ```

#![allow(missing_docs)]

use axum::{
    extract::Json as JsonExtract,
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use azure_guest_attestation_sdk::report::CvmReportType;
use azure_guest_attestation_sdk::tpm::attestation;
use azure_guest_attestation_sdk::tpm::commands::TpmCommandExt;
use azure_guest_attestation_sdk::tpm::device::Tpm;
use azure_guest_attestation_sdk::tpm::event_log;
use azure_guest_attestation_sdk::tpm::types::PcrAlgorithm;
use azure_guest_attestation_sdk::{AttestOptions, AttestationClient, Provider};

// ---------------------------------------------------------------------------
// Embedded static assets
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = include_str!("../static/index.html");
const STYLE_CSS: &str = include_str!("../static/style.css");
const APP_JS: &str = include_str!("../static/app.js");
const API_DOCS_HTML: &str = include_str!("../static/api-docs.html");

// ---------------------------------------------------------------------------
// API response wrapper
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ApiResponse {
    fn ok(data: serde_json::Value) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }

    fn err(msg: impl ToString) -> Json<Self> {
        Json(Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// Static file handlers
// ---------------------------------------------------------------------------

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn style_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css")],
        STYLE_CSS,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript")],
        APP_JS,
    )
}

// ---------------------------------------------------------------------------
// API: Index & Documentation
// ---------------------------------------------------------------------------

/// Machine-readable JSON index of all available API endpoints.
async fn api_index() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "Azure Guest Attestation REST API",
        "docs": "/api/docs",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/diagnose",
                "description": "System diagnostics: OS, TPM availability, CVM type"
            },
            {
                "method": "GET",
                "path": "/api/cvm-report",
                "description": "Full CVM attestation report (header + TEE report + runtime claims)",
                "query_params": ["user_data"]
            },
            {
                "method": "GET",
                "path": "/api/tee-report",
                "description": "Raw TEE report (SNP / TDX / VBS)",
                "query_params": ["user_data"]
            },
            {
                "method": "GET",
                "path": "/api/ak-cert",
                "description": "Attestation Key certificate (PEM + base64)"
            },
            {
                "method": "GET",
                "path": "/api/ak-pub",
                "description": "Attestation Key public area (hex)"
            },
            {
                "method": "GET",
                "path": "/api/pcrs",
                "description": "PCR values across SHA-1 / SHA-256 / SHA-384 banks",
                "query_params": ["indices"]
            },
            {
                "method": "GET",
                "path": "/api/event-log",
                "description": "TPM event log with PCR replay"
            },
            {
                "method": "GET",
                "path": "/api/td-quote",
                "description": "Intel TDX quote (TDX CVMs only)"
            },
            {
                "method": "GET",
                "path": "/api/isolation-evidence",
                "description": "Platform isolation evidence (VCEK chain or TD quote)"
            },
            {
                "method": "POST",
                "path": "/api/guest-attest",
                "description": "Full guest attestation (TPM + TEE → provider)",
                "body_params": ["provider", "endpoint", "client_payload", "pcr_indices", "decode_token"]
            },
            {
                "method": "POST",
                "path": "/api/tee-attest",
                "description": "TEE-only platform attestation (no TPM/PCR)",
                "body_params": ["endpoint", "decode_token"]
            },
            {
                "method": "POST",
                "path": "/api/parse-token",
                "description": "Decode a JWT attestation token",
                "body_params": ["token"]
            }
        ]
    }))
}

/// HTML documentation page for the REST API.
async fn api_docs() -> Html<&'static str> {
    Html(API_DOCS_HTML)
}

// ---------------------------------------------------------------------------
// API: Diagnose
// ---------------------------------------------------------------------------

async fn api_diagnose() -> Json<ApiResponse> {
    tokio::task::spawn_blocking(|| {
        let mut info = serde_json::Map::new();
        info.insert("os".into(), serde_json::json!(std::env::consts::OS));
        info.insert("arch".into(), serde_json::json!(std::env::consts::ARCH));

        match Tpm::open() {
            Ok(_tpm) => {
                info.insert("tpm_available".into(), serde_json::json!(true));
                info.insert(
                    "tpm_status".into(),
                    serde_json::json!("TPM opened successfully"),
                );
            }
            Err(e) => {
                info.insert("tpm_available".into(), serde_json::json!(false));
                info.insert(
                    "tpm_status".into(),
                    serde_json::json!(format!("Failed to open TPM: {e}")),
                );
            }
        }

        // Detect CVM type if TPM is available
        if let Ok(tpm) = Tpm::open() {
            match attestation::get_cvm_report(&tpm, None) {
                Ok((report, _claims)) => {
                    let rtype = report.runtime_claims_header.report_type;
                    info.insert("cvm_type".into(), serde_json::json!(format!("{rtype:?}")));
                }
                Err(e) => {
                    info.insert(
                        "cvm_type".into(),
                        serde_json::json!(format!("Not detected ({e})")),
                    );
                }
            }
        }

        ApiResponse::ok(serde_json::Value::Object(info))
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: CVM Report
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CvmReportParams {
    #[serde(default)]
    user_data: Option<String>,
}

async fn api_cvm_report(params: axum::extract::Query<CvmReportParams>) -> Json<ApiResponse> {
    let user_data = params.user_data.clone();
    tokio::task::spawn_blocking(move || {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let ud_vec = match parse_user_data_opt(user_data.as_deref()) {
            Ok(v) => v,
            Err(e) => return ApiResponse::err(e),
        };

        let (report, claims) = match attestation::get_cvm_report(&tpm, ud_vec.as_deref()) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Failed to get CVM report: {e}")),
        };

        let rtype = report.runtime_claims_header.report_type;
        let rh = &report.report_header;
        let rch = &report.runtime_claims_header;

        let mut result = serde_json::json!({
            "report_header": {
                "signature": format!("0x{:08x}", rh.signature),
                "version": rh.version,
                "report_size": rh.report_size,
                "request_type": format!("{:?}", rh.request_type),
                "status": format!("0x{:08x}", rh.status),
            },
            "runtime_claims_header": {
                "data_size": rch.data_size,
                "version": rch.version,
                "report_type": format!("{rtype:?}"),
                "report_data_hash_type": format!("{:?}", rch.report_data_hash_type),
                "variable_data_size": rch.variable_data_size,
            },
        });

        // Parse and pretty-print TEE report
        let expected = match rtype {
            CvmReportType::SnpVmReport => azure_guest_attestation_sdk::report::SNP_VM_REPORT_SIZE,
            CvmReportType::TdxVmReport => azure_guest_attestation_sdk::report::TDX_VM_REPORT_SIZE,
            CvmReportType::VbsVmReport => azure_guest_attestation_sdk::report::VBS_VM_REPORT_SIZE,
            _ => 0,
        };

        if expected > 0 && expected <= report.tee_report.len() {
            let tee_pretty = match rtype {
                CvmReportType::SnpVmReport => {
                    let parsed = azure_guest_attestation_sdk::parse::snp_report(
                        &report.tee_report[..expected],
                    );
                    parsed
                        .map(|r| azure_guest_attestation_sdk::parse::snp_report_pretty(&r))
                        .ok()
                }
                CvmReportType::TdxVmReport => {
                    let parsed = azure_guest_attestation_sdk::parse::tdx_report(
                        &report.tee_report[..expected],
                    );
                    parsed
                        .map(|r| azure_guest_attestation_sdk::parse::tdx_report_pretty(&r))
                        .ok()
                }
                CvmReportType::VbsVmReport => {
                    let parsed = azure_guest_attestation_sdk::parse::vbs_report(
                        &report.tee_report[..expected],
                    );
                    parsed
                        .map(|r| azure_guest_attestation_sdk::parse::vbs_report_pretty(&r))
                        .ok()
                }
                _ => None,
            };
            if let Some(pretty) = tee_pretty {
                result["tee_report_pretty"] = serde_json::json!(pretty);
            }
            result["tee_report_hex"] =
                serde_json::json!(hex::encode(&report.tee_report[..expected]));
        }

        match claims {
            Some(c) => result["runtime_claims"] = serde_json::json!(c),
            None => result["runtime_claims"] = serde_json::json!(null),
        }

        ApiResponse::ok(result)
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: TEE Report
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TeeReportParams {
    #[serde(default)]
    user_data: Option<String>,
}

async fn api_tee_report(params: axum::extract::Query<TeeReportParams>) -> Json<ApiResponse> {
    let user_data = params.user_data.clone();
    tokio::task::spawn_blocking(move || {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let ud_vec = match parse_user_data_opt(user_data.as_deref()) {
            Ok(v) => v,
            Err(e) => return ApiResponse::err(e),
        };

        let (tee_bytes, rtype) = match attestation::get_tee_report_and_type(&tpm, ud_vec.as_deref())
        {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Failed to get TEE report: {e}")),
        };

        if tee_bytes.is_empty() {
            return ApiResponse::ok(serde_json::json!({
                "report_type": format!("{rtype:?}"),
                "message": "No TEE report payload for this report type"
            }));
        }

        let pretty = match rtype {
            CvmReportType::SnpVmReport => {
                azure_guest_attestation_sdk::parse::snp_report(&tee_bytes)
                    .map(|r| azure_guest_attestation_sdk::parse::snp_report_pretty(&r))
                    .ok()
            }
            CvmReportType::TdxVmReport => {
                azure_guest_attestation_sdk::parse::tdx_report(&tee_bytes)
                    .map(|r| azure_guest_attestation_sdk::parse::tdx_report_pretty(&r))
                    .ok()
            }
            CvmReportType::VbsVmReport => {
                azure_guest_attestation_sdk::parse::vbs_report(&tee_bytes)
                    .map(|r| azure_guest_attestation_sdk::parse::vbs_report_pretty(&r))
                    .ok()
            }
            _ => None,
        };

        let mut result = serde_json::json!({
            "report_type": format!("{rtype:?}"),
            "raw_hex": hex::encode(&tee_bytes),
            "size_bytes": tee_bytes.len(),
        });

        if let Some(p) = pretty {
            result["pretty"] = serde_json::json!(p);
        }

        ApiResponse::ok(result)
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: AK Cert
// ---------------------------------------------------------------------------

async fn api_ak_cert() -> Json<ApiResponse> {
    tokio::task::spawn_blocking(|| {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let cert = match attestation::get_ak_cert_trimmed(&tpm) {
            Ok(c) => c,
            Err(e) => return ApiResponse::err(format!("Failed to get AK cert: {e}")),
        };

        if cert.is_empty() {
            return ApiResponse::ok(serde_json::json!({
                "message": "AK cert NV index empty or not defined"
            }));
        }

        let pem = der_to_pem("CERTIFICATE", &cert);
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert);

        ApiResponse::ok(serde_json::json!({
            "pem": pem,
            "base64": b64,
            "size_bytes": cert.len(),
        }))
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: AK Pub
// ---------------------------------------------------------------------------

async fn api_ak_pub() -> Json<ApiResponse> {
    tokio::task::spawn_blocking(|| {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let pub_area = match attestation::get_ak_pub(&tpm) {
            Ok(p) => p,
            Err(e) => return ApiResponse::err(format!("Failed to get AK pub: {e}")),
        };

        ApiResponse::ok(serde_json::json!({
            "hex": hex::encode(&pub_area),
            "size_bytes": pub_area.len(),
        }))
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: PCR Values
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PcrParams {
    #[serde(default)]
    indices: Option<String>,
}

async fn api_pcrs(params: axum::extract::Query<PcrParams>) -> Json<ApiResponse> {
    let indices_str = params.indices.clone();
    tokio::task::spawn_blocking(move || {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let indices = parse_pcr_indices(indices_str.as_deref());

        let mut banks = serde_json::Map::new();
        let mut errors = Vec::new();

        for alg in [
            PcrAlgorithm::Sha1,
            PcrAlgorithm::Sha256,
            PcrAlgorithm::Sha384,
        ] {
            match tpm.read_pcrs_for_alg(alg, &indices) {
                Ok(values) if !values.is_empty() => {
                    let bank: serde_json::Map<String, serde_json::Value> = values
                        .iter()
                        .map(|(idx, digest)| {
                            (
                                format!("PCR[{idx}]"),
                                serde_json::json!(hex::encode(digest)),
                            )
                        })
                        .collect();
                    banks.insert(format!("{alg}"), serde_json::Value::Object(bank));
                }
                Ok(_) => {}
                Err(e) => errors.push(format!("{alg}: {e}")),
            }
        }

        let mut result = serde_json::json!({ "banks": banks });
        if !errors.is_empty() {
            result["notes"] = serde_json::json!(errors);
        }

        ApiResponse::ok(result)
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: TPM Event Log
// ---------------------------------------------------------------------------

async fn api_event_log() -> Json<ApiResponse> {
    tokio::task::spawn_blocking(|| {
        let log_bytes = match load_event_log() {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return ApiResponse::ok(serde_json::json!({
                    "message": "No event log found at standard platform locations"
                }))
            }
            Err(e) => return ApiResponse::err(format!("Failed to load event log: {e}")),
        };

        let parsed = match event_log::parse_event_log(&log_bytes) {
            Ok(p) => p,
            Err(e) => return ApiResponse::err(format!("Failed to parse event log: {e}")),
        };

        let events: Vec<serde_json::Value> = parsed
            .events
            .iter()
            .map(|evt| {
                // Pick the first digest (usually SHA-256) for display
                let digest_hex = evt
                    .digest_for_algorithm(PcrAlgorithm::Sha256)
                    .or_else(|| evt.digests.first().map(|d| d.digest.as_slice()))
                    .map(hex::encode)
                    .unwrap_or_default();
                serde_json::json!({
                    "pcr_index": evt.pcr_index,
                    "event_type": format!("0x{:08x}", evt.event_type),
                    "event_type_name": event_type_name(evt.event_type),
                    "digest_hex": digest_hex,
                    "event_data_size": evt.event_data.len(),
                })
            })
            .collect();

        // Replay PCR values
        let replayed = event_log::replay_pcrs(&parsed.events, PcrAlgorithm::Sha256);
        let pcr_replay: serde_json::Map<String, serde_json::Value> = replayed
            .iter()
            .map(|(idx, digest)| {
                (
                    format!("PCR[{idx}]"),
                    serde_json::json!(hex::encode(digest)),
                )
            })
            .collect();

        ApiResponse::ok(serde_json::json!({
            "event_count": events.len(),
            "events": events,
            "replayed_pcrs_sha256": pcr_replay,
        }))
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: TD Quote
// ---------------------------------------------------------------------------

async fn api_td_quote() -> Json<ApiResponse> {
    tokio::task::spawn_blocking(|| {
        // Fetch TD quote from platform (requires TDX CVM)
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let raw_report = match attestation::get_cvm_report_raw(&tpm, None) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Failed to get CVM report: {e}")),
        };

        let (parsed, _) = match azure_guest_attestation_sdk::report::CvmAttestationReport::parse_with_runtime_claims(&raw_report) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Failed to parse CVM report: {e}")),
        };

        if parsed.runtime_claims_header.report_type != CvmReportType::TdxVmReport {
            return ApiResponse::ok(serde_json::json!({
                "message": format!("Not a TDX VM (detected: {:?})", parsed.runtime_claims_header.report_type)
            }));
        }

        let imds = azure_guest_attestation_sdk::guest_attest::ImdsClient::new();
        let quote_bytes = match imds.get_td_quote(&parsed.tee_report) {
            Ok(q) => q,
            Err(e) => return ApiResponse::err(format!("Failed to fetch TD quote from IMDS: {e}")),
        };

        let mut result = serde_json::json!({
            "size_bytes": quote_bytes.len(),
            "hex": hex::encode(&quote_bytes),
            "base64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &quote_bytes,
            ),
        });

        // Try to parse the quote
        match azure_guest_attestation_sdk::parse::td_quote(&quote_bytes) {
            Ok(parsed_quote) => {
                result["pretty"] =
                    serde_json::json!(azure_guest_attestation_sdk::parse::td_quote_pretty(&parsed_quote));
            }
            Err(e) => {
                result["parse_error"] = serde_json::json!(format!("{e}"));
            }
        }

        ApiResponse::ok(result)
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: Isolation Evidence
// ---------------------------------------------------------------------------

async fn api_isolation_evidence() -> Json<ApiResponse> {
    tokio::task::spawn_blocking(|| {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let raw_report = match attestation::get_cvm_report_raw(&tpm, None) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Failed to get CVM report: {e}")),
        };

        let (parsed, _) = match azure_guest_attestation_sdk::report::CvmAttestationReport::parse_with_runtime_claims(&raw_report) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Failed to parse CVM report: {e}")),
        };

        let rtype = parsed.runtime_claims_header.report_type;

        match rtype {
            CvmReportType::SnpVmReport => {
                let imds = azure_guest_attestation_sdk::guest_attest::ImdsClient::new();
                match imds.get_vcek_chain() {
                    Ok(bytes) => ApiResponse::ok(serde_json::json!({
                        "type": "SNP VCEK Chain",
                        "hex": hex::encode(&bytes),
                        "base64": base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &bytes,
                        ),
                        "size_bytes": bytes.len(),
                    })),
                    Err(e) => ApiResponse::err(format!("Failed to fetch VCEK chain: {e}")),
                }
            }
            CvmReportType::TdxVmReport => {
                let imds = azure_guest_attestation_sdk::guest_attest::ImdsClient::new();
                match imds.get_td_quote(&parsed.tee_report) {
                    Ok(bytes) => ApiResponse::ok(serde_json::json!({
                        "type": "TDX TD Quote",
                        "hex": hex::encode(&bytes),
                        "base64": base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &bytes,
                        ),
                        "size_bytes": bytes.len(),
                    })),
                    Err(e) => ApiResponse::err(format!("Failed to fetch TD quote: {e}")),
                }
            }
            _ => ApiResponse::ok(serde_json::json!({
                "message": format!("No isolation evidence for report type {:?}", rtype)
            })),
        }
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: Guest Attestation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GuestAttestRequest {
    #[serde(default = "default_provider")]
    provider: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    client_payload: Option<String>,
    #[serde(default)]
    pcr_indices: Option<Vec<u32>>,
    #[serde(default)]
    decode_token: bool,
}

fn default_provider() -> String {
    "loopback".into()
}

async fn api_guest_attest(JsonExtract(req): JsonExtract<GuestAttestRequest>) -> Json<ApiResponse> {
    tokio::task::spawn_blocking(move || {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let provider = match req.provider.as_str() {
            "loopback" => Provider::Loopback,
            "maa" => {
                let endpoint = req
                    .endpoint
                    .as_deref()
                    .unwrap_or("https://sharedweu.weu.attest.azure.net");
                Provider::maa(endpoint)
            }
            other => {
                return ApiResponse::err(format!(
                    "Unknown provider: {other}. Use 'loopback' or 'maa'"
                ))
            }
        };

        let client = AttestationClient::from_tpm(tpm);
        let opts = AttestOptions {
            client_payload: req.client_payload.clone(),
            pcr_selection: req.pcr_indices.clone(),
        };

        let result = match client.attest_guest(provider, Some(&opts)) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("Attestation failed: {e}")),
        };

        let mut response = serde_json::json!({
            "pcrs": result.pcrs,
            "request_json": result.request_json,
            "encoded_request": result.encoded_request,
        });

        if let Some(ref token) = result.token {
            response["token"] = serde_json::json!(token);

            if req.decode_token {
                // Try to decrypt the token envelope first
                match client.decrypt_token(&result.pcrs, token) {
                    Ok(Some(inner_jwt)) => {
                        response["decrypted"] = serde_json::json!(true);
                        if let Ok(claims) =
                            azure_guest_attestation_sdk::parse::attestation_token(&inner_jwt)
                        {
                            response["token_header"] = claims.header;
                            response["token_payload"] = claims.payload;
                        }
                    }
                    Ok(None) | Err(_) => {
                        // Try direct JWT decode
                        response["decrypted"] = serde_json::json!(false);
                        if let Ok(claims) =
                            azure_guest_attestation_sdk::parse::attestation_token(token)
                        {
                            response["token_header"] = claims.header;
                            response["token_payload"] = claims.payload;
                        }
                    }
                }
            }
        }

        ApiResponse::ok(response)
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: TEE Attestation (no TPM evidence)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TeeAttestRequest {
    #[serde(default = "default_tee_endpoint")]
    endpoint: String,
    #[serde(default)]
    decode_token: bool,
}

fn default_tee_endpoint() -> String {
    "https://sharedweu.weu.attest.azure.net".into()
}

async fn api_tee_attest(JsonExtract(req): JsonExtract<TeeAttestRequest>) -> Json<ApiResponse> {
    tokio::task::spawn_blocking(move || {
        let tpm = match Tpm::open() {
            Ok(t) => t,
            Err(e) => return ApiResponse::err(format!("Failed to open TPM: {e}")),
        };

        let client = AttestationClient::from_tpm(tpm);
        let provider = Provider::maa(&req.endpoint);

        let result = match client.attest_platform(provider) {
            Ok(r) => r,
            Err(e) => return ApiResponse::err(format!("TEE attestation failed: {e}")),
        };

        let mut response = serde_json::json!({
            "request_json": result.request_json,
        });

        if let Some(ref token) = result.token {
            response["token"] = serde_json::json!(token);

            if req.decode_token {
                if let Ok(claims) = azure_guest_attestation_sdk::parse::attestation_token(token) {
                    response["token_header"] = claims.header;
                    response["token_payload"] = claims.payload;
                }
            }
        }

        ApiResponse::ok(response)
    })
    .await
    .unwrap_or_else(|e| ApiResponse::err(format!("Task failed: {e}")))
}

// ---------------------------------------------------------------------------
// API: Parse Token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ParseTokenRequest {
    token: String,
}

async fn api_parse_token(JsonExtract(req): JsonExtract<ParseTokenRequest>) -> Json<ApiResponse> {
    // Token parsing is purely CPU-bound, no TPM needed
    match azure_guest_attestation_sdk::parse::attestation_token(&req.token) {
        Ok(claims) => ApiResponse::ok(serde_json::json!({
            "header": claims.header,
            "payload": claims.payload,
        })),
        Err(e) => ApiResponse::err(format!("Failed to parse token: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse optional user data from query param.
/// Supports `hex:...`, `utf8:...`, or auto-detect hex.
fn parse_user_data_opt(input: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    let input = match input {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };

    if let Some(hex_str) = input.strip_prefix("hex:") {
        hex::decode(hex_str)
            .map(Some)
            .map_err(|e| format!("Invalid hex: {e}"))
    } else if let Some(utf8_str) = input.strip_prefix("utf8:") {
        let mut bytes = utf8_str.as_bytes().to_vec();
        bytes.truncate(64);
        Ok(Some(bytes))
    } else if input.len() % 2 == 0 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(input)
            .map(Some)
            .map_err(|e| format!("Invalid hex: {e}"))
    } else {
        let mut bytes = input.as_bytes().to_vec();
        bytes.truncate(64);
        Ok(Some(bytes))
    }
}

/// Parse PCR indices from comma-separated string; defaults to 0..=23.
fn parse_pcr_indices(input: Option<&str>) -> Vec<u32> {
    match input {
        Some(s) if !s.is_empty() => s
            .split(',')
            .filter_map(|p| p.trim().parse::<u32>().ok())
            .collect(),
        _ => (0..=23).collect(),
    }
}

/// Convert DER bytes to a PEM string with the given label.
fn der_to_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----"));
    pem
}

/// Try to load the platform event log from standard locations.
fn load_event_log() -> std::io::Result<Option<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        let path = std::path::Path::new("/sys/kernel/security/tpm0/binary_bios_measurements");
        if path.exists() {
            return std::fs::read(path).map(Some);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let path = std::path::Path::new(r"C:\Windows\Logs\MeasuredBoot\0000000001-0000000000.log");
        if path.exists() {
            return std::fs::read(path).map(Some);
        }
    }

    Ok(None)
}

/// Map common TCG event type IDs to human-readable names.
fn event_type_name(event_type: u32) -> &'static str {
    match event_type {
        0x0000_0000 => "EV_PREBOOT_CERT",
        0x0000_0001 => "EV_POST_CODE",
        0x0000_0002 => "EV_UNUSED",
        0x0000_0003 => "EV_NO_ACTION",
        0x0000_0004 => "EV_SEPARATOR",
        0x0000_0005 => "EV_ACTION",
        0x0000_0006 => "EV_EVENT_TAG",
        0x0000_0007 => "EV_S_CRTM_CONTENTS",
        0x0000_0008 => "EV_S_CRTM_VERSION",
        0x0000_0009 => "EV_CPU_MICROCODE",
        0x0000_000a => "EV_PLATFORM_CONFIG_FLAGS",
        0x0000_000b => "EV_TABLE_OF_DEVICES",
        0x0000_000c => "EV_COMPACT_HASH",
        0x0000_000d => "EV_IPL",
        0x0000_000e => "EV_IPL_PARTITION_DATA",
        0x0000_000f => "EV_NONHOST_CODE",
        0x0000_0010 => "EV_NONHOST_CONFIG",
        0x0000_0011 => "EV_NONHOST_INFO",
        0x0000_0012 => "EV_OMIT_BOOT_DEVICE_EVENTS",
        0x8000_0001 => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x8000_0002 => "EV_EFI_VARIABLE_BOOT",
        0x8000_0003 => "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x8000_0004 => "EV_EFI_BOOT_SERVICES_DRIVER",
        0x8000_0005 => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x8000_0006 => "EV_EFI_GPT_EVENT",
        0x8000_0007 => "EV_EFI_ACTION",
        0x8000_0008 => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        0x8000_0009 => "EV_EFI_HANDOFF_TABLES",
        0x8000_000a => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        0x8000_000b => "EV_EFI_HANDOFF_TABLES2",
        0x8000_000c => "EV_EFI_VARIABLE_BOOT2",
        0x8000_000e => "EV_EFI_HCRTM_EVENT",
        0x8000_0010 => "EV_EFI_VARIABLE_AUTHORITY",
        0x8000_0011 => "EV_EFI_SPDM_FIRMWARE_BLOB",
        0x8000_0012 => "EV_EFI_SPDM_FIRMWARE_CONFIG",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(about = "Azure Guest Attestation Web UI")]
struct Cli {
    /// Address and port to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,

    /// Path to TLS certificate file (PEM).
    /// When both --tls-cert and --tls-key are provided, the server uses HTTPS.
    #[arg(long = "tls-cert")]
    tls_cert: Option<std::path::PathBuf>,

    /// Path to TLS private key file (PEM)
    #[arg(long = "tls-key")]
    tls_key: Option<std::path::PathBuf>,

    /// Generate and use a self-signed TLS certificate (ephemeral).
    /// No external tools (e.g. openssl) required.
    /// The generated cert covers localhost, 127.0.0.1, ::1, and the --bind host.
    /// Use --tls-san to add extra Subject Alternative Names (IPs or hostnames).
    /// The cert is regenerated on every restart; use --tls-self-signed-dir to
    /// persist it to disk.
    #[arg(long = "tls-self-signed")]
    tls_self_signed: bool,

    /// Directory to store a persistent self-signed certificate.
    /// If cert.pem + key.pem already exist in this directory, they are loaded;
    /// otherwise a new self-signed certificate is generated and saved there.
    /// Implies --tls-self-signed behaviour.
    #[arg(long = "tls-self-signed-dir")]
    tls_self_signed_dir: Option<std::path::PathBuf>,

    /// Additional Subject Alternative Name(s) for the self-signed certificate.
    /// Accepts both IP addresses and DNS hostnames. Use when clients connect
    /// via an address not in the defaults (e.g. --tls-san 10.0.0.5,
    /// --tls-san myvm.eastus.cloudapp.azure.com). Can be repeated.
    #[arg(long = "tls-san")]
    tls_san: Vec<String>,
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

/// Load TLS certificate and private key from PEM files.
fn load_tls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    use std::io::BufReader;

    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("opening cert {}: {e}", cert_path.display()),
        )
    })?;
    let key_file = std::fs::File::open(key_path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("opening key {}: {e}", key_path.display()))
    })?;

    let certs: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file)).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no certificates found in cert file",
        ));
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no private key found in key file",
        )
    })?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("TLS config: {e}"))
        })?;

    Ok(Arc::new(config))
}

/// Build a rustls `ServerConfig` from PEM-encoded certificate and key strings.
fn build_tls_config_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no certificates found in PEM data",
        ));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no private key found in PEM data",
        )
    })?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("TLS config: {e}"))
        })?;

    Ok(Arc::new(config))
}

/// Generate a self-signed certificate using `rcgen`.
///
/// Returns `(cert_pem, key_pem, rustls_config)`.  The PEM strings can be
/// saved to disk for reuse on subsequent runs.
///
/// The certificate covers `localhost`, `127.0.0.1`, `::1`, and optionally
/// the host portion of the `--bind` address (if it differs).
fn generate_self_signed_config(
    bind_host: &str,
    extra_sans: &[String],
) -> std::io::Result<(String, String, Arc<rustls::ServerConfig>)> {
    use rcgen::CertifiedKey;

    // Collect Subject Alternative Names
    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    // If the bind address host is something other than the defaults, add it
    if !bind_host.is_empty() && bind_host != "0.0.0.0" && !sans.contains(&bind_host.to_string()) {
        sans.push(bind_host.to_string());
    }
    // Append user-supplied extra SANs (--tls-san)
    for san in extra_sans {
        if !sans.contains(san) {
            sans.push(san.clone());
        }
    }

    let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| std::io::Error::other(format!("failed to generate self-signed cert: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let config = build_tls_config_from_pem(&cert_pem, &key_pem)?;

    Ok((cert_pem, key_pem, config))
}

/// Load or generate a self-signed certificate, persisted in `dir`.
///
/// If `dir/cert.pem` and `dir/key.pem` exist, they are loaded.  Otherwise a
/// new self-signed cert is generated and written to those files.
///
/// Returns `(config, was_loaded_from_disk)`.
fn load_or_generate_self_signed(
    dir: &std::path::Path,
    bind_host: &str,
    extra_sans: &[String],
) -> std::io::Result<(Arc<rustls::ServerConfig>, bool)> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        // Reuse existing certificate
        let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("reading {}: {e}", cert_path.display()))
        })?;
        let key_pem = std::fs::read_to_string(&key_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("reading {}: {e}", key_path.display()))
        })?;
        let config = build_tls_config_from_pem(&cert_pem, &key_pem)?;
        Ok((config, true))
    } else {
        // Generate and save
        std::fs::create_dir_all(dir).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("creating directory {}: {e}", dir.display()),
            )
        })?;
        let (cert_pem, key_pem, config) = generate_self_signed_config(bind_host, extra_sans)?;
        std::fs::write(&cert_path, &cert_pem).map_err(|e| {
            std::io::Error::new(e.kind(), format!("writing {}: {e}", cert_path.display()))
        })?;
        std::fs::write(&key_path, &key_pem).map_err(|e| {
            std::io::Error::new(e.kind(), format!("writing {}: {e}", key_path.display()))
        })?;
        Ok((config, false))
    }
}

/// Run the TLS accept loop: accept TCP connections, TLS-handshake, then
/// serve with hyper + axum.
async fn serve_https(
    listener: tokio::net::TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
    app: Router,
) {
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    loop {
        let (tcp_stream, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("TCP accept error: {e}");
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let Ok(tls_stream) = tls_acceptor.accept(tcp_stream).await else {
                return;
            };

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let mut svc = app.clone();
                    async move {
                        use tower::Service;
                        svc.call(req.map(axum::body::Body::new)).await
                    }
                });

            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
        });
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    azure_guest_attestation_sdk::init_tracing();

    // Install the ring crypto provider for rustls before any TLS config is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    let app = Router::new()
        // Static assets
        .route("/", get(index))
        .route("/style.css", get(style_css))
        .route("/app.js", get(app_js))
        // API index & docs
        .route("/api", get(api_index))
        .route("/api/docs", get(api_docs))
        // API endpoints
        .route("/api/diagnose", get(api_diagnose))
        .route("/api/cvm-report", get(api_cvm_report))
        .route("/api/tee-report", get(api_tee_report))
        .route("/api/ak-cert", get(api_ak_cert))
        .route("/api/ak-pub", get(api_ak_pub))
        .route("/api/pcrs", get(api_pcrs))
        .route("/api/event-log", get(api_event_log))
        .route("/api/td-quote", get(api_td_quote))
        .route("/api/isolation-evidence", get(api_isolation_evidence))
        .route("/api/guest-attest", post(api_guest_attest))
        .route("/api/tee-attest", post(api_tee_attest))
        .route("/api/parse-token", post(api_parse_token));

    // Determine TLS mode
    let use_self_signed = cli.tls_self_signed || cli.tls_self_signed_dir.is_some();
    let tls_config: Option<Arc<rustls::ServerConfig>> = if use_self_signed {
        if cli.tls_cert.is_some() || cli.tls_key.is_some() {
            eprintln!(
                "Error: --tls-self-signed / --tls-self-signed-dir cannot be combined with --tls-cert / --tls-key"
            );
            std::process::exit(1);
        }
        // Extract the host part from the bind address (strip :port)
        let bind_host = cli
            .bind
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&cli.bind);

        let config = if let Some(ref dir) = cli.tls_self_signed_dir {
            // Persistent mode: load existing or generate + save
            let (cfg, loaded) = load_or_generate_self_signed(dir, bind_host, &cli.tls_san)
                .unwrap_or_else(|e| {
                    eprintln!("Self-signed certificate error: {e}");
                    std::process::exit(1);
                });
            if loaded {
                eprintln!("Loaded self-signed certificate from {}", dir.display());
            } else {
                eprintln!(
                    "Generated and saved self-signed certificate to {}",
                    dir.display()
                );
            }
            cfg
        } else {
            // Ephemeral mode
            let (_cert_pem, _key_pem, cfg) = generate_self_signed_config(bind_host, &cli.tls_san)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to generate self-signed certificate: {e}");
                    std::process::exit(1);
                });
            eprintln!("Generated ephemeral self-signed certificate (will change on restart)");
            cfg
        };

        // Display SANs
        let mut san_display = vec!["localhost", "127.0.0.1", "::1"];
        if !bind_host.is_empty() && bind_host != "0.0.0.0" && !san_display.contains(&bind_host) {
            san_display.push(bind_host);
        }
        for san in &cli.tls_san {
            if !san_display.iter().any(|s| s == san) {
                san_display.push(san);
            }
        }
        eprintln!("  SANs: {}", san_display.join(", "));
        Some(config)
    } else if let (Some(cert), Some(key)) = (&cli.tls_cert, &cli.tls_key) {
        let config = load_tls_config(cert, key).unwrap_or_else(|e| {
            eprintln!("TLS configuration error: {e}");
            std::process::exit(1);
        });
        Some(config)
    } else if cli.tls_cert.is_some() || cli.tls_key.is_some() {
        eprintln!("Error: --tls-cert and --tls-key must both be specified for HTTPS");
        std::process::exit(1);
    } else {
        if !cli.tls_san.is_empty() {
            eprintln!("Error: --tls-san can only be used with --tls-self-signed");
            std::process::exit(1);
        }
        None
    };

    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind to {}: {e}", cli.bind);
            std::process::exit(1);
        });

    if let Some(tls_config) = tls_config {
        eprintln!("╔══════════════════════════════════════════════════╗");
        eprintln!("║  Azure Guest Attestation — Web UI  (HTTPS)      ║");
        eprintln!("║  https://{:<38} ║", cli.bind);
        eprintln!("╚══════════════════════════════════════════════════╝");
        if use_self_signed {
            eprintln!("  ⚠  Self-signed cert — browser will show a warning.");
            eprintln!("     Accept it to proceed, or add the cert to your");
            eprintln!("     trust store for a clean experience.");
            if cli.tls_self_signed_dir.is_some() {
                eprintln!("     The cert is persistent and will be reused on restart.");
            } else {
                eprintln!("     Tip: use --tls-self-signed-dir <DIR> to persist the cert.");
            }
        }

        serve_https(listener, tls_config, app).await;
    } else {
        eprintln!("╔══════════════════════════════════════════════════╗");
        eprintln!("║  Azure Guest Attestation — Web UI               ║");
        eprintln!("║  http://{:<39} ║", cli.bind);
        eprintln!("╚══════════════════════════════════════════════════╝");

        axum::serve(listener, app).await.expect("Server error");
    }
}
