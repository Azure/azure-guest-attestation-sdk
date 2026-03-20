// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Attestation provider abstractions and implementations.
//!
//! This module defines the [`AttestationProvider`] trait and its concrete
//! implementations:
//!
//! - [`MaaProvider`] — submits attestation requests to Microsoft Azure
//!   Attestation (MAA) endpoints.
//! - [`LoopbackProvider`] — echoes the request back as a JSON token
//!   (useful for testing and diagnostics).
//!
//! It also provides [`submit_to_provider`] for retry-wrapped submission
//! and [`submit_tee_only`] for TEE-only platform attestation.

use reqwest::blocking::Client;
use std::time::Duration;
use std::{io, thread};

use super::{base64_url_encode, StageTimer};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Attestation provider abstraction.
///
/// Implementations receive a base64url-encoded guest attestation request and
/// return the provider's response token (also base64url-encoded).
pub trait AttestationProvider {
    /// Submit an encoded attestation request and return the provider's token.
    fn attest_guest(&self, encoded_request: &str) -> io::Result<Option<String>>;
}

// ---------------------------------------------------------------------------
// LoopbackProvider
// ---------------------------------------------------------------------------

/// Dummy provider that echoes back the request embedded in a JSON token.
///
/// Useful for testing and diagnostics without network access.
pub struct LoopbackProvider;

impl AttestationProvider for LoopbackProvider {
    fn attest_guest(&self, encoded_request: &str) -> io::Result<Option<String>> {
        let token = serde_json::json!({"loopback": true, "request": encoded_request});
        Ok(Some(base64_url_encode(token.to_string().as_bytes())))
    }
}

// ---------------------------------------------------------------------------
// MaaProvider
// ---------------------------------------------------------------------------

/// Microsoft Azure Attestation (MAA) provider implementation.
///
/// Posts the base64url-encoded request as JSON to a supplied endpoint and
/// expects a JWT token string in response (under JSON field `"token"`, or
/// the raw body as fallback).
pub struct MaaProvider {
    client: Client,
    endpoint: String,
}

impl MaaProvider {
    /// Create a new MAA provider targeting the given endpoint URL.
    pub fn new(endpoint: impl Into<String>) -> Self {
        // Extended timeout (5 minutes) to accommodate potentially slow responses.
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
        // Trace response headers (redact sensitive values)
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

// ---------------------------------------------------------------------------
// Submission helpers
// ---------------------------------------------------------------------------

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

/// Submit a TEE-only JSON payload to a MAA platform endpoint.
///
/// Returns the token string. If the response body is not JSON with a
/// `"token"` field the raw body is returned as the token string.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_attest::base64_url_decode;

    #[test]
    fn loopback_provider_returns_token() {
        let provider = LoopbackProvider;
        let result = provider.attest_guest("test_request").unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        let decoded = base64_url_decode(&token).unwrap();
        let json_str = String::from_utf8(decoded).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["loopback"], true);
        assert_eq!(v["request"], "test_request");
    }
}
