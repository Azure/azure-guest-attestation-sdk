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
// MAA endpoint defaults
// ---------------------------------------------------------------------------

/// Default API path for guest attestation (with TPM evidence).
const GUEST_ATTEST_PATH: &str = "/attest/AzureGuest";
/// Default API version for guest attestation.
const GUEST_ATTEST_API_VERSION: &str = "2020-10-01";
/// Default API path for TEE-only SNP attestation.
const TEE_SNP_PATH: &str = "/attest/SevSnpVm";
/// Default API path for TEE-only TDX attestation.
const TEE_TDX_PATH: &str = "/attest/TdxVm";
/// Default API version for TEE-only attestation.
const TEE_ATTEST_API_VERSION: &str = "2022-08-01";

/// If the endpoint URL looks like a bare base URL (no `/attest/` path),
/// append the given `path` and `api_version` query parameter.
///
/// When the URL already contains `/attest/`, it is returned unchanged so that
/// callers who supply a fully-qualified URL are unaffected.
fn resolve_maa_url(base: &str, path: &str, api_version: &str) -> String {
    if base.contains("/attest/") {
        return base.to_string();
    }
    let base = base.trim_end_matches('/');
    format!("{base}{path}?api-version={api_version}")
}

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
///
/// If only a base URL is provided (e.g.
/// `https://sharedeus.eus.attest.azure.net`), the guest attestation path
/// `/attest/AzureGuest?api-version=2020-10-01` is appended automatically.
/// When a full URL is supplied (containing `/attest/`), it is used as-is.
pub struct MaaProvider {
    client: Client,
    endpoint: String,
}

impl MaaProvider {
    /// Create a new MAA provider targeting the given endpoint URL.
    ///
    /// Accepts either a bare MAA base URL (e.g.
    /// `https://sharedeus.eus.attest.azure.net`) or a fully-qualified URL
    /// (e.g. `https://…/attest/AzureGuest?api-version=2020-10-01`). When
    /// only the base URL is given the default guest-attest path and
    /// api-version are appended.
    pub fn new(endpoint: impl Into<String>) -> Self {
        let raw: String = endpoint.into();
        let resolved = resolve_maa_url(&raw, GUEST_ATTEST_PATH, GUEST_ATTEST_API_VERSION);
        tracing::info!(target: "guest_attest", provider = "MAA", raw_endpoint = %raw, resolved_endpoint = %resolved, "MAA provider created");
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
            endpoint: resolved,
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
/// If only a base URL is provided (e.g.
/// `https://sharedeus.eus.attest.azure.net`), the correct TEE-only path
/// (`/attest/SevSnpVm` or `/attest/TdxVm`) and api-version are appended
/// automatically based on `report_type`. Fully-qualified URLs (containing
/// `/attest/`) are used as-is.
///
/// Returns the token string. If the response body is not JSON with a
/// `"token"` field the raw body is returned as the token string.
pub fn submit_tee_only(
    payload: &str,
    endpoint: &str,
    report_type: crate::report::CvmReportType,
) -> io::Result<String> {
    let mut timer = StageTimer::new();
    // Resolve the URL: append the correct TEE-only path when only a base URL is given.
    let tee_path = match report_type {
        crate::report::CvmReportType::SnpVmReport => TEE_SNP_PATH,
        _ => TEE_TDX_PATH,
    };
    let endpoint = resolve_maa_url(endpoint, tee_path, TEE_ATTEST_API_VERSION);
    // Best-effort endpoint / type sanity warnings
    if report_type == crate::report::CvmReportType::SnpVmReport && !endpoint.contains("SevSnpVm") {
        tracing::warn!(target: "guest_attest", %endpoint, "SNP evidence but endpoint name lacks 'SevSnpVm'");
    }
    if report_type == crate::report::CvmReportType::TdxVmReport && !endpoint.contains("TdxVm") {
        tracing::warn!(target: "guest_attest", %endpoint, "TDX evidence but endpoint name lacks 'TdxVm'");
    }
    let client = reqwest::blocking::Client::new();
    tracing::info!(target: "guest_attest", %endpoint, "POST tee-only attestation request");
    let resp = client
        .post(&endpoint)
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

    // resolve_maa_url
    #[test]
    fn resolve_base_url_appends_path() {
        let url = resolve_maa_url(
            "https://sharedeus.eus.attest.azure.net",
            GUEST_ATTEST_PATH,
            GUEST_ATTEST_API_VERSION,
        );
        assert_eq!(
            url,
            "https://sharedeus.eus.attest.azure.net/attest/AzureGuest?api-version=2020-10-01"
        );
    }

    #[test]
    fn resolve_base_url_trailing_slash() {
        let url = resolve_maa_url(
            "https://sharedeus.eus.attest.azure.net/",
            GUEST_ATTEST_PATH,
            GUEST_ATTEST_API_VERSION,
        );
        assert_eq!(
            url,
            "https://sharedeus.eus.attest.azure.net/attest/AzureGuest?api-version=2020-10-01"
        );
    }

    #[test]
    fn resolve_full_url_unchanged() {
        let full =
            "https://sharedeus.eus.attest.azure.net/attest/AzureGuest?api-version=2020-10-01";
        let url = resolve_maa_url(full, GUEST_ATTEST_PATH, GUEST_ATTEST_API_VERSION);
        assert_eq!(url, full);
    }

    #[test]
    fn resolve_full_url_custom_api_version_unchanged() {
        let full = "https://custom.attest.azure.net/attest/SevSnpVm?api-version=2023-04-01-preview";
        let url = resolve_maa_url(full, TEE_SNP_PATH, TEE_ATTEST_API_VERSION);
        assert_eq!(url, full);
    }

    #[test]
    fn resolve_tee_snp_path() {
        let url = resolve_maa_url(
            "https://sharedeus.eus.attest.azure.net",
            TEE_SNP_PATH,
            TEE_ATTEST_API_VERSION,
        );
        assert_eq!(
            url,
            "https://sharedeus.eus.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01"
        );
    }

    #[test]
    fn resolve_tee_tdx_path() {
        let url = resolve_maa_url(
            "https://sharedeus.eus.attest.azure.net",
            TEE_TDX_PATH,
            TEE_ATTEST_API_VERSION,
        );
        assert_eq!(
            url,
            "https://sharedeus.eus.attest.azure.net/attest/TdxVm?api-version=2022-08-01"
        );
    }

    #[test]
    fn maa_provider_resolves_base_url() {
        let provider = MaaProvider::new("https://example.attest.azure.net");
        assert_eq!(
            provider.endpoint,
            "https://example.attest.azure.net/attest/AzureGuest?api-version=2020-10-01"
        );
    }

    #[test]
    fn maa_provider_keeps_full_url() {
        let provider = MaaProvider::new(
            "https://example.attest.azure.net/attest/AzureGuest?api-version=2020-10-01",
        );
        assert_eq!(
            provider.endpoint,
            "https://example.attest.azure.net/attest/AzureGuest?api-version=2020-10-01"
        );
    }

    // -----------------------------------------------------------------------
    // submit_to_provider with LoopbackProvider
    // -----------------------------------------------------------------------

    #[test]
    fn submit_to_provider_loopback_returns_token() {
        let provider = LoopbackProvider;
        let result = submit_to_provider("test_request_data", &provider).unwrap();
        assert!(result.is_some());
        let token = result.unwrap();
        let decoded = base64_url_decode(&token).unwrap();
        let json_str = String::from_utf8(decoded).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["request"], "test_request_data");
    }

    // -----------------------------------------------------------------------
    // submit_to_provider with a failing provider (tests retry logic)
    // -----------------------------------------------------------------------

    struct FailingProvider {
        fail_count: std::cell::Cell<u32>,
        max_failures: u32,
    }

    impl AttestationProvider for FailingProvider {
        fn attest_guest(&self, encoded_request: &str) -> io::Result<Option<String>> {
            let current = self.fail_count.get();
            if current < self.max_failures {
                self.fail_count.set(current + 1);
                Err(io::Error::other("transient failure"))
            } else {
                Ok(Some(format!("success:{encoded_request}")))
            }
        }
    }

    #[test]
    fn submit_to_provider_retries_on_transient_failure() {
        let provider = FailingProvider {
            fail_count: std::cell::Cell::new(0),
            max_failures: 2, // fails twice, succeeds on 3rd attempt
        };
        let result = submit_to_provider("retry_test", &provider).unwrap();
        assert_eq!(result, Some("success:retry_test".to_string()));
        assert_eq!(provider.fail_count.get(), 2);
    }

    #[test]
    fn submit_to_provider_exhausts_retries_returns_error() {
        let provider = FailingProvider {
            fail_count: std::cell::Cell::new(0),
            max_failures: 10, // always fails, exceeds max_retries (3)
        };
        let result = submit_to_provider("exhaust_test", &provider);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("transient failure"));
    }

    /// Provider that always returns Ok(None)
    struct NoneProvider;

    impl AttestationProvider for NoneProvider {
        fn attest_guest(&self, _encoded_request: &str) -> io::Result<Option<String>> {
            Ok(None)
        }
    }

    #[test]
    fn submit_to_provider_none_result() {
        let provider = NoneProvider;
        let result = submit_to_provider("none_test", &provider).unwrap();
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // resolve_maa_url additional cases
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_maa_url_empty_base() {
        let url = resolve_maa_url("", GUEST_ATTEST_PATH, GUEST_ATTEST_API_VERSION);
        assert_eq!(url, "/attest/AzureGuest?api-version=2020-10-01");
    }

    #[test]
    fn resolve_maa_url_multiple_trailing_slashes() {
        let url = resolve_maa_url(
            "https://example.net///",
            GUEST_ATTEST_PATH,
            GUEST_ATTEST_API_VERSION,
        );
        assert_eq!(
            url,
            "https://example.net/attest/AzureGuest?api-version=2020-10-01"
        );
    }
}
