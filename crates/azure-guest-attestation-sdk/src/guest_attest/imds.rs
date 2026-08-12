// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Instance Metadata Service (IMDS) client.
//!
//! Provides access to platform endorsements available through IMDS / THIM:
//!
//! - [`ImdsClient::get_vcek_chain`] — AMD SEV-SNP VCEK certificate chain.
//! - [`ImdsClient::get_td_quote`]   — Intel TDX TD Quote.

use reqwest::blocking::Client;
use std::io;
use std::time::Duration;

/// Subset IMDS client for platform endorsements (SNP VCEK chain + TDX quote).
///
/// Network errors are mapped to [`io::Error`].
pub struct ImdsClient {
    http: Client,
}

impl ImdsClient {
    /// Create a new IMDS client.
    ///
    /// A short connect timeout and an overall request timeout are configured
    /// so IMDS calls fail fast when running off-Azure (the link-local metadata
    /// address `169.254.169.254` is unreachable there). Without this, callers
    /// such as [`get_region`](Self::get_region) — and the CLI's endpoint
    /// auto-detection — could hang indefinitely instead of falling back.
    ///
    /// In the rare event the timed client fails to build, a warning is logged
    /// and an untimed default client is used as a last resort.
    pub fn new() -> Self {
        crate::ensure_crypto_provider();
        // Connect timeout fails fast when the metadata IP is unroutable;
        // the longer overall timeout accommodates TD Quote generation on Azure.
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    target: "guest_attest",
                    error = %e,
                    "failed to build IMDS HTTP client with timeouts; \
                     falling back to an untimed default client (requests may hang)"
                );
                Client::new()
            });
        Self { http }
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

    /// GET a URL with the IMDS `Metadata: true` header and return the response
    /// body as text. Errors on transport failure or a non-2xx status.
    ///
    /// Kept separate from [`get_region`](Self::get_region) so the network path
    /// can be mocked in unit tests (see the injectorpp tests in this module).
    fn get_text(&self, url: &str) -> io::Result<String> {
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
        resp.text()
            .map_err(|e| io::Error::other(format!("read body: {e}")))
    }

    /// Fetch the current VM's Azure region (e.g. `"eastus"`) from IMDS.
    ///
    /// Queries `instance/compute/location` in text form. The returned string
    /// is the region name as reported by the platform; callers typically pass
    /// it to [`maa_base_url_for_region`](crate::endpoint::maa_base_url_for_region).
    pub fn get_region(&self) -> io::Result<String> {
        const LOCATION_ENDPOINT: &str = "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-01-01&format=text";
        let region = self.get_text(LOCATION_ENDPOINT)?.trim().to_string();
        if region.is_empty() {
            return Err(io::Error::other("IMDS returned empty region"));
        }
        Ok(region)
    }

    /// Fetch the AMD SEV-SNP VCEK certificate chain from Azure THIM / IMDS.
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

    /// Fetch a TDX TD Quote from IMDS for the given TDX report bytes.
    pub fn get_td_quote(&self, report: &[u8]) -> io::Result<Vec<u8>> {
        // Trim to canonical TDX report size expected by IMDS.
        // Validation is in this thin wrapper so its stack frame stays small;
        // the heavy HTTP / base64 work lives in `fetch_td_quote_http` whose
        // frame is only allocated when we actually need the network call.
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
        self.fetch_td_quote_http(&report[..needed])
    }

    /// Post the (already-validated) TDX report to IMDS and return the quote.
    ///
    /// Separated from [`get_td_quote`] so that the large stack frame for
    /// reqwest responses, base64 buffers, and JSON values is only allocated
    /// when the caller actually reaches the network path.  With `opt-level = 0`
    /// (required by injectorpp in the test profile) the compiler does not
    /// shrink stack frames, and keeping everything in a single function caused
    /// stack overflows on Windows test threads.
    fn fetch_td_quote_http(&self, rep: &[u8]) -> io::Result<Vec<u8>> {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        const TDQUOTE_ENDPOINT: &str = "http://169.254.169.254/acc/tdquote";

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
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text_std) {
                if let Some(quote_enc) = v.get("quote").and_then(|x| x.as_str()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use injectorpp::interface::injector::*;
    use std::sync::Mutex;

    // injectorpp patches process-global memory, so tests that install mocks
    // must not run concurrently under `cargo test`. Serialize them behind a
    // shared mutex. `unwrap_or_else(into_inner)` recovers from poisoning so a
    // single failing/panicking test does not cascade into the others.
    static INJECT_MUTEX: Mutex<()> = Mutex::new(());

    fn inject_guard() -> std::sync::MutexGuard<'static, ()> {
        INJECT_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn imds_client_new_creates_instance() {
        let _client = ImdsClient::new();
    }

    #[test]
    fn imds_client_default_creates_instance() {
        let _client = ImdsClient::default();
    }

    #[test]
    fn get_td_quote_report_too_small() {
        let client = ImdsClient::new();
        let small_report = vec![0u8; 10]; // Much smaller than TDX_VM_REPORT_SIZE (1024)
        let err = client.get_td_quote(&small_report).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("too small"),
            "expected 'too small' error: {err}"
        );
    }

    // Helper: standalone replacement for ImdsClient::get_json that returns
    // a successful vcekCert + certificateChain response.
    fn fake_get_json_vcek_happy(_self: &ImdsClient, _url: &str) -> io::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "vcekCert": "-----BEGIN CERT-----\nfake-vcek\n-----END CERT-----\n",
            "certificateChain": "-----BEGIN CERT-----\nfake-chain\n-----END CERT-----\n"
        }))
    }

    #[test]
    fn get_vcek_chain_happy_path() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_json))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_get_json_vcek_happy));
        }
        let client = ImdsClient::new();
        let result = client.get_vcek_chain().unwrap();
        let expected = b"-----BEGIN CERT-----\nfake-vcek\n-----END CERT-----\n\
                         -----BEGIN CERT-----\nfake-chain\n-----END CERT-----\n";
        assert_eq!(result, expected);
    }

    fn fake_get_json_missing_fields(
        _self: &ImdsClient,
        _url: &str,
    ) -> io::Result<serde_json::Value> {
        // Response has no vcekCert or certificateChain fields
        Ok(serde_json::json!({"status": "ok"}))
    }

    #[test]
    fn get_vcek_chain_missing_fields_returns_empty() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_json))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(
                    fake_get_json_missing_fields
                ));
        }
        let client = ImdsClient::new();
        let result = client.get_vcek_chain().unwrap();
        // Both fields default to "" so the result is empty
        assert!(result.is_empty());
    }

    fn fake_get_json_error(_self: &ImdsClient, _url: &str) -> io::Result<serde_json::Value> {
        Err(io::Error::other("network unreachable"))
    }

    #[test]
    fn get_vcek_chain_error_propagates() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_json))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_get_json_error));
        }
        let client = ImdsClient::new();
        let err = client.get_vcek_chain().unwrap_err();
        assert!(
            err.to_string().contains("network unreachable"),
            "expected propagated error: {err}"
        );
    }

    fn fake_get_json_partial_fields(
        _self: &ImdsClient,
        _url: &str,
    ) -> io::Result<serde_json::Value> {
        // Only vcekCert present, no certificateChain
        Ok(serde_json::json!({"vcekCert": "only-vcek"}))
    }

    #[test]
    fn get_vcek_chain_partial_fields() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_json))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(
                    fake_get_json_partial_fields
                ));
        }
        let client = ImdsClient::new();
        let result = client.get_vcek_chain().unwrap();
        // certificateChain defaults to ""
        assert_eq!(result, b"only-vcek");
    }

    // ---- get_region: mock the private get_text helper ----------------------

    fn fake_get_text_region(_self: &ImdsClient, _url: &str) -> io::Result<String> {
        // Whitespace around the region should be trimmed.
        Ok("  eastus\n".to_string())
    }

    #[test]
    fn get_region_success_trims_body() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_text))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_get_text_region));
        }
        let client = ImdsClient::new();
        assert_eq!(client.get_region().unwrap(), "eastus");
    }

    fn fake_get_text_empty(_self: &ImdsClient, _url: &str) -> io::Result<String> {
        Ok("   \n".to_string())
    }

    #[test]
    fn get_region_empty_body_errors() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_text))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_get_text_empty));
        }
        let client = ImdsClient::new();
        let err = client.get_region().unwrap_err();
        assert!(
            err.to_string().contains("empty region"),
            "expected empty-region error: {err}"
        );
    }

    fn fake_get_text_status_error(_self: &ImdsClient, _url: &str) -> io::Result<String> {
        // Simulates the non-2xx branch inside get_text.
        Err(io::Error::other("status 404 Not Found"))
    }

    #[test]
    fn get_region_non_success_status_propagates() {
        let _guard = inject_guard();
        let mut injector = InjectorPP::new();
        unsafe {
            injector
                .when_called_unchecked(injectorpp::func_unchecked!(ImdsClient::get_text))
                .will_execute_raw_unchecked(injectorpp::func_unchecked!(
                    fake_get_text_status_error
                ));
        }
        let client = ImdsClient::new();
        let err = client.get_region().unwrap_err();
        assert!(
            err.to_string().contains("status 404"),
            "expected propagated status error: {err}"
        );
    }
}
