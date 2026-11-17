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

const THROTTLE_MAX_ATTEMPTS: u32 = 4;
const THROTTLE_BASE_DELAY: Duration = Duration::from_secs(2);

// IMDS documents HTTP 429 for throttling:
// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#rate-limiting
// HTTP 403 with RequestRateLimitExceeded is based on testing the IMDS /acc/tdquote endpoint.
fn is_throttled(status: reqwest::StatusCode, body: &str) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || (status == reqwest::StatusCode::FORBIDDEN && body.contains("RequestRateLimitExceeded"))
}

fn throttle_delay(attempt: u32, retry_after: Option<&reqwest::header::HeaderValue>) -> Duration {
    retry_after
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|s| Duration::from_secs(s.min(60)))
        .unwrap_or(THROTTLE_BASE_DELAY * 2u32.pow(attempt - 1))
}

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
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be initialized. There is no untimed
    /// fallback and no fallback to another cryptographic backend.
    pub fn new() -> Self {
        // Connect timeout fails fast when the metadata IP is unroutable;
        // the longer overall timeout accommodates TD Quote generation on Azure.
        let http = crate::crypto::http_client_builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("initialize IMDS HTTP client with timeouts and selected crypto backend");
        Self { http }
    }

    fn get_json(&self, url: &str) -> io::Result<serde_json::Value> {
        let mut attempt = 1;
        let resp = loop {
            let resp = self
                .http
                .get(url)
                .header("Metadata", "true")
                .send()
                .map_err(|e| io::Error::other(format!("http error: {e}")))?;
            if resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS
                || attempt >= THROTTLE_MAX_ATTEMPTS
            {
                break resp;
            }
            std::thread::sleep(throttle_delay(
                attempt,
                resp.headers().get(reqwest::header::RETRY_AFTER),
            ));
            attempt += 1;
        };
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
        let mut attempt = 1;
        let (status_std, text_std) = loop {
            let resp_std = self
                .http
                .post(TDQUOTE_ENDPOINT)
                .header("Metadata", "true")
                .json(&body_std)
                .send()
                .map_err(|e| io::Error::other(format!("tdquote http (std b64) error: {e}")))?;
            let status = resp_std.status();
            let retry_after = resp_std
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .cloned();
            let text = resp_std.text().unwrap_or_default();
            if !is_throttled(status, &text) || attempt >= THROTTLE_MAX_ATTEMPTS {
                break (status, text);
            }
            std::thread::sleep(throttle_delay(attempt, retry_after.as_ref()));
            attempt += 1;
        };
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

        // Still throttled: a URL-safe re-POST would only consume another rate-limit slot.
        if is_throttled(status_std, &text_std) {
            return Err(io::Error::other(format!(
                "tdquote throttled (status {status_std}) after {attempt} attempts: {text_std}"
            )));
        }

        // Fallback attempt: URL safe no pad (some older docs/examples)
        let url_b64 = URL_SAFE_NO_PAD.encode(rep);
        let body_url = serde_json::json!({"report": url_b64});
        let mut attempt = 1;
        let (status_url, text_url) = loop {
            let resp_url = self
                .http
                .post(TDQUOTE_ENDPOINT)
                .header("Metadata", "true")
                .json(&body_url)
                .send()
                .map_err(|e| io::Error::other(format!("tdquote http (url b64) error: {e}")))?;
            let status = resp_url.status();
            let retry_after = resp_url
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .cloned();
            let text = resp_url.text().unwrap_or_default();
            if !is_throttled(status, &text) || attempt >= THROTTLE_MAX_ATTEMPTS {
                break (status, text);
            }
            std::thread::sleep(throttle_delay(attempt, retry_after.as_ref()));
            attempt += 1;
        };
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

        if is_throttled(status_url, &text_url) {
            return Err(io::Error::other(format!(
                "tdquote fallback throttled (status {status_url}) after {attempt} attempts: {text_url}"
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

    #[test]
    fn is_throttled_matches_imds_and_wireserver() {
        use reqwest::StatusCode;
        assert!(is_throttled(StatusCode::TOO_MANY_REQUESTS, ""));
        assert!(is_throttled(
            StatusCode::FORBIDDEN,
            "<Error><Code>RequestRateLimitExceeded</Code></Error>"
        ));
        assert!(!is_throttled(
            StatusCode::FORBIDDEN,
            "<Error><Code>Forbidden</Code></Error>"
        ));
        assert!(!is_throttled(StatusCode::BAD_REQUEST, ""));
        assert!(!is_throttled(StatusCode::OK, ""));
    }

    #[test]
    fn throttle_delay_backoff_and_retry_after() {
        use reqwest::header::HeaderValue;
        assert_eq!(throttle_delay(1, None), Duration::from_secs(2));
        assert_eq!(throttle_delay(3, None), Duration::from_secs(8));
        assert_eq!(
            throttle_delay(1, Some(&HeaderValue::from_static("5"))),
            Duration::from_secs(5)
        );
        assert_eq!(
            throttle_delay(1, Some(&HeaderValue::from_static("600"))),
            Duration::from_secs(60)
        );
        assert_eq!(
            throttle_delay(2, Some(&HeaderValue::from_static("soon"))),
            Duration::from_secs(4)
        );
    }

    fn tdquote_with_responses(
        responses: Vec<(u16, &'static str)>,
    ) -> (io::Result<Vec<u8>>, Vec<String>) {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = ImdsClient {
            http: crate::crypto::http_client_builder()
                .no_proxy()
                .proxy(
                    reqwest::Proxy::http(format!("http://{}", listener.local_addr().unwrap()))
                        .unwrap(),
                )
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        };
        let finished = Arc::new(AtomicBool::new(false));
        let server_finished = Arc::clone(&finished);
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            while !server_finished.load(Ordering::Acquire) {
                let (stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("accept test request: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut stream = BufReader::new(stream);
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(stream.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0; content_length];
                stream.read_exact(&mut body).unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                requests.push(body["report"].as_str().unwrap().to_owned());
                let (status, body) = responses
                    .get(requests.len() - 1)
                    .expect("unexpected extra tdquote request");
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nRetry-After: 0\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            requests
        });
        let report = vec![0xfb; crate::report::TDX_VM_REPORT_SIZE];
        let result = client.get_td_quote(&report);
        finished.store(true, Ordering::Release);
        let requests = server.join().unwrap();
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        assert_eq!(requests[0], STANDARD.encode(&report));
        let fallback_report = URL_SAFE_NO_PAD.encode(&report);
        assert!(requests.iter().skip(1).all(|body| body == &fallback_report));
        (result, requests)
    }

    #[test]
    fn tdquote_fallback_retries_throttling_then_succeeds() {
        for throttle in [(429, "throttled"), (403, "RequestRateLimitExceeded")] {
            let (result, requests) = tdquote_with_responses(vec![
                (400, "unsupported encoding"),
                throttle,
                (200, r#"{"quote":"AQID"}"#),
            ]);
            assert_eq!(result.unwrap(), [1, 2, 3]);
            assert_eq!(requests.len(), 3);
        }
    }

    #[test]
    fn tdquote_fallback_stops_after_four_throttled_attempts() {
        for throttle in [(429, "throttled"), (403, "RequestRateLimitExceeded")] {
            let mut responses = vec![(400, "unsupported encoding")];
            responses.extend([throttle; 4]);
            let (result, requests) = tdquote_with_responses(responses);
            assert_eq!(requests.len(), 5);
            let error = result.unwrap_err().to_string();
            assert!(error.contains("tdquote fallback throttled"), "{error}");
            assert!(error.contains("after 4 attempts"), "{error}");
            assert!(error.contains(throttle.1), "{error}");
        }
    }

    #[test]
    fn tdquote_fallback_does_not_retry_plain_forbidden() {
        let (result, requests) =
            tdquote_with_responses(vec![(400, "unsupported encoding"), (403, "Forbidden")]);
        assert_eq!(requests.len(), 2);
        assert_eq!(
            result.unwrap_err().to_string(),
            "tdquote failed (std status 400 Bad Request, fallback status 403 Forbidden) std_body='unsupported encoding' fallback_body='Forbidden'"
        );
    }

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
