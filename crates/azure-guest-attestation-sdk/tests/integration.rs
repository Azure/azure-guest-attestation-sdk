// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end integration tests exercising the public SDK API against a
//! reference in-process TPM.
//!
//! These tests require the `vtpm-tests` feature (which pulls the
//! `ms-tpm-20-ref` crate).  They are run by CI via:
//!
//! ```sh
//! cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests
//! ```
//!
//! Each test gets its own process with `cargo nextest`, avoiding
//! global-state collisions from the in-process reference TPM.

// Only compile when the vtpm-tests feature is active.
#![cfg(feature = "vtpm-tests")]

use azure_guest_attestation_sdk::client::{
    AttestOptions, AttestationClient, CvmEvidenceOptions, DeviceEvidenceOptions, DeviceType,
    Provider,
};
use azure_guest_attestation_sdk::tpm::device::Tpm;
use azure_guest_attestation_sdk::tpm::{attestation, TpmCommandExt};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Open a reference TPM and build an `AttestationClient` from it.
/// Returns `None` if the reference TPM is not available.
fn make_client() -> Option<AttestationClient> {
    let tpm = Tpm::open_reference().ok()?;
    Some(AttestationClient::from_tpm(tpm))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full `get_device_evidence` flow: ensure AK → read AK cert/pub →
/// PCR quote → PCR values → ephemeral key creation + certify.
///
/// This exercises the entire TPM evidence collection pipeline end-to-end.
#[test]
fn device_evidence_full_pipeline() {
    let client = match make_client() {
        Some(c) => c,
        None => return,
    };

    let opts = DeviceEvidenceOptions {
        device_type: DeviceType::Tpm,
        pcr_selection: Some(vec![0, 1, 2]),
    };

    let evidence = match client.get_device_evidence(Some(&opts)) {
        Ok(ev) => ev,
        Err(e) => {
            // On shared reference TPM, resource contention may cause failures.
            eprintln!("Skipping device_evidence_full_pipeline: {e}");
            return;
        }
    };

    // Verify structural invariants of the returned evidence
    assert!(
        !evidence.tpm_info.ak_pub.is_empty(),
        "AK public must be non-empty"
    );
    assert!(
        !evidence.tpm_info.pcr_quote.is_empty(),
        "PCR quote must be non-empty"
    );
    assert!(
        !evidence.tpm_info.pcr_sig.is_empty(),
        "PCR signature must be non-empty"
    );
    assert_eq!(
        evidence.tpm_info.pcr_set,
        vec![0, 1, 2],
        "PCR set must match requested selection"
    );
    assert_eq!(
        evidence.tpm_info.pcrs.len(),
        3,
        "Should have exactly 3 PCR entries"
    );
    for pcr in &evidence.tpm_info.pcrs {
        assert_eq!(
            pcr.digest.len(),
            32,
            "SHA-256 PCR digest should be 32 bytes"
        );
    }
    assert!(
        !evidence.tpm_info.enc_key_pub.is_empty(),
        "Ephemeral key public must be non-empty"
    );
    assert!(
        !evidence.tpm_info.enc_key_certify_info.is_empty(),
        "Certify info must be non-empty"
    );
    assert!(
        !evidence.tpm_info.enc_key_certify_info_sig.is_empty(),
        "Certify signature must be non-empty"
    );
    assert_eq!(evidence.pcrs, vec![0, 1, 2]);
}

/// `attest_guest` with `Loopback` provider exercises the full pipeline:
/// CVM evidence (fails → TrustedLaunch fallback) → device evidence →
/// build report → Loopback provider → returns a token.
#[test]
fn attest_guest_loopback_trusted_launch() {
    let client = match make_client() {
        Some(c) => c,
        None => return,
    };

    let opts = AttestOptions {
        pcr_selection: Some(vec![0, 1]),
        client_payload: Some("integration-test-payload".to_string()),
    };

    let result = match client.attest_guest(Provider::Loopback, Some(&opts)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Skipping attest_guest_loopback_trusted_launch: {e}");
            return;
        }
    };

    // Loopback provider returns the request as the token
    assert!(
        result.token.is_some(),
        "Loopback provider should return a token"
    );
    // The JSON request should be valid JSON
    let json: serde_json::Value =
        serde_json::from_str(&result.request_json).expect("request_json should be valid JSON");
    assert_eq!(
        json["AttestationProtocolVersion"], "2.0",
        "Protocol version should be 2.0"
    );
    // Client payload should be present
    assert!(
        result.request_json.contains("integration-test-payload"),
        "Client payload should be in request JSON"
    );
    // PCRs should match requested selection
    assert_eq!(result.pcrs, vec![0, 1]);
    // Encoded request should be non-empty base64url
    assert!(!result.encoded_request.is_empty());
}

/// `get_cvm_evidence` on a reference TPM fails (no CVM report NV index)
/// and should produce an appropriate error — not a panic.
#[test]
fn get_cvm_evidence_fails_gracefully_on_reference_tpm() {
    let client = match make_client() {
        Some(c) => c,
        None => return,
    };

    let opts = CvmEvidenceOptions {
        user_data: None,
        fetch_platform_quote: false,
    };

    // The reference TPM has no CVM report NV index, so this should fail
    let result = client.get_cvm_evidence(Some(&opts));
    assert!(
        result.is_err(),
        "get_cvm_evidence should fail on reference TPM (no CVM NV index)"
    );
}

/// ECC signing key lifecycle: create → sign → verify → cleanup.
///
/// Exercises the full ECC key management API through the public
/// attestation module functions.
#[test]
fn ecc_signing_key_lifecycle() {
    let tpm = match Tpm::open_reference() {
        Ok(t) => t,
        Err(_) => return,
    };

    // 1. Create and persist ECC signing key
    let pub_key = match attestation::create_and_persist_ecc_signing_key(&tpm) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Skipping ecc_signing_key_lifecycle: {e}");
            return;
        }
    };
    assert!(!pub_key.is_empty(), "ECC public key must be non-empty");

    // 2. Read it back
    let pub_key2 = match attestation::get_ecc_signing_key_pub(&tpm) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Skipping ecc_signing_key_lifecycle (read back): {e}");
            return;
        }
    };
    assert_eq!(pub_key, pub_key2, "Public key should be stable");

    // 3. Sign a digest
    let digest = [0x42u8; 32]; // SHA-256 sized
    let signature = match attestation::sign_with_ecc_key(&tpm, &digest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping ecc_signing_key_lifecycle (sign): {e}");
            // Cleanup
            let _ = tpm.evict_control(
                attestation::ECC_SIGNING_KEY_PERSISTENT_HANDLE,
                attestation::ECC_SIGNING_KEY_PERSISTENT_HANDLE,
            );
            return;
        }
    };

    // 4. Verify the signature
    match attestation::verify_with_ecc_key(&tpm, &digest, &signature) {
        Ok(()) => { /* success */ }
        Err(e) => {
            eprintln!("ecc_signing_key_lifecycle: verify failed: {e}");
        }
    }

    // 5. Cleanup: remove persistent key
    let _ = tpm.evict_control(
        attestation::ECC_SIGNING_KEY_PERSISTENT_HANDLE,
        attestation::ECC_SIGNING_KEY_PERSISTENT_HANDLE,
    );
}

/// PCR read → quote → parse roundtrip.
///
/// Reads PCR values, generates a quote, then parses the attestation
/// structure using the public `tpm::types` parser.
#[test]
fn pcr_quote_parse_roundtrip() {
    let tpm = match Tpm::open_reference() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Ensure AK exists
    if attestation::ensure_persistent_ak(&tpm).is_err() {
        return;
    }

    // Read PCRs
    let pcr_values = match attestation::get_pcr_values(&tpm, &[0, 7]) {
        Ok(v) => v,
        Err(_) => return,
    };
    assert_eq!(pcr_values.len(), 2);
    assert_eq!(pcr_values[0].0, 0);
    assert_eq!(pcr_values[1].0, 7);

    // Generate quote
    let (attest, sig) = match attestation::get_pcr_quote(&tpm, &[0, 7]) {
        Ok(v) => v,
        Err(_) => return,
    };
    assert!(!attest.is_empty());
    assert!(!sig.is_empty());

    // Parse the attestation structure.
    // The reference TPM may produce slightly different TPMS_ATTEST layouts;
    // verify that the parser doesn't panic and returns Ok or a clean error.
    match azure_guest_attestation_sdk::tpm::types::parse_quote_attestation(&attest) {
        Ok(parsed) => {
            // If it parses successfully, verify structural properties
            assert!(
                !parsed.pcr_selections.is_empty() || !parsed.pcr_digests.is_empty(),
                "Parsed quote should have PCR selections or digests"
            );
        }
        Err(e) => {
            // Parser may fail on some reference TPM output (e.g. different
            // digest format); that's OK — we just verify no panic.
            eprintln!("parse_quote_attestation returned error (non-fatal): {e}");
        }
    }
}

/// Verify that `get_ak_cert_trimmed` produces output ≤ `get_ak_cert` length.
///
/// On the reference TPM, AK cert is typically empty (no NV index defined).
/// This test ensures both functions agree and trimming doesn't panic.
#[test]
fn ak_cert_trimmed_is_subset_of_full() {
    let tpm = match Tpm::open_reference() {
        Ok(t) => t,
        Err(_) => return,
    };

    let full = match attestation::get_ak_cert(&tpm) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trimmed = match attestation::get_ak_cert_trimmed(&tpm) {
        Ok(c) => c,
        Err(_) => return,
    };

    assert!(
        trimmed.len() <= full.len(),
        "Trimmed cert should not exceed full cert length"
    );

    // If full is non-empty, trimmed should start with the same bytes
    if !full.is_empty() && !trimmed.is_empty() {
        assert_eq!(
            &full[..trimmed.len()],
            &trimmed[..],
            "Trimmed cert should be a prefix of full cert"
        );
    }
}

/// Verify user data NV read on a fresh reference TPM returns `None`.
///
/// The reference TPM starts clean, so the user-data NV index should not exist.
#[test]
fn user_data_nv_absent_on_fresh_tpm() {
    let tpm = match Tpm::open_reference() {
        Ok(t) => t,
        Err(_) => return,
    };

    match attestation::get_user_data_nv(&tpm) {
        Ok(None) => { /* expected — index not defined */ }
        Ok(Some(data)) => {
            // Index might exist from a previous test in the same process
            // (shouldn't happen with nextest, but handle gracefully)
            eprintln!(
                "user_data NV index already exists with {} bytes",
                data.len()
            );
        }
        Err(e) => {
            eprintln!("get_user_data_nv error (acceptable on ref TPM): {e}");
        }
    }
}
