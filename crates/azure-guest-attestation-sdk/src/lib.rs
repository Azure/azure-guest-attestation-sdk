// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Missing rustdoc on public items is allowed for the initial v0.1 release.
// Comprehensive documentation will be added in a follow-up pass.
#![allow(missing_docs)]

//! Azure Guest Attestation SDK
//!
//! This crate provides attestation capabilities for Azure Virtual Machines,
//! including Confidential VMs (Intel TDX, AMD SEV-SNP, VBS) and
//! TrustedLaunch VMs.
//!
//! # Quick start
//!
//! ```ignore
//! use azure_guest_attestation_sdk::{AttestationClient, Provider};
//!
//! // Create a client (owns TPM internally)
//! let client = AttestationClient::new()?;
//!
//! // One-shot attestation against MAA
//! let result = client.attest_guest(
//!     Provider::maa("https://sharedeus.eus.attest.azure.net/attest/SevSnpVm"),
//!     None,
//! )?;
//! println!("Token: {}", result.token.unwrap_or_default());
//! ```
//!
//! # Layered API
//!
//! The SDK offers multiple levels of abstraction:
//!
//! | Level | Entry point | Description |
//! |-------|------------|-------------|
//! | **High** | [`AttestationClient::attest_guest`] | One-shot: collect evidence → build report → submit → token |
//! | **Mid** | [`AttestationClient::get_cvm_evidence`], [`get_device_evidence`](AttestationClient::get_device_evidence), [`create_attestation_report`](AttestationClient::create_attestation_report) | Collect and assemble artifacts separately |
//! | **Low** | [`tpm`], [`tee_report`], [`report`] | Direct TPM commands, TEE report parsing |
//! | **Parse** | [`parse`] | Stateless parsing of reports, quotes, and tokens |

// ---- Public API modules ---------------------------------------------------
pub mod client;
pub mod parse;

// ---- Internal implementation modules (still public for advanced users) -----
pub mod guest_attest;
pub mod report;
pub mod tee_report;
pub mod tpm;

// ---- Re-exports: primary public API at crate root -------------------------
pub use client::{
    AttestOptions, AttestResult, AttestationClient, AttestationReport, CvmEvidence,
    CvmEvidenceOptions, DeviceEvidence, DeviceEvidenceOptions, DeviceType, Endorsement,
    EndorsementKind, Provider,
};
pub use parse::TokenClaims;

use std::io::Write;
use std::sync::Once;
use tracing_subscriber::prelude::*;

static INIT_TRACING: Once = Once::new();

/// Wrapper around [`std::io::Stderr`] that calls `flush()` on drop.
///
/// Geneva and similar log-collection agents can miss events when a process
/// exits or crashes if the underlying writer is buffered.  Wrapping stderr
/// in this newtype guarantees a flush after every formatted tracing event.
struct FlushOnDropStderr(std::io::Stderr);

impl std::io::Write for FlushOnDropStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Drop for FlushOnDropStderr {
    fn drop(&mut self) {
        let _ = self.0.flush();
    }
}

/// Initialize global tracing subscriber (idempotent).
///
/// Default level: INFO.  Override via `AZURE_GUEST_ATTESTATION_LOG` or `RUST_LOG`.
///
/// Set `AZURE_GUEST_ATTESTATION_LOG_FORMAT=json` for JSON-structured output
/// (recommended for Geneva / structured-log collectors).
pub fn init_tracing() {
    INIT_TRACING.call_once(|| {
        // Default level INFO; allow override via AZURE_GUEST_ATTESTATION_LOG or RUST_LOG.
        let env_var = std::env::var("AZURE_GUEST_ATTESTATION_LOG").ok();
        let default = "info".to_string();
        let filter = env_var
            .or_else(|| std::env::var("RUST_LOG").ok())
            .unwrap_or(default);

        let use_json = std::env::var("AZURE_GUEST_ATTESTATION_LOG_FORMAT")
            .map(|v| v.eq_ignore_ascii_case("json"))
            .unwrap_or(false);

        // Use Option<Layer> pattern so only the chosen format is active.
        let json_layer = use_json.then(|| {
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_level(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_writer(|| FlushOnDropStderr(std::io::stderr()))
        });

        let text_layer = (!use_json).then(|| {
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_writer(|| FlushOnDropStderr(std::io::stderr()))
        });

        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(filter))
            .with(json_layer)
            .with(text_layer);
        let _ = tracing::subscriber::set_global_default(subscriber);
        tracing::info!(target: "guest_attest", "tracing initialized");
    });
}
