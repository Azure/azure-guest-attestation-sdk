// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TPM 2.0 interface for Azure Guest Attestation.
//!
//! This module re-exports the [`azure_tpm`] crate and extends it with
//! CVM-specific attestation functions that depend on the SDK's report
//! parsing types.
//!
//! # Example
//!
//! ```no_run
//! use azure_guest_attestation_sdk::tpm::{Tpm, TpmCommandExt};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Open the platform TPM
//!     let tpm = Tpm::open()?;
//!
//!     // Read PCR values
//!     let pcrs = tpm.read_pcrs_sha256(&[0, 1, 2, 7])?;
//!     for (index, digest) in &pcrs {
//!         println!("PCR{}: {}", index, hex::encode(digest));
//!     }
//!     Ok(())
//! }
//! ```

// Re-export sub-modules from the azure-tpm crate so that existing
// `azure_guest_attestation_sdk::tpm::commands::*` paths keep working.
pub use azure_tpm::commands;
pub use azure_tpm::device;
pub use azure_tpm::event_log;
pub use azure_tpm::helpers;
pub use azure_tpm::types;

/// Azure CVM-specific attestation operations built on top of [`azure_tpm`] TPM
/// primitives: AK management, PCR quotes, ephemeral keys, ECC signing,
/// CVM report parsing, and NV index operations.
pub mod attestation;

// Re-export commonly-used items at the `tpm` level.
pub use azure_tpm::commands::TpmCommandExt;
pub use azure_tpm::device::{RawTpm, Tpm};
pub use azure_tpm::types::TpmCommandCode;
