// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Platform-agnostic TPM 2.0 command interface for Azure guest VMs.
//!
//! This crate provides a platform-agnostic TPM 2.0 interface. It includes:
//!
//! - **Device access** ([`device`]): Platform-agnostic TPM device communication
//! - **Commands** ([`commands`]): High-level TPM command implementations via [`TpmCommandExt`]
//! - **Types** ([`types`]): TPM 2.0 data structures and marshaling
//! - **Helpers** ([`helpers`]): Internal utilities for command building
//! - **Event log** ([`event_log`]): TCG event log parsing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         TpmCommandExt Trait             │
//! │  (create_primary, sign, quote, etc.)    │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │           RawTpm Trait                  │
//! │        (transmit_raw bytes)             │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │    Platform TPM Driver / vTPM / Ref     │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```no_run
//! use azure_tpm::{Tpm, TpmCommandExt};
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

/// High-level TPM command implementations.
pub mod commands;
/// Platform-agnostic TPM device communication.
pub mod device;
/// TCG event log parsing.
pub mod event_log;
/// Internal utilities for command building.
pub mod helpers;
/// TPM 2.0 data structures and marshaling.
pub mod types;

pub use commands::TpmCommandExt;
pub use device::{RawTpm, Tpm};
pub use types::TpmCommandCode;
