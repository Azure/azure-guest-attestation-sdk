// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local (offline) attestation verification.
//!
//! Cryptographically validates attestation evidence without a round-trip to
//! MAA: certificate-chain validation to a pinned hardware root and signature
//! verification of the report/quote.
//!
//! Gated behind backend-neutral `verify` plus explicit `native` or `symcrypt`.
//! Native uses OpenSSL on Linux and CNG/crypt32 on Windows. SymCrypt uses
//! WebPKI path building and SymCrypt signature verification on both platforms.

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("the `verify` feature currently supports Linux and Windows");

mod crypto;
mod roots;
pub mod snp;
pub mod tdx;

pub use snp::{verify_snp_report, SnpMeasurements, SnpVerifyPolicy, SnpVerifyResult};
pub use tdx::{verify_td_quote, TdxMeasurements, TdxVerifyPolicy, TdxVerifyResult};
