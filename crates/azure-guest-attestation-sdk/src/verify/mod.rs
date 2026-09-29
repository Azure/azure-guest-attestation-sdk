// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local (offline) attestation verification.
//!
//! Cryptographically validates attestation evidence without a round-trip to
//! MAA: certificate-chain validation to a pinned hardware root and signature
//! verification of the report/quote.
//!
//! Gated behind the `verify` feature, which requires the `native` crypto
//! backend: system OpenSSL on Linux, CNG (BCrypt) + CryptoAPI (crypt32) on
//! Windows.

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("the `verify` feature requires Linux (OpenSSL) or Windows (CNG/crypt32)");

mod crypto;
mod roots;
pub mod snp;
pub mod tdx;
pub mod tdx_tcb;

pub use snp::{verify_snp_report, SnpMeasurements, SnpVerifyPolicy, SnpVerifyResult};
pub use tdx::{verify_td_quote, TdxMeasurements, TdxVerifyPolicy, TdxVerifyResult};
pub use tdx_tcb::{
    verify_td_quote_with_collateral, TcbAssessment, TcbStatus, TdxCollateral,
    TdxCollateralVerifyResult, TdxTcbPolicy, TdxTcbResult,
};
