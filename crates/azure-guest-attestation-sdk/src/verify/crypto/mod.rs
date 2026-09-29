// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-neutral cryptographic primitives for local attestation verification.
//!
//! The `verify` feature requires the `native` crypto backend, which is the
//! system OpenSSL on Linux and CNG (BCrypt) + CryptoAPI (crypt32) on Windows.
//! Both backends expose the same interface — an opaque [`Cert`] handle, SHA-2
//! hashing, raw ECDSA verification and certificate-chain validation against a
//! *pinned* set of trust anchors — so the SNP/TDX verifiers never name a
//! backend-specific type.

use std::io;

#[cfg(target_os = "linux")]
#[path = "openssl.rs"]
mod backend;

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod backend;

pub(crate) use backend::{
    cert_from_pem, cert_is_self_signed, cert_to_der, ecdsa_p256_verify_point, ecdsa_verify_raw,
    parse_pem_chain, sha256, verify_cert_chain, verify_cert_chain_at, Cert,
};

/// Message digest used by [`ecdsa_verify_raw`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DigestAlg {
    /// SHA-256 (Intel TDX).
    Sha256,
    /// SHA-384 (AMD SEV-SNP).
    Sha384,
}

fn other<E: std::fmt::Display>(ctx: &str, e: E) -> io::Error {
    io::Error::other(format!("{ctx}: {e}"))
}

/// Convert nonnegative Unix seconds to 100 ns ticks since 1601-01-01.
///
/// Both backends restrict explicit times to the Windows-safe FILETIME range
/// below 2^63 ticks (Unix seconds 0..=910_692_730_085). OpenSSL additionally
/// checks that seconds fit the platform's native `time_t`.
fn unix_time_to_filetime_ticks(unix_time: i64) -> io::Result<u64> {
    u64::try_from(unix_time)
        .ok()
        .and_then(|seconds| seconds.checked_add(11_644_473_600))
        .and_then(|seconds| seconds.checked_mul(10_000_000))
        .filter(|&ticks| ticks < (1u64 << 63))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "certificate validation time must be Unix seconds in 0..=910692730085",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_ticks_boundaries() {
        assert_eq!(
            unix_time_to_filetime_ticks(0).unwrap(),
            116_444_736_000_000_000
        );
        assert_eq!(
            unix_time_to_filetime_ticks(1).unwrap(),
            116_444_736_010_000_000
        );
        assert_eq!(
            unix_time_to_filetime_ticks(910_692_730_085).unwrap(),
            9_223_372_036_850_000_000
        );
        for time in [-1, i64::MIN, 910_692_730_086, i64::MAX] {
            assert_eq!(
                unix_time_to_filetime_ticks(time).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn sha256_known_answer() {
        // NIST FIPS 180-2 test vector for "abc".
        assert_eq!(
            hex::encode(sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
