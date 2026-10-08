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
    parse_pem_chain, sha256, verify_cert_chain, Cert,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        // NIST FIPS 180-2 test vector for "abc".
        assert_eq!(
            hex::encode(sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
