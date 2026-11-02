// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-selected hashing and session entropy.
//!
//! SHA-1 is required here only because the TPM exposes a legacy SHA-1 PCR
//! bank whose values must be replayed byte-for-byte during TCG event-log
//! verification — it is a wire-format requirement, not a security choice.
//!
//! - **default (`rustcrypto`)**: the pure-Rust `sha1` crate. Portable, no C
//!   toolchain, published to crates.io.
//! - **`native`**: platform crypto — OpenSSL on Linux, CNG/BCrypt on Windows —
//!   so the shipped binary carries no RustCrypto SHA-1 implementation.
//! - **`symcrypt`**: explicitly linked SymCrypt for all hashes and entropy.
//!
//! `native` retains precedence over `rustcrypto`. SymCrypt is mutually exclusive
//! with either backend. At least one backend must be selected.

#[cfg(all(feature = "symcrypt", any(feature = "native", feature = "rustcrypto")))]
compile_error!(
    "`symcrypt` cannot be combined with `native` or `rustcrypto`; disable default features"
);

#[cfg(not(any(feature = "native", feature = "rustcrypto", feature = "symcrypt")))]
compile_error!("azure-tpm requires `rustcrypto` (default), `native`, or `symcrypt`");

/// Compute the SHA-1 digest of `parts` concatenated in order (20 bytes).
#[cfg(all(not(feature = "native"), feature = "rustcrypto"))]
pub(crate) fn sha1_concat(parts: &[&[u8]]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

#[cfg(feature = "symcrypt")]
pub(crate) fn sha1_concat(parts: &[&[u8]]) -> Vec<u8> {
    symcrypt::hash::sha1(&parts.concat()).to_vec()
}

pub(crate) fn sha256_concat(parts: &[&[u8]]) -> Vec<u8> {
    #[cfg(feature = "symcrypt")]
    {
        symcrypt::hash::sha256(&parts.concat()).to_vec()
    }
    #[cfg(not(feature = "symcrypt"))]
    {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize().to_vec()
    }
}

pub(crate) fn sha384_concat(parts: &[&[u8]]) -> Vec<u8> {
    #[cfg(feature = "symcrypt")]
    {
        symcrypt::hash::sha384(&parts.concat()).to_vec()
    }
    #[cfg(not(feature = "symcrypt"))]
    {
        use sha2::{Digest, Sha384};
        let mut hash = Sha384::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize().to_vec()
    }
}

pub(crate) fn random_bytes(bytes: &mut [u8]) -> std::io::Result<()> {
    #[cfg(feature = "symcrypt")]
    {
        symcrypt::symcrypt_random(bytes);
        Ok(())
    }
    #[cfg(not(feature = "symcrypt"))]
    {
        use rand::TryRngCore;
        rand::rngs::OsRng
            .try_fill_bytes(bytes)
            .map_err(std::io::Error::other)
    }
}

/// Compute the SHA-1 digest of `parts` concatenated in order (20 bytes).
#[cfg(all(feature = "native", target_os = "linux"))]
pub(crate) fn sha1_concat(parts: &[&[u8]]) -> Vec<u8> {
    use openssl::hash::{Hasher, MessageDigest};
    let mut hasher = Hasher::new(MessageDigest::sha1()).expect("openssl sha1 init");
    for part in parts {
        hasher.update(part).expect("openssl sha1 update");
    }
    hasher.finish().expect("openssl sha1 finish").to_vec()
}

/// Compute the SHA-1 digest of `parts` concatenated in order (20 bytes).
#[cfg(all(feature = "native", target_os = "windows"))]
pub(crate) fn sha1_concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(part);
    }
    windows_cng::sha1(&data)
}

#[cfg(all(feature = "native", target_os = "windows"))]
mod windows_cng {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptHash, BCryptOpenAlgorithmProvider,
        BCRYPT_SHA1_ALGORITHM,
    };

    /// One-shot SHA-1 via CNG (BCrypt). BCrypt routes to the OS SymCrypt module.
    pub(super) fn sha1(data: &[u8]) -> Vec<u8> {
        // SHA-1 digest length is fixed at 20 bytes.
        let mut out = [0u8; 20];
        // Safety: FFI into CNG. Handles are opened/closed within this scope
        // and buffer sizes match the SHA-1 digest length.
        unsafe {
            let mut alg = std::ptr::null_mut();
            let status =
                BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA1_ALGORITHM, std::ptr::null(), 0);
            assert!(
                status == 0,
                "BCryptOpenAlgorithmProvider(SHA1) failed: {status:#x}"
            );
            let status = BCryptHash(
                alg,
                std::ptr::null(),
                0,
                data.as_ptr(),
                data.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
            );
            assert!(status == 0, "BCryptHash(SHA1) failed: {status:#x}");
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        out.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::sha1_concat;

    #[test]
    fn sha2_known_answers_and_parts() {
        assert_eq!(
            hex::encode(super::sha256_concat(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(super::sha384_concat(&[b"a", b"bc"])),
            concat!(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163",
                "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            )
        );
    }

    #[test]
    fn sha1_empty_matches_known_vector() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        assert_eq!(
            hex::encode(sha1_concat(&[])),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn sha1_abc_matches_known_vector() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        assert_eq!(
            hex::encode(sha1_concat(&[b"abc"])),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn sha1_concat_matches_single_buffer() {
        // Concatenation must be identical to hashing the joined bytes.
        let split = sha1_concat(&[b"ab", b"c"]);
        let whole = sha1_concat(&[b"abc"]);
        assert_eq!(split, whole);
    }
}
