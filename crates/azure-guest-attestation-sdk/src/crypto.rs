// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-GCM backend for decrypting the MAA guest-attestation token envelope.
//!
//! The MAA "Transport Key" flow returns the attestation JWT encrypted under an
//! AES-GCM inner key (itself RSA-unwrapped by the TPM ephemeral key). Decrypting
//! it is part of producing a usable token, so this lives on the attestation
//! callout path — not the verification path.
//!
//! Three interchangeable backends are provided:
//!
//! - **default (`rustcrypto`)**: the pure-Rust `aes-gcm` crate. Portable, no C
//!   toolchain, published to crates.io.
//! - **`native`**: platform crypto — OpenSSL on Linux, CNG/BCrypt on Windows —
//!   so the shipped binary carries no RustCrypto AES implementation.
//! - **`symcrypt`**: explicitly linked SymCrypt, including TLS.
//!
//! `native` retains precedence over `rustcrypto`. SymCrypt is mutually exclusive
//! with either backend. At least one backend must be selected.

use std::io;

pub(crate) fn http_client_builder() -> reqwest::blocking::ClientBuilder {
    let builder = reqwest::blocking::Client::builder();
    #[cfg(feature = "symcrypt")]
    {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder_with_provider(
            rustls_symcrypt::default_symcrypt_provider_arc(),
        )
        .with_safe_default_protocol_versions()
        .expect("SymCrypt supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        builder.use_preconfigured_tls(config)
    }
    #[cfg(not(feature = "symcrypt"))]
    {
        builder
    }
}

#[cfg(all(feature = "symcrypt", any(feature = "native", feature = "rustcrypto")))]
compile_error!(
    "`symcrypt` cannot be combined with `native` or `rustcrypto`; disable default features"
);

#[cfg(not(any(feature = "native", feature = "rustcrypto", feature = "symcrypt")))]
compile_error!(
    "azure-guest-attestation-sdk requires `rustcrypto` (default), `native`, or `symcrypt`"
);

#[cfg(all(feature = "verify", not(any(feature = "native", feature = "symcrypt"))))]
compile_error!("`verify` requires an explicit `native` or `symcrypt` backend");

/// AES-128/256-GCM decrypt. `key` selects the variant by length (16 or 32),
/// `nonce` must be 12 bytes, `tag` 16 bytes. Returns the plaintext or an error
/// on authentication failure / bad parameters.
#[cfg(all(not(feature = "native"), feature = "rustcrypto"))]
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> io::Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::KeyInit, Aes128Gcm, Aes256Gcm, Nonce};
    let mut ct_and_tag = Vec::with_capacity(ciphertext.len() + tag.len());
    ct_and_tag.extend_from_slice(ciphertext);
    ct_and_tag.extend_from_slice(tag);
    let nonce = Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload {
        msg: &ct_and_tag,
        aad,
    };
    let result = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|e| io::Error::other(format!("aes-128 key init: {e}")))?
            .decrypt(nonce, payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|e| io::Error::other(format!("aes-256 key init: {e}")))?
            .decrypt(nonce, payload),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported AES key length: {other} (expected 16 or 32)"),
            ))
        }
    };
    result.map_err(|e| io::Error::other(format!("aes-gcm decrypt: {e}")))
}

#[cfg(feature = "symcrypt")]
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> io::Result<Vec<u8>> {
    use symcrypt::{cipher::BlockCipherType, gcm::GcmExpandedKey};
    if !matches!(key.len(), 16 | 32) || tag.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AES-GCM requires a 16/32-byte key and 16-byte tag",
        ));
    }
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "AES-GCM requires a 12-byte nonce",
        )
    })?;
    let key = GcmExpandedKey::new(key, BlockCipherType::AesBlock)
        .map_err(|e| io::Error::other(format!("SymCrypt AES key: {e}")))?;
    let mut plaintext = ciphertext.to_vec();
    key.decrypt_in_place(nonce, aad, &mut plaintext, tag)
        .map_err(|e| io::Error::other(format!("SymCrypt AES-GCM decrypt: {e}")))?;
    Ok(plaintext)
}

/// AES-128/256-GCM decrypt. `key` selects the variant by length (16 or 32),
/// `nonce` must be 12 bytes, `tag` 16 bytes. Returns the plaintext or an error
/// on authentication failure / bad parameters.
#[cfg(all(feature = "native", target_os = "linux"))]
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> io::Result<Vec<u8>> {
    use openssl::symm::{decrypt_aead, Cipher};
    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        32 => Cipher::aes_256_gcm(),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported AES key length: {other} (expected 16 or 32)"),
            ))
        }
    };
    decrypt_aead(cipher, key, Some(nonce), aad, ciphertext, tag)
        .map_err(|e| io::Error::other(format!("aes-gcm decrypt: {e}")))
}

/// AES-128/256-GCM decrypt. `key` selects the variant by length (16 or 32),
/// `nonce` must be 12 bytes, `tag` 16 bytes. Returns the plaintext or an error
/// on authentication failure / bad parameters.
#[cfg(all(feature = "native", target_os = "windows"))]
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> io::Result<Vec<u8>> {
    match key.len() {
        16 | 32 => {}
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported AES key length: {other} (expected 16 or 32)"),
            ))
        }
    }
    windows_cng::aes_gcm_decrypt(key, nonce, aad, ciphertext, tag)
}

#[cfg(all(feature = "native", target_os = "windows"))]
mod windows_cng {
    use std::io;
    use windows_sys::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDestroyKey, BCryptGenerateSymmetricKey,
        BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_AES_ALGORITHM,
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_GCM,
    };

    /// One-shot AES-GCM decrypt via CNG (BCrypt). BCrypt routes to the OS
    /// SymCrypt module. Verifies the authentication tag.
    pub(super) fn aes_gcm_decrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> io::Result<Vec<u8>> {
        // Safety: FFI into CNG. Handles are created and destroyed within this
        // scope; buffer pointers/lengths are derived from the input slices and
        // remain valid for the duration of each call.
        unsafe {
            let mut alg = std::ptr::null_mut();
            let mut status =
                BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_AES_ALGORITHM, std::ptr::null(), 0);
            if status != 0 {
                return Err(io::Error::other(format!(
                    "BCryptOpenAlgorithmProvider(AES) failed: {status:#x}"
                )));
            }

            // Select GCM chaining mode on the algorithm provider.
            let mode = BCRYPT_CHAIN_MODE_GCM;
            let mode_bytes = pcwstr_bytes(mode);
            status = BCryptSetProperty(
                alg,
                BCRYPT_CHAINING_MODE,
                mode_bytes.as_ptr(),
                mode_bytes.len() as u32,
                0,
            );
            if status != 0 {
                BCryptCloseAlgorithmProvider(alg, 0);
                return Err(io::Error::other(format!(
                    "BCryptSetProperty(GCM) failed: {status:#x}"
                )));
            }

            let mut key_handle = std::ptr::null_mut();
            status = BCryptGenerateSymmetricKey(
                alg,
                &mut key_handle,
                std::ptr::null_mut(),
                0,
                key.as_ptr(),
                key.len() as u32,
                0,
            );
            if status != 0 {
                BCryptCloseAlgorithmProvider(alg, 0);
                return Err(io::Error::other(format!(
                    "BCryptGenerateSymmetricKey failed: {status:#x}"
                )));
            }

            let mut auth_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO = std::mem::zeroed();
            auth_info.cbSize = std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32;
            auth_info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
            auth_info.pbNonce = nonce.as_ptr() as *mut u8;
            auth_info.cbNonce = nonce.len() as u32;
            auth_info.pbAuthData = aad.as_ptr() as *mut u8;
            auth_info.cbAuthData = aad.len() as u32;
            auth_info.pbTag = tag.as_ptr() as *mut u8;
            auth_info.cbTag = tag.len() as u32;

            let mut out = vec![0u8; ciphertext.len()];
            let mut out_len: u32 = 0;
            status = BCryptDecrypt(
                key_handle,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                &auth_info as *const _ as *const core::ffi::c_void,
                std::ptr::null_mut(),
                0,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut out_len,
                0,
            );
            BCryptDestroyKey(key_handle);
            BCryptCloseAlgorithmProvider(alg, 0);
            if status != 0 {
                // STATUS_AUTH_TAG_MISMATCH (0xC000A002) surfaces here on a bad tag.
                return Err(io::Error::other(format!(
                    "BCryptDecrypt(AES-GCM) failed: {status:#x}"
                )));
            }
            out.truncate(out_len as usize);
            Ok(out)
        }
    }

    /// Copy a NUL-terminated wide string (PCWSTR) into a UTF-16 byte buffer,
    /// including the terminator, as required by `BCryptSetProperty`.
    unsafe fn pcwstr_bytes(s: windows_sys::core::PCWSTR) -> Vec<u8> {
        let mut len = 0usize;
        while *s.add(len) != 0 {
            len += 1;
        }
        // Include the terminating NUL.
        let units = std::slice::from_raw_parts(s, len + 1);
        let mut bytes = Vec::with_capacity((len + 1) * 2);
        for u in units {
            bytes.extend_from_slice(&u.to_ne_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::aes_gcm_decrypt;

    // NIST/McGrew GCM Test Case 4 (AES-128, with AAD).
    #[test]
    fn aes128_gcm_roundtrip_known_vector() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ciphertext = hex_bytes(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let tag = hex_bytes("5bc94fbc3221a5db94fae95ae7121a47");
        let out = aes_gcm_decrypt(&key, &iv, &aad, &ciphertext, &tag).expect("decrypt ok");
        assert_eq!(out, plaintext);
    }

    // NIST/McGrew GCM Test Case 16 (AES-256, with AAD).
    #[test]
    fn aes256_gcm_roundtrip_with_aad() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex_bytes("cafebabefacedbaddecaf888");
        let aad = hex_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex_bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ciphertext = hex_bytes(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        );
        let tag = hex_bytes("76fc6ece0f4e1768cddf8853bb2d551b");
        let out = aes_gcm_decrypt(&key, &iv, &aad, &ciphertext, &tag).expect("decrypt ok");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn aes_gcm_rejects_tampered_tag() {
        let key = hex_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_bytes("cafebabefacedbaddecaf888");
        let ciphertext = hex_bytes("42831ec2217774244b7221b784d0d49c");
        let mut tag = hex_bytes("5bc94fbc3221a5db94fae95ae7121a47");
        tag[0] ^= 0xff;
        assert!(aes_gcm_decrypt(&key, &iv, &[], &ciphertext, &tag).is_err());
    }

    #[test]
    fn aes_gcm_rejects_bad_key_length() {
        assert!(aes_gcm_decrypt(&[0u8; 24], &[0u8; 12], &[], &[], &[0u8; 16]).is_err());
    }

    #[cfg(feature = "symcrypt")]
    #[test]
    fn aes_gcm_rejects_bad_nonce_and_tag_lengths() {
        for nonce_len in [0, 1, 11, 13, 16] {
            assert!(aes_gcm_decrypt(&[0; 16], &vec![0; nonce_len], &[], &[], &[0; 16]).is_err());
        }
        for tag_len in [0, 1, 12, 15, 17] {
            assert!(aes_gcm_decrypt(&[0; 16], &[0; 12], &[], &[], &vec![0; tag_len]).is_err());
        }
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }
}
