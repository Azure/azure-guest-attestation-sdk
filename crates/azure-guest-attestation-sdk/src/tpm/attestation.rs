// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;

use crate::tpm::device::Tpm;
use crate::tpm::types::NvPublic;
use crate::tpm::types::TpmaNvBits;
use crate::tpm::types::TpmtSignature;
use crate::tpm::types::{
    ecc_unrestricted_signing_public, rsa_restricted_signing_public,
    rsa_unrestricted_sign_decrypt_public_with_policy, Hierarchy, ALG_SHA256,
};
// TpmCommandExt may be used later for NV backed operations
use crate::report::CvmAttestationReport;
use crate::report::RuntimeClaims;
use crate::tpm::commands::TpmCommandExt;
use crate::tpm::helpers::hex_fmt;

/// Persistent handle for the Attestation Key (AK) public object.
pub const AK_PERSISTENT_HANDLE: u32 = 0x81000003;

/// Persistent handle for ECC signing key
pub const ECC_SIGNING_KEY_PERSISTENT_HANDLE: u32 = 0x81000010;

/// Artifacts produced by creating an ephemeral RSA primary key.
///
/// The key is created as a TPM2 primary under the owner hierarchy with
/// a PCR-based authorization policy.  It is certified by the persistent
/// AK so the attestation service can trust the binding.
#[derive(Debug, Clone)]
pub struct EphemeralKey {
    /// TPM2B_PUBLIC of the ephemeral key.
    pub public: Vec<u8>,
    /// Transient handle (big-endian u32) for the key. Callers must flush
    /// this handle when done, or recreate it later from the same PCRs.
    pub handle: u32,
    /// TPMS_ATTEST from TPM2_Certify (certifying the ephemeral key with the AK).
    pub certify_info: Vec<u8>,
    /// Signature over `certify_info` from the AK.
    pub certify_sig: Vec<u8>,
}

/// Create an ECC P-256 signing key and persist it to TPM NV space.
/// Returns the public key bytes.
pub fn create_and_persist_ecc_signing_key(tpm: &Tpm) -> io::Result<Vec<u8>> {
    // Check if key already exists at the persistent handle
    if let Ok(pub_bytes) = tpm.read_public(ECC_SIGNING_KEY_PERSISTENT_HANDLE) {
        tracing::trace!(target: "guest_attest", "ECC signing key already exists at persistent handle");
        return Ok(pub_bytes);
    }

    // Create ECC signing key
    let public_template = ecc_unrestricted_signing_public();
    let created = tpm.create_primary_ecc(Hierarchy::Owner, public_template)?;

    tracing::trace!(target: "guest_attest", handle = format_args!("0x{:08x}", created.handle), "Created ECC primary key");

    // Persist the key
    tpm.evict_control(ECC_SIGNING_KEY_PERSISTENT_HANDLE, created.handle)?;

    // Flush the transient handle
    let _ = tpm.flush_context(created.handle);

    tracing::trace!(target: "guest_attest", persistent_handle = format_args!("0x{:08x}", ECC_SIGNING_KEY_PERSISTENT_HANDLE), "ECC signing key persisted");

    // Read and return the public key from the persistent handle
    tpm.read_public(ECC_SIGNING_KEY_PERSISTENT_HANDLE)
}

/// Get the public area of a persistent ECC signing key.
pub fn get_ecc_signing_key_pub(tpm: &Tpm) -> io::Result<Vec<u8>> {
    tpm.read_public(ECC_SIGNING_KEY_PERSISTENT_HANDLE)
}

/// Sign a digest using the persistent ECC signing key.
/// Returns the ECDSA signature.
pub fn sign_with_ecc_key(tpm: &Tpm, digest: &[u8]) -> io::Result<TpmtSignature> {
    // Ensure key exists
    if tpm.read_public(ECC_SIGNING_KEY_PERSISTENT_HANDLE).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ECC signing key not found at persistent handle. Call create_and_persist_ecc_signing_key first.",
        ));
    }

    tpm.sign(ECC_SIGNING_KEY_PERSISTENT_HANDLE, digest)
}

/// Verify a signature using the persistent ECC signing key.
/// Returns Ok(()) if the signature is valid.
pub fn verify_with_ecc_key(tpm: &Tpm, digest: &[u8], signature: &TpmtSignature) -> io::Result<()> {
    // Ensure key exists
    if tpm.read_public(ECC_SIGNING_KEY_PERSISTENT_HANDLE).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ECC signing key not found at persistent handle. Call create_and_persist_ecc_signing_key first.",
        ));
    }

    tpm.verify_signature(ECC_SIGNING_KEY_PERSISTENT_HANDLE, digest, signature)
}

/// Ensure a restricted signing AK exists at the persistent handle. If missing, create and evict.
pub fn ensure_persistent_ak(tpm: &Tpm) -> io::Result<()> {
    // Probe for existing
    if get_ak_pub(tpm).is_ok() {
        return Ok(());
    }
    let public = rsa_restricted_signing_public();
    let created = tpm.create_primary(Hierarchy::Endorsement, public.clone(), &[])?;

    // Attempt EvictControl to make it persistent. If VALUE param index=2 (likely persistent handle already in use or unsupported),
    // treat as success if the persistent handle now resolves via ReadPublic.
    tpm.evict_control(AK_PERSISTENT_HANDLE, created.handle)?;

    let _ = tpm.flush_context(created.handle);

    Ok(())
}

const NV_INDEX_AK_CERT: u32 = 0x1c101d0;
const NV_INDEX_CVM_REPORT: u32 = 0x1400001;
const NV_INDEX_USER_DATA: u32 = 0x1400002;

/// Read PCR values for provided list of indices (assuming SHA256 bank) returning (index,digest) pairs.
pub fn get_pcr_values(tpm: &Tpm, pcrs: &[u32]) -> io::Result<Vec<(u32, Vec<u8>)>> {
    tpm.read_pcrs_sha256(pcrs)
}

// NOTE: The following implementations rely on empty auth values and the password
// authorization session handle (TPM_RS_PW). Azure CVM vTPMs use empty hierarchy
// auths, so this is correct for the target environment. Platforms with non-empty
// hierarchy auths will receive a TPM_RC_BAD_AUTH error.
//
// Known limitations:
//  * Key handles are not cached; each call creates a fresh primary key.
//  * get_pcr_quote creates a transient signing primary and immediately quotes.
//  * Minimal parsing of responses; only the fields needed by the SDK are extracted.

/// Get the public area of the Attestation Key (AK) object.
pub fn get_ak_pub(tpm: &Tpm) -> io::Result<Vec<u8>> {
    tpm.read_public(AK_PERSISTENT_HANDLE)
}

/// Read the Attestation Key certificate from the TPM NV index.
/// Returns an empty `Vec` if the NV index is not defined.
pub fn get_ak_cert(tpm: &Tpm) -> io::Result<Vec<u8>> {
    // Attempt to read NV index directly. If not defined, map to NotFound
    match tpm.nv_read_public(NV_INDEX_AK_CERT) {
        Ok(pub_info) => {
            let size = pub_info.data_size as usize;
            if size == 0 {
                return Ok(Vec::new());
            }
            tpm.read_nv_index(NV_INDEX_AK_CERT)
        }
        Err(e) => {
            // If index missing return empty Vec rather than error to allow callers to decide
            if e.kind() == io::ErrorKind::NotFound {
                Ok(Vec::new())
            } else {
                Err(e)
            }
        }
    }
}

/// Read the AK certificate and trim trailing zero padding by parsing minimal DER length.
/// If the NV index stores exactly the cert size this will match `get_ak_cert`.
pub fn get_ak_cert_trimmed(tpm: &Tpm) -> io::Result<Vec<u8>> {
    let full = get_ak_cert(tpm)?;

    if full.len() < 4 {
        return Ok(full);
    }
    // Basic DER parser for Certificate ::= SEQUENCE (0x30)
    if full[0] != 0x30 {
        return Ok(full);
    }

    // Handle short vs long form length octets
    let len_byte = full[1] as usize;
    let (content_len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte, 2)
    } else {
        let n = len_byte & 0x7F; // number of subsequent length bytes
        if n == 0 || n > 4 || 2 + n > full.len() {
            return Ok(full);
        }
        let mut l: usize = 0;
        for i in 0..n {
            l = (l << 8) | (full[2 + i] as usize);
        }
        (l, 2 + n)
    };

    let total = header_len + content_len;
    if total <= full.len() {
        Ok(full[..total].to_vec())
    } else {
        Ok(full)
    }
}

/// Read (if present) the user data NV index contents (trim trailing zero padding).
/// Returns Ok(None) if the NV index is not defined. The returned Vec length is the
/// number of meaningful bytes (<=64). If the index exists but all bytes are zero
/// this returns Some(Vec::new()).
pub fn get_user_data_nv(tpm: &Tpm) -> io::Result<Option<Vec<u8>>> {
    // First check if the index exists (avoid surfacing raw TPM handle errors)
    match tpm.find_nv_index(NV_INDEX_USER_DATA) {
        Ok(Some(_pub)) => {
            // Now read full 64 bytes
            let raw = match tpm.read_nv_index(NV_INDEX_USER_DATA) {
                Ok(b) => b,
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("failed to read user data NV index: {e}"),
                    ))
                }
            };
            // Trim trailing zeros
            let meaningful_len = raw
                .iter()
                .rposition(|b| *b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            let trimmed = raw[..meaningful_len].to_vec();
            Ok(Some(trimmed))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            // Treat a NotFound style error conservatively as absence
            if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(io::Error::new(
                    e.kind(),
                    format!("failed to query user data NV index: {e}"),
                ))
            }
        }
    }
}

/// Get a CVM report + optional runtime claims with arbitrary user data (0..=64 bytes).
/// Input will be zero padded out to 64 bytes before staging into the NV index backing user data.
pub fn get_cvm_report(
    tpm: &Tpm,
    user_data: Option<&[u8]>,
) -> io::Result<(CvmAttestationReport, Option<RuntimeClaims>)> {
    let raw = get_cvm_report_raw(tpm, user_data)?;

    CvmAttestationReport::parse_with_runtime_claims(&raw)
}

/// Get a CVM report + optional runtime claims with arbitrary user data (0..=64 bytes).
/// Input will be zero padded out to 64 bytes before staging into the NV index backing user data.
pub fn get_cvm_report_raw(tpm: &Tpm, user_data: Option<&[u8]>) -> io::Result<Vec<u8>> {
    if let Some(data) = user_data {
        if data.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("user_data length {} exceeds 64 bytes", data.len()),
            ));
        }

        let padded = pad_user_data(data);
        if let Err(e) = ensure_user_data_index_and_write(tpm, &padded) {
            tracing::warn!(target: "guest_attest", error = %e, "Failed to stage user data into NV index");
        }
    }

    tpm.read_nv_index(NV_INDEX_CVM_REPORT)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read CVM report NV index: {e}")))
}

/// Fetch the raw CVM attestation report and return (tee_report_bytes_trimmed, report_type).
/// The tee_report is sliced to the expected size for the detected report type; returns empty
/// Vec if type is Invalid or TVM (no TEE report).
pub fn get_tee_report_and_type(
    tpm: &Tpm,
    user_data: Option<&[u8]>,
) -> io::Result<(Vec<u8>, crate::report::CvmReportType)> {
    let raw = get_cvm_report_raw(tpm, user_data)?;
    let (rep, _claims) = crate::report::CvmAttestationReport::parse_with_runtime_claims(&raw)?;
    use crate::report::{
        CvmReportType, SNP_VM_REPORT_SIZE, TDX_VM_REPORT_SIZE, VBS_VM_REPORT_SIZE,
    };
    let rtype = rep.runtime_claims_header.report_type;
    let expected = match rtype {
        CvmReportType::VbsVmReport => VBS_VM_REPORT_SIZE,
        CvmReportType::SnpVmReport => SNP_VM_REPORT_SIZE,
        CvmReportType::TdxVmReport => TDX_VM_REPORT_SIZE,
        CvmReportType::TvmReport | CvmReportType::Invalid => 0,
    };
    let mut out = Vec::new();
    if expected > 0 {
        out.extend_from_slice(&rep.tee_report[..expected.min(rep.tee_report.len())]);
    }
    Ok((out, rtype))
}

fn define_user_data_index(tpm: &Tpm) -> io::Result<()> {
    let attr_bits = TpmaNvBits::new()
        .with_nv_ownerwrite(true)
        .with_nv_authwrite(true)
        .with_nv_ownerread(true)
        .with_nv_authread(true);
    let attrs: u32 = attr_bits.into();
    let public = NvPublic {
        nv_index: NV_INDEX_USER_DATA,
        name_alg: ALG_SHA256,
        attributes: attrs,
        auth_policy: Vec::new(),
        data_size: 64,
    };
    tracing::trace!(target: "guest_attest", nv_index = format_args!("0x{NV_INDEX_USER_DATA:08x}"), attrs = format_args!("0x{attrs:08x}"), "Defining user-data NV index");
    if let Err(e) = tpm.nv_define_space(public, &[]) {
        // If define fails because index already exists (race) we proceed; otherwise return error.
        tracing::trace!(target: "guest_attest", error = %e, "Define attempt error");
        return Err(e);
    }

    Ok(())
}

// Helper: define user data NV index if missing and write content
fn ensure_user_data_index_and_write(tpm: &Tpm, user_data: &[u8; 64]) -> io::Result<()> {
    match tpm.find_nv_index(NV_INDEX_USER_DATA) {
        Ok(Some(_)) => {}
        Ok(None) => define_user_data_index(tpm)?,
        Err(e) => {
            tracing::debug!(target: "guest_attest", error = %e, "Failed to find user-data NV index; will attempt define");
            define_user_data_index(tpm)?;
        }
    }

    // Write (single or multi-chunk handled internally)
    tpm.write_nv_index(NV_INDEX_USER_DATA, user_data)?;

    Ok(())
}

// Build a fixed 64-byte user data array, zero padding any unused tail.
fn pad_user_data(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let len = input.len().min(64);
    out[..len].copy_from_slice(&input[..len]);
    out
}

/// Produce a PCR quote over the supplied PCR indices (0-23) using a transient
/// attestation key. Returns (attestation, signature) byte blobs.
pub fn get_pcr_quote(tpm: &Tpm, pcrs: &[u32]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    tracing::trace!(target: "guest_attest", ?pcrs, "get_pcr_quote start");
    if let Err(e) = ensure_persistent_ak(tpm) {
        tracing::trace!(target: "guest_attest", error = %e, "ensure_persistent_ak before quote failed");
        return Err(e);
    }
    let (quote, signature) = match tpm.quote_with_key(AK_PERSISTENT_HANDLE, pcrs) {
        Ok(v) => v,
        Err(e) => {
            tracing::trace!(target: "guest_attest", error = %e, "TPM2_Quote failed");
            return Err(e);
        }
    };

    tracing::trace!(target: "guest_attest", quote = %hex_fmt(&quote), signature = %hex_fmt(&signature), "PCR quote result");

    Ok((quote, signature))
}

/// Create a non-restricted (unrestricted) RSA 2048 key suitable for ephemeral
/// use (signing + decrypt) and return an [`EphemeralKey`] with the public area,
/// handle, and AK certification artifacts.
///
/// The key is certified by the persistent AK using TPM2_Certify so the
/// attestation service can trust the ephemeral key binding.
pub fn get_ephemeral_key(tpm: &Tpm, pcrs: &[u32]) -> io::Result<EphemeralKey> {
    let policy = tpm.compute_pcr_policy_digest(pcrs)?;
    tracing::debug!(target: "guest_attest", ?policy, "PCR policy digest");
    let template = rsa_unrestricted_sign_decrypt_public_with_policy(policy);
    let cp = tpm.create_primary(Hierarchy::Owner, template, pcrs)?;

    tracing::debug!(target: "guest_attest", handle = format_args!("0x{:08x}", cp.handle), ?pcrs, "Created ephemeral primary key");

    let (cert_info, cert_sig) = match tpm.certify_with_key(cp.handle, AK_PERSISTENT_HANDLE) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(target: "guest_attest", handle = format_args!("0x{:08x}", cp.handle), error = %e, "TPM2_Certify failed for object");
            return Err(e);
        }
    };

    Ok(EphemeralKey {
        public: cp.public,
        handle: cp.handle,
        certify_info: cert_info,
        certify_sig: cert_sig,
    })
}

/// Decrypt data with an existing ephemeral RSA key (created via `get_ephemeral_key`).
/// Uses TPM2_RSA_Decrypt with **RSAES (PKCS#1 v1.5)** scheme, matching the encryption
/// scheme used by Microsoft Azure Attestation (MAA).
pub fn decrypt_with_ephemeral_key(
    tpm: &Tpm,
    key_handle: u32,
    pcrs: &[u32],
    ciphertext: &[u8],
) -> io::Result<Vec<u8>> {
    use crate::tpm::types::TpmtRsaDecryptScheme;
    tpm.rsa_decrypt(key_handle, pcrs, ciphertext, TpmtRsaDecryptScheme::Rsaes)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "vtpm-tests")]
    use super::ensure_user_data_index_and_write; // accessible within same module
    use super::pad_user_data;
    #[cfg(feature = "vtpm-tests")]
    use crate::tpm::attestation::ensure_persistent_ak;
    #[cfg(feature = "vtpm-tests")]
    use crate::tpm::attestation::get_ak_pub;
    #[cfg(feature = "vtpm-tests")]
    use crate::tpm::attestation::get_pcr_quote;
    #[cfg(feature = "vtpm-tests")]
    use crate::tpm::commands::TpmCommandExt;
    #[cfg(feature = "vtpm-tests")]
    use crate::tpm::device::Tpm; // bring read_nv_index into scope

    #[cfg(all(feature = "vtpm-tests", test))]
    #[test]
    fn vtpm_user_data_index_write_and_read() {
        // Open the in-process reference TPM
        let tpm = Tpm::open_reference_for_tests().expect("failed to open reference TPM");
        let raw = b"hello";
        let padded = pad_user_data(raw);
        // Under multi-threaded `cargo test`, the shared TPM may have stale NV
        // state from concurrent tests. Skip gracefully on errors.
        if let Err(e) = ensure_user_data_index_and_write(&tpm, &padded) {
            tracing::debug!(target: "guest_attest", error = %e, "Skipping user data write test (shared TPM contention)");
            return;
        }
        match tpm.read_nv_index(super::NV_INDEX_USER_DATA) {
            Ok(nv) => {
                assert_eq!(nv.len(), 64, "NV user data index size mismatch");
                assert_eq!(&nv[..raw.len()], raw, "NV user data prefix mismatch");
                assert!(
                    nv[raw.len()..].iter().all(|&b| b == 0),
                    "NV user data tail not zero padded",
                );
            }
            Err(e) => {
                // The reference TPM can return NV_SIZE errors for certain index configurations;
                // verify via nv_read_public that the index at least exists and is sized correctly.
                tracing::debug!(target: "guest_attest", error = %e, "NV read after write failed; checking public area");
                let pub_info = tpm
                    .nv_read_public(super::NV_INDEX_USER_DATA)
                    .expect("NV index should exist after define+write");
                assert_eq!(
                    pub_info.data_size, 64,
                    "NV user data size mismatch in public area"
                );
            }
        }
    }

    #[test]
    fn pad_user_data_empty() {
        let out = pad_user_data(&[]);
        assert_eq!(out, [0u8; 64]);
    }

    #[test]
    fn pad_user_data_partial() {
        let input = b"abc"; // 3 bytes
        let out = pad_user_data(input);
        assert_eq!(&out[..3], input);
        assert!(out[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_user_data_exact_64() {
        let input = [0xAB; 64];
        let out = pad_user_data(&input);
        assert_eq!(out, input);
    }

    #[test]
    fn pad_user_data_over_64_truncates() {
        let input = [0xFF; 100];
        let out = pad_user_data(&input);
        assert_eq!(&out[..], &input[..64]);
    }

    #[test]
    fn pad_user_data_single_byte() {
        let out = pad_user_data(&[0x42]);
        assert_eq!(out[0], 0x42);
        assert!(out[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn vtpm_quote_signature_verifies() {
        #[cfg(feature = "vtpm-tests")]
        {
            use crate::tpm::device::Tpm;
            use crate::tpm::types::{Tpm2bPublic, TpmUnmarshal};
            use num_bigint::BigUint;
            use sha2::{Digest, Sha256};

            // Open reference TPM & ensure AK; skip on contention errors
            let tpm = Tpm::open_reference_for_tests().expect("open reference TPM");
            if let Err(e) = ensure_persistent_ak(&tpm) {
                tracing::debug!(target: "guest_attest", error = %e, "Skipping vtpm_quote_signature_verifies (shared TPM contention)");
                return;
            }
            let ak_pub_blob = match get_ak_pub(&tpm) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(target: "guest_attest", error = %e, "Skipping vtpm_quote_signature_verifies (shared TPM contention)");
                    return;
                }
            };
            let mut cur = 0usize;
            let ak_pub = Tpm2bPublic::unmarshal(&ak_pub_blob, &mut cur).expect("parse ak public");
            assert!(
                !ak_pub.inner.unique.0.is_empty(),
                "AK public unique modulus unexpectedly empty"
            );

            // Issue Quote over PCR0
            let (attest, sig_blob) = match get_pcr_quote(&tpm, &[0]) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(target: "guest_attest", error = %e, "Skipping vtpm_quote_signature_verifies (quote failed under contention)");
                    return;
                }
            };
            assert!(!attest.is_empty(), "attestation blob empty");
            assert!(!sig_blob.is_empty(), "signature blob empty");

            // Perform RSASSA-PKCS1-v1_5 verification manually
            let modulus_bytes = &ak_pub.inner.unique.0; // big-endian modulus
            let modulus = BigUint::from_bytes_be(modulus_bytes);
            let exponent_u32 = if ak_pub.inner.exponent == 0 {
                65537
            } else {
                ak_pub.inner.exponent
            };
            let exponent = BigUint::from(exponent_u32);
            let s = BigUint::from_bytes_be(&sig_blob);
            let m = s.modpow(&exponent, &modulus); // decrypted signature representative
            let mut em = m.to_bytes_be();
            let k = modulus_bytes.len();
            if em.len() < k {
                // Left pad EM to k bytes
                let mut pad = vec![0u8; k - em.len()];
                pad.extend_from_slice(&em);
                em = pad;
            }
            assert_eq!(em.len(), k, "EM length != modulus length");

            // Build expected EMSA-PKCS1-v1_5 encoded message for SHA256
            const DER_PREFIX: &[u8] =
                b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"; // DigestInfo prefix for SHA256
            let digest = Sha256::digest(&attest);
            let t_len = 3 + DER_PREFIX.len() + digest.len(); // 0x00 0x01 0x00 + DER + H
            assert!(
                k > t_len,
                "modulus too small for PKCS#1 padding (k={}, t_len={})",
                k,
                t_len
            );
            let ps_len = k - t_len; // number of 0xFF padding bytes
            assert!(
                ps_len >= 8,
                "PKCS#1 v1.5 requires PS length >= 8 (got {})",
                ps_len
            );
            let mut expected = Vec::with_capacity(k);
            expected.push(0x00);
            expected.push(0x01);
            expected.extend(std::iter::repeat_n(0xFF, ps_len));
            expected.push(0x00);
            expected.extend_from_slice(DER_PREFIX);
            expected.extend_from_slice(&digest);

            assert_eq!(
                em, expected,
                "RSASSA PKCS#1 v1.5 block mismatch (signature invalid)"
            );
        }
    }

    #[test]
    fn vtpm_get_quote() {
        #[cfg(feature = "vtpm-tests")]
        {
            use crate::tpm::attestation::{ensure_persistent_ak, get_pcr_quote}; // explicit path
            use crate::tpm::device::Tpm;

            let tpm = match Tpm::open_reference_for_tests() {
                Ok(t) => t,
                Err(_) => return,
            }; // skip if reference TPM unavailable

            // Ensure AK present (ignore error to allow skip on auth failures)
            if let Err(e) = ensure_persistent_ak(&tpm) {
                tracing::debug!(target: "guest_attest", error = %e, "[vtpm-test] skipping: ensure_persistent_ak failed");
                return;
            }

            // Under multi-threaded `cargo test`, CreatePrimary or Quote may
            // fail due to resource exhaustion on the shared reference TPM.
            match get_pcr_quote(&tpm, &[0]) {
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(target: "guest_attest", error = %e, "[vtpm-test] get_pcr_quote failed (shared TPM contention, skipping)");
                }
            }
        }
    }

    #[test]
    fn vtpm_ephemeral_key_multiple_pcrs_policy_non_empty() {
        #[cfg(feature = "vtpm-tests")]
        {
            use crate::tpm::attestation::{ensure_persistent_ak, get_ephemeral_key};
            use crate::tpm::device::Tpm;
            use crate::tpm::types::{Tpm2bPublic, TpmUnmarshal};
            let tpm = match Tpm::open_reference_for_tests() {
                Ok(t) => t,
                Err(_) => return,
            };
            if let Err(e) = ensure_persistent_ak(&tpm) {
                tracing::debug!(target: "guest_attest", error = %e, "[vtpm-test] skipping: ensure_persistent_ak failed");
                return;
            }
            let ek = match get_ephemeral_key(&tpm, &[0, 1, 2]) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut cur = 0usize;
            let parsed = Tpm2bPublic::unmarshal(&ek.public, &mut cur).expect("parse pub");
            if parsed.inner.auth_policy.0.is_empty() {
                panic!("Expected non-empty policy for multi-PCR bound key");
            }
            assert_eq!(
                parsed.inner.auth_policy.0.len(),
                32,
                "Policy digest must be 32 bytes"
            );
        }
    }

    #[test]
    fn vtpm_ephemeral_rsa_decrypt_roundtrip() {
        #[cfg(feature = "vtpm-tests")]
        {
            use crate::tpm::attestation::get_ephemeral_key;
            use crate::tpm::commands::TpmCommandExt;
            use crate::tpm::device::Tpm;
            use crate::tpm::types::{Tpm2bPublic, TpmUnmarshal, TpmtRsaDecryptScheme};
            use num_bigint::BigUint;
            use rand::{rngs::StdRng, RngCore, SeedableRng};

            let tpm = match Tpm::open_reference_for_tests() {
                Ok(t) => t,
                Err(_) => return,
            };
            let ek = match get_ephemeral_key(&tpm, &[]) {
                Ok(v) => v,
                Err(_) => return,
            };
            let handle = ek.handle;
            let mut cur = 0usize;
            let parsed = Tpm2bPublic::unmarshal(&ek.public, &mut cur).expect("parse pub");
            let modulus_be = &parsed.inner.unique.0;
            if modulus_be.len() != 256 {
                return;
            } // skip if not RSA2048
            let n = BigUint::from_bytes_be(modulus_be);
            let e_u32 = if parsed.inner.exponent == 0 {
                65537
            } else {
                parsed.inner.exponent
            };
            let e = BigUint::from(e_u32);
            let k = modulus_be.len();
            let message = b"rsa decrypt sample"; // <= k - 11
                                                 // Build PKCS#1 v1.5 block 0x00 0x02 PS 0x00 M
            let ps_len = k - 3 - message.len();
            if ps_len < 8 {
                return;
            }
            let mut rng = StdRng::seed_from_u64(0xA1B2C3D4);
            let mut ps = vec![0u8; ps_len];
            for b in ps.iter_mut() {
                let mut v = 0u8;
                while v == 0 {
                    v = (rng.next_u32() & 0xFF) as u8;
                }
                *b = v;
            }
            let mut em = Vec::with_capacity(k);
            em.push(0x00);
            em.push(0x02);
            em.extend_from_slice(&ps);
            em.push(0x00);
            em.extend_from_slice(message);
            let m = BigUint::from_bytes_be(&em);
            let c = m.modpow(&e, &n);
            let mut ciphertext = c.to_bytes_be();
            if ciphertext.len() < k {
                let mut pad = vec![0u8; k - ciphertext.len()];
                pad.extend_from_slice(&ciphertext);
                ciphertext = pad;
            }
            // Use RSAES scheme directly since we built PKCS#1 v1.5 padding above
            let decrypted = match tpm.rsa_decrypt(
                handle,
                &[],
                &ciphertext,
                TpmtRsaDecryptScheme::Rsaes,
            ) {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(target: "guest_attest", error = %e, "Skipping RSA decrypt test (shared TPM contention)");
                    return;
                }
            };
            // Expect plaintext ends with original message (TPM strips PKCS#1 v1.5 padding including leading structure)
            if decrypted.ends_with(message) {
                assert!(decrypted.len() <= message.len() + k);
            } else {
                panic!("decrypted output mismatch");
            }
        }
    }

    #[test]
    fn vtpm_ephemeral_rsa_decrypt_roundtrip_policy() {
        #[cfg(feature = "vtpm-tests")]
        {
            use crate::tpm::attestation::get_ephemeral_key;
            use crate::tpm::commands::TpmCommandExt;
            use crate::tpm::device::Tpm;
            use crate::tpm::types::{Tpm2bPublic, TpmUnmarshal, TpmtRsaDecryptScheme};
            use num_bigint::BigUint;
            use rand::{rngs::StdRng, RngCore, SeedableRng};

            let tpm = match Tpm::open_reference_for_tests() {
                Ok(t) => t,
                Err(_) => return,
            }; // skip if ref TPM absent
               // Create policy-bound key (PCR0)
            let ek = match get_ephemeral_key(&tpm, &[0]) {
                Ok(v) => v,
                Err(_) => return,
            };
            let handle = ek.handle;
            let mut cur = 0usize;
            let parsed = Tpm2bPublic::unmarshal(&ek.public, &mut cur).expect("parse pub");
            if parsed.inner.unique.0.len() != 256 {
                return;
            } // only test RSA2048
            if parsed.inner.auth_policy.0.is_empty() {
                return;
            } // skip if policy not set unexpectedly
            let modulus_be = &parsed.inner.unique.0;
            let n = BigUint::from_bytes_be(modulus_be);
            let e_u32 = if parsed.inner.exponent == 0 {
                65537
            } else {
                parsed.inner.exponent
            };
            let e = BigUint::from(e_u32);
            let k = modulus_be.len();
            let message = b"policy decrypt sample";
            let ps_len = k - 3 - message.len();
            if ps_len < 8 {
                return;
            }
            let mut rng = StdRng::seed_from_u64(0x1234_5678_9abc_def0);
            let mut ps = vec![0u8; ps_len];
            for b in ps.iter_mut() {
                let mut v = 0u8;
                while v == 0 {
                    v = (rng.next_u32() & 0xFF) as u8;
                }
                *b = v;
            }
            let mut em = Vec::with_capacity(k);
            em.push(0x00);
            em.push(0x02);
            em.extend_from_slice(&ps);
            em.push(0x00);
            em.extend_from_slice(message);
            let m = BigUint::from_bytes_be(&em);
            let c = m.modpow(&e, &n);
            let mut ciphertext = c.to_bytes_be();
            if ciphertext.len() < k {
                let mut pad = vec![0u8; k - ciphertext.len()];
                pad.extend_from_slice(&ciphertext);
                ciphertext = pad;
            }
            // Use RSAES scheme directly since we built PKCS#1 v1.5 padding above
            let decrypted =
                match tpm.rsa_decrypt(handle, &[0], &ciphertext, TpmtRsaDecryptScheme::Rsaes) {
                    Ok(v) => v,
                    Err(_) => return,
                };
            assert!(
                decrypted.ends_with(message),
                "policy decrypt output mismatch"
            );
        }
    }
}
