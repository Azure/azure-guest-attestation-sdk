// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CNG (BCrypt) + CryptoAPI (crypt32) implementation of the [`super`] crypto
//! interface (Windows).
//!
//! Semantics must match the OpenSSL backend byte-for-byte: callers hand over
//! already big-endian `r`/`s` components and pre-ordered message bytes, so
//! nothing here re-orders anything. The one adaptation CNG forces is that
//! `BCryptVerifySignature` wants `r ‖ s` at exactly the curve size, whereas
//! OpenSSL's `BigNum` accepts any length — see [`fixed_width_be`].

use super::{other, unix_time_to_filetime_ticks, DigestAlg};
use base64::Engine as _;
use core::ffi::c_void;
use std::io;
use std::ptr;
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{FILETIME, NTSTATUS};
use windows_sys::Win32::Security::Cryptography::{
    szOID_BASIC_CONSTRAINTS2, BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash,
    BCryptDestroyKey, BCryptFinishHash, BCryptHashData, BCryptImportKeyPair,
    BCryptOpenAlgorithmProvider, BCryptVerifySignature, CertCompareCertificateName,
    CertCreateCertificateContext, CertFindExtension, CertFreeCertificateContext,
    CertVerifyTimeValidity, CryptDecodeObjectEx, CryptImportPublicKeyInfoEx2,
    CryptVerifyCertificateSignatureEx, BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_HASH_HANDLE,
    BCRYPT_KEY_HANDLE, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM,
    CERT_BASIC_CONSTRAINTS2_INFO, CERT_CONTEXT, CERT_INFO, CERT_V1,
    CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, X509_ASN_ENCODING,
    X509_BASIC_CONSTRAINTS2,
};

const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_INVALID_SIGNATURE: NTSTATUS = 0xC000_A000_u32 as NTSTATUS;

/// Upper bound on the number of links walked while building a chain. Guards
/// against cycles in caller-supplied intermediates.
const MAX_CHAIN_DEPTH: usize = 8;

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// An X.509 certificate handle. Stores the DER encoding; `CERT_CONTEXT`s are
/// created on demand so the handle stays cheap to clone and thread-safe.
#[derive(Clone)]
pub(crate) struct Cert {
    der: Vec<u8>,
}

impl Cert {
    fn from_der(der: Vec<u8>) -> io::Result<Self> {
        let cert = Self { der };
        cert.context()?; // reject anything crypt32 cannot parse up front
        Ok(cert)
    }

    fn context(&self) -> io::Result<CertContext> {
        CertContext::new(&self.der)
    }
}

/// SHA-256 digest of `data`.
pub(crate) fn sha256(data: &[u8]) -> io::Result<Vec<u8>> {
    digest(DigestAlg::Sha256, data)
}

/// Parse a buffer of one or more concatenated PEM certificates, leaf first.
pub(crate) fn parse_pem_chain(pem: &[u8]) -> io::Result<Vec<Cert>> {
    let blocks = pem_blocks(pem)?;
    if blocks.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no PEM certificates found",
        ));
    }
    blocks.into_iter().map(Cert::from_der).collect()
}

/// Parse a single PEM certificate.
pub(crate) fn cert_from_pem(pem: &[u8]) -> io::Result<Cert> {
    let der = pem_blocks(pem)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no PEM certificate found"))?;
    Cert::from_der(der)
}

/// Encode a certificate as DER.
pub(crate) fn cert_to_der(cert: &Cert) -> io::Result<Vec<u8>> {
    Ok(cert.der.clone())
}

/// Whether `cert` is self-signed (subject == issuer and the signature verifies
/// under its own public key).
pub(crate) fn cert_is_self_signed(cert: &Cert) -> bool {
    let Ok(ctx) = cert.context() else {
        return false;
    };
    issuer_name_matches(&ctx, &ctx) && signature_verifies(&ctx, &ctx)
}

/// Verify an ECDSA signature given raw big-endian `r`/`s` integers over `msg`,
/// using the public key in `cert` and the supplied message digest.
///
/// The curve (P-256 / P-384) is taken from the certificate's public key, so the
/// same routine serves both TDX (P-256/SHA-256) and SEV-SNP (P-384/SHA-384).
pub(crate) fn ecdsa_verify_raw(
    cert: &Cert,
    digest_alg: DigestAlg,
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    let ctx = cert.context()?;
    let spki = &ctx.info().SubjectPublicKeyInfo;
    let curve_len = ec_curve_len(spki.PublicKey.cbData as usize)?;

    let mut key: BCRYPT_KEY_HANDLE = ptr::null_mut();
    let ok =
        unsafe { CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, spki, 0, ptr::null(), &mut key) };
    if ok == 0 {
        return Err(other(
            "import certificate public key",
            io::Error::last_os_error(),
        ));
    }
    let key = KeyHandle(key);
    verify_with_key(&key, curve_len, digest_alg, msg, r_be, s_be)
}

/// Verify an ECDSA P-256/SHA-256 signature (raw big-endian `r`/`s`) over `msg`
/// using a raw uncompressed public point `x_y` (64 bytes, big-endian `x‖y`).
///
/// TDX quotes carry the attestation key as a bare `x‖y` point (not a cert), so
/// this imports it as a `BCRYPT_ECCPUBLIC_BLOB` directly.
pub(crate) fn ecdsa_p256_verify_point(
    x_y: &[u8],
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    if x_y.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("P-256 public point must be 64 bytes, got {}", x_y.len()),
        ));
    }
    let provider = AlgProvider::open(BCRYPT_ECDSA_P256_ALGORITHM)?;

    // BCRYPT_ECCKEY_BLOB { dwMagic, cbKey } followed by big-endian X ‖ Y.
    let mut blob = Vec::with_capacity(8 + x_y.len());
    blob.extend_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&32u32.to_le_bytes());
    blob.extend_from_slice(x_y);

    let mut key: BCRYPT_KEY_HANDLE = ptr::null_mut();
    nt("BCryptImportKeyPair", unsafe {
        BCryptImportKeyPair(
            provider.0,
            ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            &mut key,
            blob.as_ptr(),
            len_u32(blob.len(), "EC public key blob")?,
            0,
        )
    })?;
    let key = KeyHandle(key);
    verify_with_key(&key, 32, DigestAlg::Sha256, msg, r_be, s_be)
}

/// Validate that `leaf` chains up (via `intermediates`) to one of the trusted
/// `roots`, and to nothing else.
///
/// The pinned roots are the *only* trust anchors: the machine certificate store
/// is never consulted, so the chain is built by hand. Every link must have a
/// matching issuer name, a verifying issuer signature and a CA issuer, and every
/// certificate on the path must be within its validity period — the same
/// properties OpenSSL's `X509_verify_cert` enforces by default.
pub(crate) fn verify_cert_chain(
    leaf: &Cert,
    intermediates: &[Cert],
    roots: &[Cert],
) -> io::Result<()> {
    verify_cert_chain_at(leaf, intermediates, roots, None)
}

/// Validate a chain against pinned `roots` at `unix_time`, or the wall clock
/// when `None`. Explicit times must be nonnegative and fit the shared FILETIME
/// range; invalid times return `InvalidInput`. All existing chain checks apply.
pub(crate) fn verify_cert_chain_at(
    leaf: &Cert,
    intermediates: &[Cert],
    roots: &[Cert],
    unix_time: Option<i64>,
) -> io::Result<()> {
    let time = unix_time.map(unix_time_to_filetime).transpose()?;
    if roots.is_empty() {
        return Err(io::Error::other(
            "certificate chain validation failed: no trusted roots supplied",
        ));
    }
    let mut current = leaf.clone();
    for _ in 0..MAX_CHAIN_DEPTH {
        let ctx = current.context()?;
        if !time_valid(&ctx, time.as_ref()) {
            return Err(io::Error::other(
                "certificate chain validation failed: certificate is expired or not yet valid",
            ));
        }
        if let Some(root) = roots.iter().find(|r| issued_by(&ctx, r)) {
            let root_ctx = root.context()?;
            return if time_valid(&root_ctx, time.as_ref()) {
                Ok(())
            } else {
                Err(io::Error::other(
                    "certificate chain validation failed: pinned trust anchor is expired or not yet valid",
                ))
            };
        }
        let next = intermediates
            .iter()
            .find(|c| c.der != current.der && issued_by(&ctx, c));
        match next {
            Some(c) => current = c.clone(),
            None => {
                return Err(io::Error::other(
                    "certificate chain validation failed: chain does not terminate at a pinned trust anchor",
                ))
            }
        }
    }
    Err(io::Error::other(
        "certificate chain validation failed: maximum chain depth exceeded",
    ))
}

// ---------------------------------------------------------------------------
// Chain helpers
// ---------------------------------------------------------------------------

/// Whether `issuer` is a CA that issued `subject`.
fn issued_by(subject: &CertContext, issuer: &Cert) -> bool {
    let Ok(issuer_ctx) = issuer.context() else {
        return false;
    };
    is_ca(&issuer_ctx)
        && issuer_name_matches(subject, &issuer_ctx)
        && signature_verifies(subject, &issuer_ctx)
}

fn issuer_name_matches(subject: &CertContext, issuer: &CertContext) -> bool {
    unsafe {
        CertCompareCertificateName(
            X509_ASN_ENCODING,
            &subject.info().Issuer,
            &issuer.info().Subject,
        ) != 0
    }
}

fn signature_verifies(subject: &CertContext, issuer: &CertContext) -> bool {
    unsafe {
        CryptVerifyCertificateSignatureEx(
            0,
            X509_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
            subject.0 as *const c_void,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
            issuer.0 as *const c_void,
            0,
            ptr::null_mut(),
        ) != 0
    }
}

fn unix_time_to_filetime(unix_time: i64) -> io::Result<FILETIME> {
    let ticks = unix_time_to_filetime_ticks(unix_time)?;
    Ok(FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    })
}

fn time_valid(ctx: &CertContext, time: Option<&FILETIME>) -> bool {
    let time = time.map_or(ptr::null(), ptr::from_ref);
    unsafe { CertVerifyTimeValidity(time, ctx.info()) == 0 }
}

/// Whether the certificate may sign other certificates. X.509 v1 certificates
/// predate `basicConstraints`; OpenSSL accepts them as CAs, so this does too.
fn is_ca(ctx: &CertContext) -> bool {
    let info = ctx.info();
    let ext =
        unsafe { CertFindExtension(szOID_BASIC_CONSTRAINTS2, info.cExtension, info.rgExtension) };
    if ext.is_null() {
        return info.dwVersion == CERT_V1;
    }
    // `CERT_BASIC_CONSTRAINTS2_INFO` needs 4-byte alignment; a u32 buffer gives it.
    let mut buf = [0u32; 8];
    let mut len = std::mem::size_of_val(&buf) as u32;
    let ok = unsafe {
        let value = (*ext).Value;
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_BASIC_CONSTRAINTS2,
            value.pbData,
            value.cbData,
            0,
            ptr::null(),
            buf.as_mut_ptr().cast::<c_void>(),
            &mut len,
        )
    };
    if ok == 0 {
        return false;
    }
    let bc = unsafe { &*buf.as_ptr().cast::<CERT_BASIC_CONSTRAINTS2_INFO>() };
    bc.fCA != 0
}

// ---------------------------------------------------------------------------
// PEM / DER
// ---------------------------------------------------------------------------

fn pem_blocks(pem: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(pem).map_err(|e| other("PEM is not valid UTF-8", e))?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(begin) = rest.find(PEM_BEGIN) {
        let body_start = begin + PEM_BEGIN.len();
        let body_len = rest[body_start..].find(PEM_END).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "PEM certificate is missing its END marker",
            )
        })?;
        let body: String = rest[body_start..body_start + body_len]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        out.push(
            base64::engine::general_purpose::STANDARD
                .decode(&body)
                .map_err(|e| other("decode PEM certificate", e))?,
        );
        rest = &rest[body_start + body_len + PEM_END.len()..];
    }
    Ok(out)
}

/// Byte length of one EC coordinate, derived from the size of the uncompressed
/// `SubjectPublicKey` point (`0x04 ‖ X ‖ Y`).
fn ec_curve_len(public_key_len: usize) -> io::Result<usize> {
    match public_key_len {
        65 => Ok(32),
        97 => Ok(48),
        n => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported EC public key length: {n} bytes"),
        )),
    }
}

/// Normalize a big-endian integer to exactly `len` bytes, as CNG requires.
fn fixed_width_be(value: &[u8], len: usize, what: &str) -> io::Result<Vec<u8>> {
    let trimmed = value
        .iter()
        .position(|&b| b != 0)
        .map_or(&value[..0], |i| &value[i..]);
    if trimmed.len() > len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ECDSA {what} is {} bytes, larger than the {len}-byte curve order",
                trimmed.len()
            ),
        ));
    }
    let mut out = vec![0u8; len - trimmed.len()];
    out.extend_from_slice(trimmed);
    Ok(out)
}

// ---------------------------------------------------------------------------
// CNG primitives
// ---------------------------------------------------------------------------

fn verify_with_key(
    key: &KeyHandle,
    curve_len: usize,
    digest_alg: DigestAlg,
    msg: &[u8],
    r_be: &[u8],
    s_be: &[u8],
) -> io::Result<bool> {
    let mut sig = fixed_width_be(r_be, curve_len, "r")?;
    sig.extend_from_slice(&fixed_width_be(s_be, curve_len, "s")?);
    let dgst = digest(digest_alg, msg)?;
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            ptr::null(),
            dgst.as_ptr(),
            len_u32(dgst.len(), "digest")?,
            sig.as_ptr(),
            len_u32(sig.len(), "signature")?,
            0,
        )
    };
    match status {
        STATUS_SUCCESS => Ok(true),
        STATUS_INVALID_SIGNATURE => Ok(false),
        s => Err(io::Error::other(format!(
            "BCryptVerifySignature failed: {s:#010x}"
        ))),
    }
}

fn digest(alg: DigestAlg, data: &[u8]) -> io::Result<Vec<u8>> {
    let (alg_id, out_len) = match alg {
        DigestAlg::Sha256 => (BCRYPT_SHA256_ALGORITHM, 32usize),
        DigestAlg::Sha384 => (BCRYPT_SHA384_ALGORITHM, 48usize),
    };
    let provider = AlgProvider::open(alg_id)?;
    let mut handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
    nt("BCryptCreateHash", unsafe {
        BCryptCreateHash(
            provider.0,
            &mut handle,
            ptr::null_mut(),
            0,
            ptr::null(),
            0,
            0,
        )
    })?;
    let hash = HashHandle(handle);
    nt("BCryptHashData", unsafe {
        BCryptHashData(hash.0, data.as_ptr(), len_u32(data.len(), "hash input")?, 0)
    })?;
    let mut out = vec![0u8; out_len];
    nt("BCryptFinishHash", unsafe {
        BCryptFinishHash(hash.0, out.as_mut_ptr(), out_len as u32, 0)
    })?;
    Ok(out)
}

fn nt(what: &str, status: NTSTATUS) -> io::Result<()> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what} failed: {status:#010x}")))
    }
}

fn len_u32(len: usize, what: &str) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} is too large ({len} bytes)"),
        )
    })
}

struct CertContext(*const CERT_CONTEXT);

impl CertContext {
    fn new(der: &[u8]) -> io::Result<Self> {
        let ctx = unsafe {
            CertCreateCertificateContext(
                X509_ASN_ENCODING,
                der.as_ptr(),
                len_u32(der.len(), "certificate")?,
            )
        };
        if ctx.is_null() {
            return Err(other("parse DER certificate", io::Error::last_os_error()));
        }
        Ok(Self(ctx))
    }

    fn info(&self) -> &CERT_INFO {
        unsafe { &*(*self.0).pCertInfo }
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

struct AlgProvider(BCRYPT_ALG_HANDLE);

impl AlgProvider {
    fn open(alg_id: PCWSTR) -> io::Result<Self> {
        let mut handle: BCRYPT_ALG_HANDLE = ptr::null_mut();
        nt("BCryptOpenAlgorithmProvider", unsafe {
            BCryptOpenAlgorithmProvider(&mut handle, alg_id, ptr::null(), 0)
        })?;
        Ok(Self(handle))
    }
}

impl Drop for AlgProvider {
    fn drop(&mut self) {
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

struct HashHandle(BCRYPT_HASH_HANDLE);

impl Drop for HashHandle {
    fn drop(&mut self) {
        unsafe { BCryptDestroyHash(self.0) };
    }
}

struct KeyHandle(BCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        unsafe { BCryptDestroyKey(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_time_to_filetime_boundaries() {
        for (seconds, ticks) in [
            (0, 116_444_736_000_000_000u64),
            (1, 116_444_736_010_000_000),
            (910_692_730_085, 9_223_372_036_850_000_000),
        ] {
            let time = unix_time_to_filetime(seconds).unwrap();
            assert_eq!(
                (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime),
                ticks
            );
        }
        for seconds in [-1, i64::MIN, 910_692_730_086, i64::MAX] {
            assert_eq!(
                unix_time_to_filetime(seconds).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn cert_to_der_roundtrip() {
        let pem = include_bytes!("../testdata/snp_vcek_chain_turin.pem");
        let cert = cert_from_pem(pem).unwrap();
        let der = cert_to_der(&cert).unwrap();
        assert_eq!(der, pem_blocks(pem).unwrap()[0]);
        let parsed = Cert::from_der(der.clone()).unwrap();
        assert_eq!(cert_to_der(&parsed).unwrap(), der);
    }

    #[test]
    fn fixed_width_be_pads_and_trims() {
        // SNP hands over 72-byte components that must shrink to the P-384 order.
        let mut wide = vec![0u8; 72];
        wide[70] = 0xab;
        wide[71] = 0xcd;
        let out = fixed_width_be(&wide, 48, "r").unwrap();
        assert_eq!(out.len(), 48);
        assert_eq!(&out[46..], &[0xab, 0xcd]);

        // Short input is left-padded.
        assert_eq!(fixed_width_be(&[0x01], 32, "s").unwrap()[..31], [0u8; 31]);

        // Genuinely oversized input is rejected rather than silently truncated.
        assert!(fixed_width_be(&[0xff; 49], 48, "r").is_err());
    }

    #[test]
    fn pem_blocks_splits_a_chain() {
        let chain = include_bytes!("../testdata/snp_vcek_chain_turin.pem");
        assert!(pem_blocks(chain).unwrap().len() >= 2);
    }
}
