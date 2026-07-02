// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed representations for TDX Quote (version 5) structures as defined in
//! the Intel® TDX DCAP Quote Generation/Verification Library specification
//! (Appendix A.4, Rev 0.9, May 2025).
//!
//! The layout closely mirrors the C structures emitted by the quoting library so
//! the types can be safely transmuted from the raw quote buffer using
//! `ptr::read_unaligned`. Parsing helpers are provided to safely walk a quote
//! without relying on alignment guarantees.

use core::fmt;
use core::mem::size_of;
use core::ptr;
use core::str;
use std::fmt::Write as _;

use crate::tee_report::tdx::TdAttributes;
use hex::encode as hex_encode;

/// Size in bytes of an ECDSA P-256 signature component.
const SGX_ECDSA_SIGNATURE_SIZE: usize = 64;
/// Size in bytes of an uncompressed P-256 public key (X || Y).
const SGX_EC_P256_POINT_SIZE: usize = 64;
/// Size in bytes of an SGX report body embedded in certification data.
const SGX_REPORT_BODY_SIZE: usize = 384;
/// Header size (in bytes) of `sgx_ql_certification_data_t`.
const SGX_QL_CERTIFICATION_DATA_HEADER_SIZE: usize = 6;
/// Header size (in bytes) of `sgx_ql_auth_data_t`.
const SGX_QL_AUTH_DATA_HEADER_SIZE: usize = 2;
/// Certification key type value for a bundled PCK certificate chain.
const SGX_QL_CERT_KEY_TYPE_PCK_CERT_CHAIN: u16 = 5;
/// Certification key type value for ECDSA signature auxiliary data.
const SGX_QL_CERT_KEY_TYPE_ECDSA_SIG_AUX_DATA: u16 = 6;

/// Internal representation of the base TD quote header (versions 4 and 5).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TdQuoteHeaderWireV4 {
    version: u16,
    attestation_key_type: u16,
    tee_type: u32,
    qe_svn: u16,
    pce_svn: u16,
    qe_vendor_id: [u8; 16],
    user_data: [u8; 20],
}

/// Tail fields appended to the header starting in quote version 5.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TdQuoteHeaderWireV5Tail {
    body_type: u16,
    body_size: u32,
}

/// Size in bytes of a version 4 [`TdQuoteHeader`].
pub const TD_QUOTE_HEADER_V4_SIZE: usize = size_of::<TdQuoteHeaderWireV4>();

/// Size in bytes of a version 5 [`TdQuoteHeader`].
pub const TD_QUOTE_HEADER_V5_SIZE: usize =
    size_of::<TdQuoteHeaderWireV4>() + size_of::<TdQuoteHeaderWireV5Tail>();

/// Size in bytes of [`TdQuoteHeader`] for the latest supported version.
pub const TD_QUOTE_HEADER_SIZE: usize = TD_QUOTE_HEADER_V5_SIZE;

/// Size in bytes of the descriptor header (type + size fields preceding the body).
pub const TD_QUOTE_BODY_DESCRIPTOR_HEADER_SIZE: usize = size_of::<TdQuoteBodyDescriptorHeader>();

/// Size in bytes of a TDX 1.0 quote body.
pub const TD_QUOTE_BODY_V1_0_SIZE: usize = size_of::<TdQuoteBodyTdx10>();

/// Size in bytes of a TDX 1.5 quote body.
pub const TD_QUOTE_BODY_V1_5_SIZE: usize = size_of::<TdQuoteBodyTdx15>();

/// Maximum quote body size supported by this module.
pub const TD_QUOTE_BODY_MAX_SIZE: usize = TD_QUOTE_BODY_V1_5_SIZE;

/// Quote body type identifiers for version 5 quotes.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TdQuoteBodyType {
    /// Placeholder for future SGX body support.
    SgxFuture = 1,
    /// TDX Module 1.0 report body (TD Quote Body type 2).
    Tdx10 = 2,
    /// TDX Module 1.5 report body (TD Quote Body type 3).
    Tdx15 = 3,
}

/// Descriptor header preceding the concrete quote body payload.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdQuoteBodyDescriptorHeader {
    /// Body selector – see [`TdQuoteBodyType`].
    pub body_type: u16,
    /// Reserved field – expected zero in well-formed quotes.
    ///
    /// Some migration (MIG) quotes produced by older tooling place the actual
    /// body length in this field and leave the size field with an oversized
    /// value.
    pub reserved: u16,
    /// Size in bytes of the following body payload.
    pub size: u32,
}

impl TdQuoteBodyType {
    fn from_raw(value: u16) -> Option<Self> {
        match value {
            1 => Some(TdQuoteBodyType::SgxFuture),
            2 => Some(TdQuoteBodyType::Tdx10),
            3 => Some(TdQuoteBodyType::Tdx15),
            _ => None,
        }
    }
}

impl From<TdQuoteHeaderWireV4> for TdQuoteHeader {
    fn from(w: TdQuoteHeaderWireV4) -> Self {
        Self {
            version: w.version,
            attestation_key_type: w.attestation_key_type,
            tee_type: w.tee_type,
            qe_svn: w.qe_svn,
            pce_svn: w.pce_svn,
            qe_vendor_id: w.qe_vendor_id,
            user_data: w.user_data,
            body_type: 0,
            body_size: 0,
        }
    }
}

/// Quote header shared between SGX and TDX quotes (version 5 layout).
///
/// For version 5 quotes the descriptor information (body type and size) is
/// appended to the 48-byte legacy header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdQuoteHeader {
    /// Quote version (value 5 for v5 quotes).
    pub version: u16,
    /// Attestation key algorithm identifier (2 = ECDSA-P256).
    pub attestation_key_type: u16,
    /// TEE type (0 = SGX, 0x81 = TDX).
    pub tee_type: u32,
    /// Historically the QE SVN; reserved and set to zero for TDX quotes.
    pub qe_svn: u16,
    /// Historically the PCE SVN; reserved and set to zero for TDX quotes.
    pub pce_svn: u16,
    /// Quoting Enclave vendor identifier.
    pub qe_vendor_id: [u8; 16],
    /// Vendor specific user data (first 16 bytes are the platform identifier for Intel DCAP).
    pub user_data: [u8; 20],
    /// Body selector – see [`TdQuoteBodyType`].
    pub body_type: u16,
    /// Size in bytes of the following body payload.
    pub body_size: u32,
}

/// TDX quote body for module version 1.0 (body type 2).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdQuoteBodyTdx10 {
    /// TEE_TCB_SVN Array
    pub tee_tcb_svn: [u8; 16],
    /// Measurement of the SEAM module
    pub mr_seam: [u8; 48],
    /// Measurement of a 3rd party SEAM module’s signer (SHA384 hash).
    /// The value is 0’ed for Intel SEAM module
    pub mr_signer_seam: [u8; 48],
    /// MBZ: TDX 1.0
    pub seam_attributes: [u8; 8],
    /// TD's attributes
    pub td_attributes: [u8; 8],
    /// TD's XFAM
    pub xfam: [u8; 8],
    /// Measurement of the initial contents of the TD
    pub mr_td: [u8; 48],
    /// Software defined ID for non-owner-defined configuration on the
    /// guest TD. e.g., runtime or OS configuration
    pub mr_config_id: [u8; 48],
    /// Software defined ID for the guest TD's owner
    pub mr_owner: [u8; 48],
    /// Software defined ID for owner-defined configuration of the guest
    /// TD, e.g., specific to the workload rather than the runtime or OS
    pub mr_owner_config: [u8; 48],
    /// Runtime extendable measurement register 0
    pub rtmr0: [u8; 48],
    /// Runtime extendable measurement register 1
    pub rtmr1: [u8; 48],
    /// Runtime extendable measurement register 2
    pub rtmr2: [u8; 48],
    /// Runtime extendable measurement register 3
    pub rtmr3: [u8; 48],
    /// Additional report data
    pub report_data: [u8; 64],
}

/// TDX quote body for module version 1.5 (body type 3).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdQuoteBodyTdx15 {
    /// TDX 1.0 base body fields.
    pub base: TdQuoteBodyTdx10,
    /// Array of TEE TCB SVNs (for TD preserving).
    pub tee_tcb_svn_2: [u8; 16],
    /// If is one or more bound or pre-bound service TDs, SERVTD_HASH is the SHA384 hash of the TDINFO_STRUCTs of those service TDs bound.
    /// Else, SERVTD_HASH is 0..
    pub mr_service_td: [u8; 48],
}

/// Parsed view over a TDX Quote (version 5).
#[derive(Debug)]
pub struct ParsedTdQuote<'a> {
    /// Fixed header copied out of the quote.
    pub header: TdQuoteHeader,
    /// Descriptor header copied out of the quote.
    pub body_header: TdQuoteBodyDescriptorHeader,
    /// Decoded body variant or raw bytes if the type is unknown.
    pub body: TdQuoteBody<'a>,
    /// Length of the signature/certification blob in bytes.
    pub signature_data_len: u32,
    /// Raw signature blob (Quote Signature Data).
    pub signature_data: &'a [u8],
    /// Decoded view of the signature and certification data, if parsing succeeded.
    pub signature: Option<TdQuoteSignature<'a>>,
    /// Error encountered while parsing the signature blob (kept for diagnostics).
    pub signature_parse_error: Option<TdQuoteSignatureError>,
    /// Any trailing bytes beyond the declared signature length (should be empty).
    pub remainder: &'a [u8],
}

/// Quote body variants returned by [`parse_td_quote`].
#[derive(Debug)]
pub enum TdQuoteBody<'a> {
    /// TDX Module 1.0 body.
    Tdx10(TdQuoteBodyTdx10),
    /// TDX Module 1.5 body.
    Tdx15(TdQuoteBodyTdx15),
    /// Unrecognised body type – returns the raw payload for external handling.
    Unknown {
        /// Body type identifier.
        body_type: u16,
        /// Raw payload bytes.
        bytes: &'a [u8],
    },
}

/// Errors returned when parsing a raw TD quote.
#[derive(Debug)]
pub enum TdQuoteParseError {
    /// The buffer ended prematurely while reading a particular component.
    Truncated(&'static str),
    /// The body size does not match the expected layout for the advertised type.
    InvalidBodySize {
        /// Advertised body type identifier.
        body_type: u16,
        /// Expected size for the body type.
        expected: usize,
        /// Actual size found in the buffer.
        actual: usize,
    },
}

impl fmt::Display for TdQuoteParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TdQuoteParseError::Truncated(what) => {
                write!(f, "buffer too short while reading {what}")
            }
            TdQuoteParseError::InvalidBodySize {
                body_type,
                expected,
                actual,
            } => write!(
                f,
                "body type 0x{body_type:04x} has size {actual}, expected {expected}",
            ),
        }
    }
}

impl std::error::Error for TdQuoteParseError {}

/// Errors returned when parsing the structured signature segment.
#[derive(Debug)]
pub enum TdQuoteSignatureError {
    /// The buffer ended prematurely while reading a particular component.
    Truncated(&'static str),
    /// A structural invariant was violated.
    InvalidFormat(&'static str),
}

impl fmt::Display for TdQuoteSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TdQuoteSignatureError::Truncated(what) => {
                write!(f, "buffer too short while reading {what}")
            }
            TdQuoteSignatureError::InvalidFormat(what) => {
                write!(f, "malformed {what}")
            }
        }
    }
}

impl std::error::Error for TdQuoteSignatureError {}

/// Parsed representation of the quote signature block.
#[derive(Debug)]
pub struct TdQuoteSignature<'a> {
    /// ECDSA signature over the quote body (64 bytes, big endian components).
    pub signature: [u8; SGX_ECDSA_SIGNATURE_SIZE],
    /// Uncompressed P-256 attestation public key associated with the quote.
    pub attestation_public_key: [u8; SGX_EC_P256_POINT_SIZE],
    /// Certification payload describing how the attestation key was provisioned.
    pub certification: Option<TdQuoteCertification<'a>>,
    /// Any bytes left after processing the expected payload (should be empty).
    pub remainder: &'a [u8],
}

/// Parsed certification variants found within the signature block.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TdQuoteCertification<'a> {
    /// ECDSA auxiliary data containing QE report, auth data, and nested certs.
    EcdsaSigAux(TdQuoteEcdsaCertification<'a>),
    /// All other certification payloads are exposed as raw blobs.
    Raw {
        /// Certification key type identifier.
        cert_key_type: u16,
        /// Payload bytes associated with the type.
        data: &'a [u8],
    },
}

/// Nested certification data that accompanies the ECDSA auxiliary block.
#[derive(Debug)]
pub struct TdQuoteEcdsaCertification<'a> {
    /// Quoting Enclave report body included as part of attestation provenance.
    pub qe_report: [u8; SGX_REPORT_BODY_SIZE],
    /// Signature over `qe_report` by the platform certification key (PCK).
    pub qe_report_signature: [u8; SGX_ECDSA_SIGNATURE_SIZE],
    /// Optional authentication data supplied by the attestation key owner.
    pub auth_data: &'a [u8],
    /// Nested certification element (typically the PCK certificate chain).
    pub nested_certification: Option<TdQuoteEcdsaNestedCertification<'a>>,
    /// Any trailing bytes after parsing the expected structure (should be empty).
    pub remainder: &'a [u8],
}

/// Known nested certification payloads inside [`TdQuoteEcdsaCertification`].
#[derive(Debug)]
pub enum TdQuoteEcdsaNestedCertification<'a> {
    /// PCK certificate chain (typically PEM encoded) with optional QE identity payload.
    PckCertChain(TdQuotePckCertChain<'a>),
    /// Other certification payload types are surfaced as raw bytes.
    Raw {
        /// Certification key type identifier.
        cert_key_type: u16,
        /// Payload bytes.
        data: &'a [u8],
    },
}

/// Structured view of the PCK certificate chain payload (type 5).
#[derive(Debug)]
pub struct TdQuotePckCertChain<'a> {
    /// Raw certificate chain bytes (either PEM text or concatenated DER).
    pub cert_chain: &'a [u8],
    /// Optional QE identity structure appended by the quoting library.
    pub qe_identity: Option<&'a [u8]>,
    /// Any remaining bytes beyond the parsed fields.
    pub remainder: &'a [u8],
}

/// Controls how [`parse_td_quote_with_options`] treats the signature segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TdQuoteSignatureMode {
    /// Require the signature length field and payload to be fully present.
    Strict,
    /// Allow the signature portion to be missing or shorter than declared.
    AllowMissing,
}

/// Parse a raw TD quote (version 5) into structured components.
///
/// The returned view borrows from the original byte slice for the signature
/// payload (to avoid unnecessary allocations) while copying the fixed-size
/// header and known body layouts.
///
/// # Errors
///
/// Returns [`TdQuoteParseError::Truncated`] if the buffer is too small or
/// [`TdQuoteParseError::InvalidBodySize`] if the body length does not match the
/// expected layout for a recognised type.
pub fn parse_td_quote(bytes: &[u8]) -> Result<ParsedTdQuote<'_>, TdQuoteParseError> {
    parse_td_quote_with_options(bytes, TdQuoteSignatureMode::Strict)
}

/// Variant of [`parse_td_quote`] that accepts parsing options.
pub fn parse_td_quote_with_options(
    bytes: &[u8],
    signature_mode: TdQuoteSignatureMode,
) -> Result<ParsedTdQuote<'_>, TdQuoteParseError> {
    let mut cursor = 0usize;

    let header_base = read_unaligned::<TdQuoteHeaderWireV4>(bytes, &mut cursor, "TD quote header")?;
    let mut header: TdQuoteHeader = header_base.into();

    if header.version >= 5 {
        let tail = read_unaligned::<TdQuoteHeaderWireV5Tail>(
            bytes,
            &mut cursor,
            "TD quote header (v5 tail)",
        )?;
        header.body_type = tail.body_type;
        header.body_size = tail.body_size;
    }

    let mut body_header = TdQuoteBodyDescriptorHeader {
        body_type: header.body_type,
        reserved: 0,
        size: header.body_size,
    };

    if header.version <= 4 {
        body_header.body_type = TdQuoteBodyType::Tdx10 as u16;
        body_header.size = TD_QUOTE_BODY_V1_0_SIZE as u32;
        header.body_type = body_header.body_type;
        header.body_size = body_header.size;
    } else if body_header.body_type == 0 && body_header.size == 0 {
        body_header =
            read_unaligned::<TdQuoteBodyDescriptorHeader>(bytes, &mut cursor, "quote body header")?;
        header.body_type = body_header.body_type;
        header.body_size = body_header.size;
    }

    let mut body_size = body_header.size as usize;
    let remaining = bytes.len().saturating_sub(cursor);
    if body_size > remaining {
        let fallback_size = body_header.reserved as usize;
        let fallback_known =
            fallback_size == TD_QUOTE_BODY_V1_0_SIZE || fallback_size == TD_QUOTE_BODY_V1_5_SIZE;
        if fallback_known && fallback_size <= remaining {
            body_size = fallback_size;
            body_header.size = fallback_size as u32;
            header.body_size = body_header.size;
        } else if header.body_size != 0
            && (header.body_size as usize) <= remaining
            && body_header.body_type != 0
        {
            body_size = header.body_size as usize;
            body_header.size = header.body_size;
        }
    }

    if bytes.len() < cursor + body_size {
        return Err(TdQuoteParseError::Truncated("TD quote body"));
    }
    let body_slice = &bytes[cursor..cursor + body_size];
    cursor += body_size;

    let body = match TdQuoteBodyType::from_raw(body_header.body_type) {
        Some(TdQuoteBodyType::Tdx10) => {
            if body_size != TD_QUOTE_BODY_V1_0_SIZE {
                return Err(TdQuoteParseError::InvalidBodySize {
                    body_type: body_header.body_type,
                    expected: TD_QUOTE_BODY_V1_0_SIZE,
                    actual: body_size,
                });
            }
            TdQuoteBody::Tdx10(read_unaligned_slice::<TdQuoteBodyTdx10>(body_slice))
        }
        Some(TdQuoteBodyType::Tdx15) => {
            if body_size != TD_QUOTE_BODY_V1_5_SIZE {
                return Err(TdQuoteParseError::InvalidBodySize {
                    body_type: body_header.body_type,
                    expected: TD_QUOTE_BODY_V1_5_SIZE,
                    actual: body_size,
                });
            }
            TdQuoteBody::Tdx15(read_unaligned_slice::<TdQuoteBodyTdx15>(body_slice))
        }
        Some(TdQuoteBodyType::SgxFuture) | None => TdQuoteBody::Unknown {
            body_type: body_header.body_type,
            bytes: body_slice,
        },
    };

    let (signature_data_len, signature_data, remainder) =
        read_signature(bytes, &mut cursor, signature_mode)?;

    let (signature, signature_parse_error) = match parse_quote_signature(signature_data) {
        Ok(sig) => (sig, None),
        Err(err) => (None, Some(err)),
    };

    Ok(ParsedTdQuote {
        header,
        body_header,
        body,
        signature_data_len,
        signature_data,
        signature,
        signature_parse_error,
        remainder,
    })
}

/// Render a parsed TD quote into a human-readable multi-line summary.
pub fn pretty_td_quote(parsed: &ParsedTdQuote<'_>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "TD Quote v{} (TEE type 0x{:08x}, attestation key type 0x{:04x})",
        parsed.header.version, parsed.header.tee_type, parsed.header.attestation_key_type
    );
    let _ = writeln!(
        out,
        "  QE Vendor ID: {}",
        format_uuid(&parsed.header.qe_vendor_id)
    );
    let _ = writeln!(out, "  User Data: {}", hex_encode(parsed.header.user_data));
    let _ = writeln!(
        out,
        "  Body Type: 0x{:04x} ({}), declared size {} bytes",
        parsed.body_header.body_type,
        body_type_label(parsed.body_header.body_type),
        parsed.body_header.size
    );
    match &parsed.body {
        TdQuoteBody::Tdx10(body) => {
            append_tdx_body(&mut out, body);
        }
        TdQuoteBody::Tdx15(body) => {
            append_tdx_body(&mut out, &body.base);
            fmt_hex_block(&mut out, "  tee_tcb_svn_2", &body.tee_tcb_svn_2);
            fmt_hex_block(&mut out, "  mr_service_td", &body.mr_service_td);
        }
        TdQuoteBody::Unknown {
            body_type: _,
            bytes,
        } => {
            fmt_hex_block(&mut out, "  body (raw)", bytes);
        }
    }
    let _ = writeln!(
        out,
        "  Signature Data Length: {} bytes",
        parsed.signature_data_len
    );
    fmt_hex_block(&mut out, "  signature_data", parsed.signature_data);
    match (&parsed.signature, &parsed.signature_parse_error) {
        (Some(sig), _) => {
            fmt_hex_block(&mut out, "  quote_signature", &sig.signature);
            fmt_hex_block(
                &mut out,
                "  attestation_public_key",
                &sig.attestation_public_key,
            );
            if let Some(cert) = &sig.certification {
                append_certification(&mut out, cert);
            }
            if !sig.remainder.is_empty() {
                fmt_hex_block(&mut out, "  signature_remainder", sig.remainder);
            }
        }
        (None, Some(err)) => {
            let _ = writeln!(out, "  Signature parse error: {err}");
        }
        (None, None) => {}
    }
    if !parsed.remainder.is_empty() {
        fmt_hex_block(&mut out, "  trailing_bytes", parsed.remainder);
    }
    out
}

fn append_tdx_body(out: &mut String, body: &TdQuoteBodyTdx10) {
    fmt_hex_block(out, "  tee_tcb_svn", &body.tee_tcb_svn);
    fmt_hex_block(out, "  mr_seam", &body.mr_seam);
    fmt_hex_block(out, "  mr_signer_seam", &body.mr_signer_seam);
    fmt_hex_block(out, "  seam_attributes", &body.seam_attributes);
    fmt_td_attributes(out, &body.td_attributes);
    fmt_hex_block(out, "  xfam", &body.xfam);
    fmt_hex_block(out, "  mr_td", &body.mr_td);
    fmt_hex_block(out, "  mr_config_id", &body.mr_config_id);
    fmt_hex_block(out, "  mr_owner", &body.mr_owner);
    fmt_hex_block(out, "  mr_owner_config", &body.mr_owner_config);
    fmt_hex_block(out, "  rtmr0", &body.rtmr0);
    fmt_hex_block(out, "  rtmr1", &body.rtmr1);
    fmt_hex_block(out, "  rtmr2", &body.rtmr2);
    fmt_hex_block(out, "  rtmr3", &body.rtmr3);
    fmt_hex_block(out, "  report_data", &body.report_data);
}

fn fmt_td_attributes(out: &mut String, bytes: &[u8; 8]) {
    let raw = u64::from_le_bytes(*bytes);
    let attrs = TdAttributes::from_bits(raw);
    let named_flags = [
        (0u8, "debug", attrs.debug()),
        (4, "hgs_plus_prof", attrs.hgs_plus_prof()),
        (5, "perf_prof", attrs.perf_prof()),
        (6, "pmt_prof", attrs.pmt_prof()),
        (27, "lass", attrs.lass()),
        (28, "sept_ve_disable", attrs.sept_ve_disable()),
        (29, "migratable", attrs.migratable()),
        (30, "pks", attrs.pks()),
        (31, "kl", attrs.kl()),
        (62, "tpa", attrs.tpa()),
        (63, "perfmon", attrs.perfmon()),
    ];

    let mut flags: Vec<String> = Vec::new();
    let mut known_mask = 0u64;
    for (bit, name, set) in named_flags {
        known_mask |= 1u64 << bit;
        if set {
            flags.push(format!("{name} (bit {bit})"));
        }
    }

    let flags_display = if flags.is_empty() {
        String::from("none")
    } else {
        flags.join(", ")
    };

    let _ = writeln!(out, "  td_attributes: 0x{raw:016x}");
    let _ = writeln!(out, "    flags: {flags_display}");
    let unknown_bits = raw & !known_mask;
    if unknown_bits != 0 {
        let _ = writeln!(out, "    unknown_bits: 0x{unknown_bits:016x}");
    }
}

fn body_type_label(body_type: u16) -> &'static str {
    match TdQuoteBodyType::from_raw(body_type) {
        Some(TdQuoteBodyType::SgxFuture) => "SGX future body",
        Some(TdQuoteBodyType::Tdx10) => "TDX 1.0",
        Some(TdQuoteBodyType::Tdx15) => "TDX 1.5",
        None => "unknown",
    }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return String::from("00000000-0000-0000-0000-000000000000");
    }
    let mut uuid = String::with_capacity(36);
    let segments = [
        &bytes[0..4],
        &bytes[4..6],
        &bytes[6..8],
        &bytes[8..10],
        &bytes[10..16],
    ];
    for (i, segment) in segments.iter().enumerate() {
        if i != 0 {
            uuid.push('-');
        }
        uuid.push_str(&hex_encode(segment));
    }
    uuid
}

fn fmt_hex_block(out: &mut String, label: &str, bytes: &[u8]) {
    let _ = writeln!(out, "{label} ({} bytes):", bytes.len());
    for chunk in bytes.chunks(32) {
        let _ = write!(out, "    ");
        for b in chunk {
            let _ = write!(out, "{b:02x}");
        }
        let _ = writeln!(out);
    }
}

fn fmt_pem_or_hex(out: &mut String, label: &str, bytes: &[u8]) {
    if let Ok(text) = str::from_utf8(bytes) {
        if looks_like_pem(text) {
            fmt_text_block(out, label, text);
            return;
        }
    }
    fmt_hex_block(out, label, bytes);
}

fn fmt_utf8_or_hex(out: &mut String, label: &str, bytes: &[u8]) {
    if let Ok(text) = str::from_utf8(bytes) {
        if is_mostly_printable_text(text) {
            fmt_text_block(out, label, text);
            return;
        }
    }
    fmt_hex_block(out, label, bytes);
}

fn fmt_text_block(out: &mut String, label: &str, text: &str) {
    let _ = writeln!(out, "{label} ({} bytes):", text.len());
    let mut any_lines = false;
    for line in text.lines() {
        any_lines = true;
        let sanitized = line.trim_end_matches('\r');
        let _ = writeln!(out, "    {sanitized}");
    }
    if !any_lines {
        let _ = writeln!(out, "    (empty)");
    }
}

fn looks_like_pem(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.contains("-----BEGIN CERTIFICATE-----") && trimmed.contains("-----END CERTIFICATE-----")
}

fn is_mostly_printable_text(text: &str) -> bool {
    text.chars()
        .all(|c| matches!(c, '\n' | '\r' | '\t' | ' '..='~'))
}

fn append_certification(out: &mut String, cert: &TdQuoteCertification<'_>) {
    match cert {
        TdQuoteCertification::EcdsaSigAux(ecdsa) => {
            fmt_hex_block(out, "  qe_report", &ecdsa.qe_report);
            fmt_hex_block(out, "  qe_report_signature", &ecdsa.qe_report_signature);
            fmt_hex_block(out, "  auth_data", ecdsa.auth_data);
            if let Some(nested) = &ecdsa.nested_certification {
                match nested {
                    TdQuoteEcdsaNestedCertification::PckCertChain(chain) => {
                        append_pck_cert_chain(out, chain);
                    }
                    TdQuoteEcdsaNestedCertification::Raw {
                        cert_key_type,
                        data,
                    } => {
                        let _ = writeln!(out, "  nested_certification_type: 0x{cert_key_type:04x}");
                        fmt_hex_block(out, "  nested_certification_data", data);
                    }
                }
            }
            if !ecdsa.remainder.is_empty() {
                fmt_hex_block(out, "  certification_remainder", ecdsa.remainder);
            }
        }
        TdQuoteCertification::Raw {
            cert_key_type,
            data,
        } => {
            let _ = writeln!(out, "  certification_type: 0x{cert_key_type:04x}");
            fmt_hex_block(out, "  certification_data", data);
        }
    }
}

fn append_pck_cert_chain(out: &mut String, chain: &TdQuotePckCertChain<'_>) {
    fmt_pem_or_hex(out, "  pck_cert_chain", chain.cert_chain);
    match first_certificate_der(chain.cert_chain).and_then(|der| extract_fmspc_from_cert_der(&der))
    {
        Ok(fmspc) => {
            let _ = writeln!(out, "  fmspc: {}", hex_encode(fmspc));
        }
        Err(err) => {
            let _ = writeln!(out, "  fmspc: <unavailable: {err}>");
        }
    }
    if let Some(identity) = chain.qe_identity {
        fmt_utf8_or_hex(out, "  qe_identity", identity);
    }
    if !chain.remainder.is_empty() {
        fmt_hex_block(out, "  pck_cert_chain_remainder", chain.remainder);
    }
}

fn parse_quote_signature(
    signature_data: &[u8],
) -> Result<Option<TdQuoteSignature<'_>>, TdQuoteSignatureError> {
    if signature_data.is_empty() {
        return Ok(None);
    }

    if signature_data.len() < SGX_ECDSA_SIGNATURE_SIZE + SGX_EC_P256_POINT_SIZE {
        return Err(TdQuoteSignatureError::Truncated(
            "quote signature components",
        ));
    }

    let mut cursor = ByteCursor::new(signature_data);
    let signature = cursor.take_array::<SGX_ECDSA_SIGNATURE_SIZE>("quote signature")?;
    let attestation_public_key =
        cursor.take_array::<SGX_EC_P256_POINT_SIZE>("attestation public key")?;

    let certification = if cursor.remaining().is_empty() {
        None
    } else {
        Some(parse_certification(&mut cursor)?)
    };

    let remainder = cursor.remaining();
    Ok(Some(TdQuoteSignature {
        signature,
        attestation_public_key,
        certification,
        remainder,
    }))
}

fn parse_certification<'a>(
    cursor: &mut ByteCursor<'a>,
) -> Result<TdQuoteCertification<'a>, TdQuoteSignatureError> {
    if cursor.remaining().len() < SGX_QL_CERTIFICATION_DATA_HEADER_SIZE {
        return Err(TdQuoteSignatureError::Truncated(
            "certification data header",
        ));
    }

    let cert_key_type = cursor.take_u16("certification data type")?;
    let cert_size = cursor.take_u32("certification data size")? as usize;
    let payload = cursor.take(cert_size, "certification data payload")?;

    match cert_key_type {
        SGX_QL_CERT_KEY_TYPE_ECDSA_SIG_AUX_DATA => parse_ecdsa_sig_aux(payload),
        other => Ok(TdQuoteCertification::Raw {
            cert_key_type: other,
            data: payload,
        }),
    }
}

fn parse_ecdsa_sig_aux(payload: &[u8]) -> Result<TdQuoteCertification<'_>, TdQuoteSignatureError> {
    if payload.len()
        < SGX_REPORT_BODY_SIZE + SGX_ECDSA_SIGNATURE_SIZE + SGX_QL_AUTH_DATA_HEADER_SIZE
    {
        return Err(TdQuoteSignatureError::Truncated(
            "QE report certification data",
        ));
    }

    let mut cursor = ByteCursor::new(payload);
    let qe_report = cursor.take_array::<SGX_REPORT_BODY_SIZE>("QE report")?;
    let qe_report_signature =
        cursor.take_array::<SGX_ECDSA_SIGNATURE_SIZE>("QE report signature")?;
    let auth_size = cursor.take_u16("auth data size")? as usize;
    let auth_data = cursor.take(auth_size, "auth data")?;

    let nested_certification = if cursor.remaining().is_empty() {
        None
    } else {
        if cursor.remaining().len() < SGX_QL_CERTIFICATION_DATA_HEADER_SIZE {
            return Err(TdQuoteSignatureError::Truncated(
                "nested certification data header",
            ));
        }
        let nested_type = cursor.take_u16("nested certification type")?;
        let nested_size = cursor.take_u32("nested certification size")? as usize;
        let nested_payload = cursor.take(nested_size, "nested certification payload")?;
        let nested = match nested_type {
            SGX_QL_CERT_KEY_TYPE_PCK_CERT_CHAIN => match parse_pck_cert_chain(nested_payload) {
                Ok(chain) => TdQuoteEcdsaNestedCertification::PckCertChain(chain),
                Err(_) => TdQuoteEcdsaNestedCertification::Raw {
                    cert_key_type: nested_type,
                    data: nested_payload,
                },
            },
            other => TdQuoteEcdsaNestedCertification::Raw {
                cert_key_type: other,
                data: nested_payload,
            },
        };
        Some(nested)
    };

    let remainder = cursor.remaining();

    Ok(TdQuoteCertification::EcdsaSigAux(
        TdQuoteEcdsaCertification {
            qe_report,
            qe_report_signature,
            auth_data,
            nested_certification,
            remainder,
        },
    ))
}

fn parse_pck_cert_chain(payload: &[u8]) -> Result<TdQuotePckCertChain<'_>, TdQuoteSignatureError> {
    if payload.len() < 2 {
        return Ok(TdQuotePckCertChain {
            cert_chain: payload,
            qe_identity: None,
            remainder: &[],
        });
    }

    let declared_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if declared_len == 0 || declared_len > payload.len() - 2 {
        return Ok(TdQuotePckCertChain {
            cert_chain: payload,
            qe_identity: None,
            remainder: &[],
        });
    }

    let mut offset = 2;
    if payload.len() < offset + declared_len {
        return Err(TdQuoteSignatureError::Truncated("PCK cert chain payload"));
    }
    let cert_chain = &payload[offset..offset + declared_len];
    offset += declared_len;

    let mut qe_identity = None;
    if payload.len() >= offset + 2 {
        let qe_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if qe_len > 0 {
            if payload.len() < offset + qe_len {
                return Err(TdQuoteSignatureError::Truncated("QE identity payload"));
            }
            qe_identity = Some(&payload[offset..offset + qe_len]);
            offset += qe_len;
        }
    }

    let remainder = &payload[offset..];
    Ok(TdQuotePckCertChain {
        cert_chain,
        qe_identity,
        remainder,
    })
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn take(
        &mut self,
        len: usize,
        context: &'static str,
    ) -> Result<&'a [u8], TdQuoteSignatureError> {
        if self.bytes.len() < self.offset + len {
            return Err(TdQuoteSignatureError::Truncated(context));
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    fn take_array<const N: usize>(
        &mut self,
        context: &'static str,
    ) -> Result<[u8; N], TdQuoteSignatureError> {
        let slice = self.take(N, context)?;
        let mut buf = [0u8; N];
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn take_u16(&mut self, context: &'static str) -> Result<u16, TdQuoteSignatureError> {
        let bytes = self.take(2, context)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(&mut self, context: &'static str) -> Result<u32, TdQuoteSignatureError> {
        let bytes = self.take(4, context)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

fn read_unaligned<T: Copy>(
    bytes: &[u8],
    cursor: &mut usize,
    context: &'static str,
) -> Result<T, TdQuoteParseError> {
    let size = size_of::<T>();
    if bytes.len() < *cursor + size {
        return Err(TdQuoteParseError::Truncated(context));
    }
    let ptr = bytes[*cursor..*cursor + size].as_ptr() as *const T;
    let value = unsafe { ptr::read_unaligned(ptr) };
    *cursor += size;
    Ok(value)
}

fn read_unaligned_slice<T: Copy + Sized>(slice: &[u8]) -> T {
    debug_assert_eq!(slice.len(), size_of::<T>());
    let ptr = slice.as_ptr() as *const T;
    unsafe { ptr::read_unaligned(ptr) }
}

fn read_signature<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    mode: TdQuoteSignatureMode,
) -> Result<(u32, &'a [u8], &'a [u8]), TdQuoteParseError> {
    if bytes.len() < *cursor + 4 {
        return match mode {
            TdQuoteSignatureMode::Strict => {
                Err(TdQuoteParseError::Truncated("quote signature length"))
            }
            TdQuoteSignatureMode::AllowMissing => {
                let remainder = &bytes[*cursor..];
                *cursor = bytes.len();
                Ok((0, &[], remainder))
            }
        };
    }

    let declared_len = u32::from_le_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]);
    *cursor += 4;
    let sig_len = declared_len as usize;

    if bytes.len() < *cursor + sig_len {
        return match mode {
            TdQuoteSignatureMode::Strict => {
                Err(TdQuoteParseError::Truncated("quote signature blob"))
            }
            TdQuoteSignatureMode::AllowMissing => {
                let available = bytes.len().saturating_sub(*cursor);
                let signature_data = &bytes[*cursor..];
                *cursor = bytes.len();
                Ok((available as u32, signature_data, &[]))
            }
        };
    }

    let signature_data = &bytes[*cursor..*cursor + sig_len];
    *cursor += sig_len;
    let remainder = &bytes[*cursor..];
    Ok((declared_len, signature_data, remainder))
}

/// Length in bytes of an FMSPC (Family/Model/Stepping/Platform/CustomSKU) value.
pub const FMSPC_LEN: usize = 6;

/// DER-encoded Intel SGX certificate extension OID (`1.2.840.113741.1.13.1`).
const OID_INTEL_SGX_EXTENSION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01];

/// DER-encoded FMSPC OID (`1.2.840.113741.1.13.1.4`) inside the SGX extension.
const OID_INTEL_SGX_FMSPC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04];

const DER_TAG_BOOLEAN: u8 = 0x01;
const DER_TAG_OID: u8 = 0x06;
const DER_TAG_OCTET_STRING: u8 = 0x04;
const DER_TAG_SEQUENCE: u8 = 0x30;
const DER_TAG_CONTEXT_3_EXPLICIT: u8 = 0xA3;

/// Errors returned when extracting an FMSPC from a TD quote.
#[derive(Debug)]
pub enum FmspcExtractError {
    /// The quote did not carry an ECDSA PCK certificate chain.
    NoPckCertChain,
    /// The PCK certificate chain payload was not valid PEM or DER.
    InvalidCertChain,
    /// The PCK leaf certificate could not be walked as a DER X.509 structure.
    InvalidCertificate(&'static str),
    /// The PCK leaf certificate did not carry the Intel SGX extension.
    NoSgxExtension,
    /// The Intel SGX extension did not contain an FMSPC entry.
    NoFmspc,
    /// The FMSPC value had an unexpected length (Intel mandates 6 bytes).
    InvalidFmspcLength(usize),
}

impl fmt::Display for FmspcExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FmspcExtractError::NoPckCertChain => {
                f.write_str("quote does not carry an ECDSA PCK certificate chain")
            }
            FmspcExtractError::InvalidCertChain => {
                f.write_str("PCK certificate chain is not valid PEM or DER")
            }
            FmspcExtractError::InvalidCertificate(what) => {
                write!(f, "malformed PCK certificate ({what})")
            }
            FmspcExtractError::NoSgxExtension => {
                f.write_str("PCK leaf certificate has no Intel SGX extension")
            }
            FmspcExtractError::NoFmspc => f.write_str("Intel SGX extension has no FMSPC entry"),
            FmspcExtractError::InvalidFmspcLength(n) => {
                write!(f, "FMSPC has length {n}, expected {FMSPC_LEN}")
            }
        }
    }
}

impl std::error::Error for FmspcExtractError {}

impl ParsedTdQuote<'_> {
    /// Returns the raw PCK certificate chain bytes (PEM or DER) embedded in
    /// the quote, when present.
    pub fn pck_cert_chain(&self) -> Option<&[u8]> {
        let sig = self.signature.as_ref()?;
        let TdQuoteCertification::EcdsaSigAux(ecdsa) = sig.certification.as_ref()? else {
            return None;
        };
        match ecdsa.nested_certification.as_ref()? {
            TdQuoteEcdsaNestedCertification::PckCertChain(chain) => Some(chain.cert_chain),
            TdQuoteEcdsaNestedCertification::Raw { .. } => None,
        }
    }

    /// Extracts the 6-byte FMSPC from the leaf PCK certificate in the quote's
    /// certification data.
    ///
    /// The FMSPC identifies the platform SKU and is the canonical input for
    /// resolving the silicon generation (e.g. EMR vs GNR) via Intel PCS or
    /// Azure THIM TCB Info.
    pub fn fmspc(&self) -> Result<[u8; FMSPC_LEN], FmspcExtractError> {
        let chain = self
            .pck_cert_chain()
            .ok_or(FmspcExtractError::NoPckCertChain)?;
        let leaf = first_certificate_der(chain)?;
        extract_fmspc_from_cert_der(&leaf)
    }
}

/// Returns the DER bytes of the first certificate in a PEM or DER chain.
fn first_certificate_der(chain: &[u8]) -> Result<Vec<u8>, FmspcExtractError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    if let Ok(text) = str::from_utf8(chain) {
        if let Some(begin) = text.find(BEGIN) {
            let body_start = begin + BEGIN.len();
            let end_rel = text[body_start..]
                .find(END)
                .ok_or(FmspcExtractError::InvalidCertChain)?;
            let b64_body: String = text[body_start..body_start + end_rel]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            use base64::Engine;
            return base64::engine::general_purpose::STANDARD
                .decode(b64_body.as_bytes())
                .map_err(|_| FmspcExtractError::InvalidCertChain);
        }
    }

    if chain.first() != Some(&DER_TAG_SEQUENCE) {
        return Err(FmspcExtractError::InvalidCertChain);
    }
    let (len, len_size) =
        read_der_length(&chain[1..]).map_err(|_| FmspcExtractError::InvalidCertChain)?;
    let total = 1 + len_size + len;
    if chain.len() < total {
        return Err(FmspcExtractError::InvalidCertChain);
    }
    Ok(chain[..total].to_vec())
}

fn extract_fmspc_from_cert_der(cert_der: &[u8]) -> Result<[u8; FMSPC_LEN], FmspcExtractError> {
    let mut outer = DerReader::new(cert_der);
    let cert_inner = outer.expect_tag(DER_TAG_SEQUENCE, "Certificate SEQUENCE")?;

    let mut cert = DerReader::new(cert_inner);
    let tbs_inner = cert.expect_tag(DER_TAG_SEQUENCE, "TBSCertificate SEQUENCE")?;

    let extensions_outer = {
        let mut tbs = DerReader::new(tbs_inner);
        let mut found = None;
        while !tbs.is_empty() {
            let (tag, value) = tbs.read_tlv()?;
            if tag == DER_TAG_CONTEXT_3_EXPLICIT {
                found = Some(value);
                break;
            }
        }
        found.ok_or(FmspcExtractError::NoSgxExtension)?
    };

    let mut wrapper = DerReader::new(extensions_outer);
    let extensions_seq = wrapper.expect_tag(DER_TAG_SEQUENCE, "Extensions SEQUENCE")?;

    let mut exts = DerReader::new(extensions_seq);
    while !exts.is_empty() {
        let (tag, ext_value) = exts.read_tlv()?;
        if tag != DER_TAG_SEQUENCE {
            return Err(FmspcExtractError::InvalidCertificate(
                "expected Extension SEQUENCE",
            ));
        }
        let mut ext = DerReader::new(ext_value);
        let oid_bytes = ext.expect_tag(DER_TAG_OID, "Extension OID")?;
        if oid_bytes != OID_INTEL_SGX_EXTENSION {
            continue;
        }

        let (mut next_tag, mut next_value) = ext.read_tlv()?;
        if next_tag == DER_TAG_BOOLEAN {
            let (t, v) = ext.read_tlv()?;
            next_tag = t;
            next_value = v;
        }
        if next_tag != DER_TAG_OCTET_STRING {
            return Err(FmspcExtractError::InvalidCertificate(
                "expected OCTET STRING extnValue",
            ));
        }

        let mut sgx_reader = DerReader::new(next_value);
        let entries = sgx_reader.expect_tag(DER_TAG_SEQUENCE, "SGX extension SEQUENCE")?;

        let mut entries = DerReader::new(entries);
        while !entries.is_empty() {
            let (entry_tag, entry_value) = entries.read_tlv()?;
            if entry_tag != DER_TAG_SEQUENCE {
                return Err(FmspcExtractError::InvalidCertificate(
                    "expected SGX entry SEQUENCE",
                ));
            }
            let mut entry = DerReader::new(entry_value);
            let entry_oid = entry.expect_tag(DER_TAG_OID, "SGX entry OID")?;
            if entry_oid != OID_INTEL_SGX_FMSPC {
                continue;
            }
            let value = entry.expect_tag(DER_TAG_OCTET_STRING, "FMSPC OCTET STRING")?;
            if value.len() != FMSPC_LEN {
                return Err(FmspcExtractError::InvalidFmspcLength(value.len()));
            }
            let mut out = [0u8; FMSPC_LEN];
            out.copy_from_slice(value);
            return Ok(out);
        }
        return Err(FmspcExtractError::NoFmspc);
    }

    Err(FmspcExtractError::NoSgxExtension)
}

struct DerReader<'a> {
    bytes: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), FmspcExtractError> {
        if self.bytes.is_empty() {
            return Err(FmspcExtractError::InvalidCertificate("truncated TLV"));
        }
        let tag = self.bytes[0];
        let (len, len_size) = read_der_length(&self.bytes[1..])?;
        let header = 1 + len_size;
        if self.bytes.len() < header + len {
            return Err(FmspcExtractError::InvalidCertificate("truncated value"));
        }
        let value = &self.bytes[header..header + len];
        self.bytes = &self.bytes[header + len..];
        Ok((tag, value))
    }

    fn expect_tag(
        &mut self,
        expected: u8,
        what: &'static str,
    ) -> Result<&'a [u8], FmspcExtractError> {
        let (tag, value) = self.read_tlv()?;
        if tag != expected {
            return Err(FmspcExtractError::InvalidCertificate(what));
        }
        Ok(value)
    }
}

fn read_der_length(bytes: &[u8]) -> Result<(usize, usize), FmspcExtractError> {
    if bytes.is_empty() {
        return Err(FmspcExtractError::InvalidCertificate("missing DER length"));
    }
    let first = bytes[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > core::mem::size_of::<usize>() || bytes.len() < 1 + n {
            return Err(FmspcExtractError::InvalidCertificate("invalid DER length"));
        }
        let mut len: usize = 0;
        for &b in &bytes[1..1 + n] {
            len = (len << 8) | b as usize;
        }
        Ok((len, 1 + n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn sizes_match_spec() {
        assert_eq!(TD_QUOTE_HEADER_V4_SIZE, 48);
        assert_eq!(TD_QUOTE_HEADER_V5_SIZE, 54);
        assert_eq!(TD_QUOTE_HEADER_SIZE, TD_QUOTE_HEADER_V5_SIZE);
        assert_eq!(TD_QUOTE_BODY_V1_0_SIZE, 584);
        assert_eq!(TD_QUOTE_BODY_V1_5_SIZE, 648);
        assert_eq!(TD_QUOTE_BODY_DESCRIPTOR_HEADER_SIZE, 8);
    }

    #[test]
    fn body_alignment_is_not_stricter_than_byte() {
        assert!(align_of::<TdQuoteHeader>() <= 4);
        assert!(align_of::<TdQuoteBodyDescriptorHeader>() <= 4);
        assert!(align_of::<TdQuoteBodyTdx10>() <= 8);
    }

    #[test]
    fn parse_minimal_tdx10_quote() {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: TdQuoteBodyType::Tdx10 as u16,
            body_size: TD_QUOTE_BODY_V1_0_SIZE as u32,
        };
        let body = zero_tdx10_body();

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes()); // signature length

        let parsed = parse_td_quote(&quote).expect("parse minimal quote");
        assert_eq!(parsed.header.version, 5);
        assert!(matches!(parsed.body, TdQuoteBody::Tdx10(_)));
        assert_eq!(parsed.signature_data_len, 0);
        assert!(parsed.signature_data.is_empty());
        assert!(parsed.signature.is_none());
        assert!(parsed.signature_parse_error.is_none());
        assert!(parsed.remainder.is_empty());
    }

    #[test]
    fn parse_migratable_tdx15_quote() {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: TdQuoteBodyType::Tdx15 as u16,
            body_size: TD_QUOTE_BODY_V1_5_SIZE as u32,
        };
        let body = TdQuoteBodyTdx15 {
            base: zero_tdx10_body(),
            tee_tcb_svn_2: [0u8; 16],
            mr_service_td: [0u8; 48],
        };

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_td_quote(&quote).expect("parse migratable quote");
        assert_eq!(parsed.body_header.size as usize, TD_QUOTE_BODY_V1_5_SIZE);
        assert!(matches!(parsed.body, TdQuoteBody::Tdx15(_)));
        assert_eq!(parsed.header.body_type, TdQuoteBodyType::Tdx15 as u16);
        assert_eq!(parsed.header.body_size as usize, TD_QUOTE_BODY_V1_5_SIZE);
    }

    #[test]
    fn parse_legacy_descriptor_quote() {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: 0,
            body_size: 0,
        };
        let descriptor = TdQuoteBodyDescriptorHeader {
            body_type: TdQuoteBodyType::Tdx15 as u16,
            reserved: TD_QUOTE_BODY_V1_5_SIZE as u16,
            size: 0x0100_0000,
        };
        let body = TdQuoteBodyTdx15 {
            base: zero_tdx10_body(),
            tee_tcb_svn_2: [0u8; 16],
            mr_service_td: [0u8; 48],
        };

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&descriptor));
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_td_quote(&quote).expect("parse legacy descriptor quote");
        assert_eq!(parsed.body_header.size as usize, TD_QUOTE_BODY_V1_5_SIZE);
        assert!(matches!(parsed.body, TdQuoteBody::Tdx15(_)));
        assert_eq!(parsed.header.body_type, TdQuoteBodyType::Tdx15 as u16);
        assert_eq!(parsed.header.body_size as usize, TD_QUOTE_BODY_V1_5_SIZE);
    }

    #[test]
    fn parse_v4_quote_with_descriptor() {
        let header = TdQuoteHeader {
            version: 4,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: 0,
            body_size: 0,
        };
        let descriptor = TdQuoteBodyDescriptorHeader {
            body_type: TdQuoteBodyType::Tdx10 as u16,
            reserved: TD_QUOTE_BODY_V1_0_SIZE as u16,
            size: TD_QUOTE_BODY_V1_0_SIZE as u32,
        };
        let body = zero_tdx10_body();

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&descriptor));
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_td_quote(&quote).expect("parse v4 quote");
        assert_eq!(parsed.header.version, 4);
        assert_eq!(parsed.body_header.body_type, TdQuoteBodyType::Tdx10 as u16);
        assert_eq!(parsed.body_header.size as usize, TD_QUOTE_BODY_V1_0_SIZE);
        assert!(matches!(parsed.body, TdQuoteBody::Tdx10(_)));
    }

    #[test]
    fn parse_quote_with_signature_details() {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: TdQuoteBodyType::Tdx10 as u16,
            body_size: TD_QUOTE_BODY_V1_0_SIZE as u32,
        };
        let body = zero_tdx10_body();

        let mut sig_blob = Vec::new();
        sig_blob.extend_from_slice(&[0xAA; SGX_ECDSA_SIGNATURE_SIZE]);
        sig_blob.extend_from_slice(&[0xBB; SGX_EC_P256_POINT_SIZE]);

        let auth_payload = [0xCC; 4];
        let pck_chain = b"-----BEGIN CERTIFICATE-----FAKE-----END CERTIFICATE-----";

        let mut cert_payload = Vec::new();
        cert_payload.extend_from_slice(&[0x11; SGX_REPORT_BODY_SIZE]);
        cert_payload.extend_from_slice(&[0x22; SGX_ECDSA_SIGNATURE_SIZE]);
        cert_payload.extend_from_slice(&u16::to_le_bytes(auth_payload.len() as u16));
        cert_payload.extend_from_slice(&auth_payload);
        cert_payload.extend_from_slice(&SGX_QL_CERT_KEY_TYPE_PCK_CERT_CHAIN.to_le_bytes());
        cert_payload.extend_from_slice(&(pck_chain.len() as u32).to_le_bytes());
        cert_payload.extend_from_slice(pck_chain);

        sig_blob.extend_from_slice(&SGX_QL_CERT_KEY_TYPE_ECDSA_SIG_AUX_DATA.to_le_bytes());
        sig_blob.extend_from_slice(&(cert_payload.len() as u32).to_le_bytes());
        sig_blob.extend_from_slice(&cert_payload);

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&(sig_blob.len() as u32).to_le_bytes());
        quote.extend_from_slice(&sig_blob);

        let parsed = parse_td_quote(&quote).expect("parse quote with signature");
        assert_eq!(parsed.signature_data_len as usize, sig_blob.len());
        assert!(parsed.signature_parse_error.is_none());
        let signature = parsed.signature.as_ref().expect("signature present");
        assert_eq!(signature.signature, [0xAA; SGX_ECDSA_SIGNATURE_SIZE]);
        assert_eq!(
            signature.attestation_public_key,
            [0xBB; SGX_EC_P256_POINT_SIZE]
        );
        match signature
            .certification
            .as_ref()
            .expect("certification present")
        {
            TdQuoteCertification::EcdsaSigAux(ecdsa) => {
                assert_eq!(ecdsa.qe_report, [0x11; SGX_REPORT_BODY_SIZE]);
                assert_eq!(ecdsa.qe_report_signature, [0x22; SGX_ECDSA_SIGNATURE_SIZE]);
                assert_eq!(ecdsa.auth_data, auth_payload);
                match ecdsa
                    .nested_certification
                    .as_ref()
                    .expect("nested certification")
                {
                    TdQuoteEcdsaNestedCertification::PckCertChain(chain) => {
                        assert_eq!(chain.cert_chain, pck_chain);
                        assert!(chain.qe_identity.is_none());
                        assert!(chain.remainder.is_empty());
                    }
                    _ => panic!("unexpected nested certification variant"),
                }
                assert!(ecdsa.remainder.is_empty());
            }
            _ => panic!("unexpected certification variant"),
        }
        assert!(signature.remainder.is_empty());

        let rendered = pretty_td_quote(&parsed);
        assert!(rendered.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn parse_v4_quote_without_descriptor() {
        let header = TdQuoteHeader {
            version: 4,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: 0,
            body_size: 0,
        };
        let body = zero_tdx10_body();

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_td_quote(&quote).expect("parse v4 quote without descriptor");
        assert_eq!(parsed.header.version, 4);
        assert_eq!(parsed.body_header.body_type, TdQuoteBodyType::Tdx10 as u16);
        assert_eq!(parsed.body_header.size as usize, TD_QUOTE_BODY_V1_0_SIZE);
        assert!(matches!(parsed.body, TdQuoteBody::Tdx10(_)));
    }

    fn append_header_bytes(buf: &mut Vec<u8>, header: &TdQuoteHeader) {
        let base = TdQuoteHeaderWireV4 {
            version: header.version,
            attestation_key_type: header.attestation_key_type,
            tee_type: header.tee_type,
            qe_svn: header.qe_svn,
            pce_svn: header.pce_svn,
            qe_vendor_id: header.qe_vendor_id,
            user_data: header.user_data,
        };
        buf.extend_from_slice(as_bytes(&base));
        if header.version >= 5 {
            let tail = TdQuoteHeaderWireV5Tail {
                body_type: header.body_type,
                body_size: header.body_size,
            };
            buf.extend_from_slice(as_bytes(&tail));
        }
    }

    fn as_bytes<T: Copy>(value: &T) -> &[u8] {
        unsafe { core::slice::from_raw_parts((value as *const T) as *const u8, size_of::<T>()) }
    }

    fn zero_tdx10_body() -> TdQuoteBodyTdx10 {
        TdQuoteBodyTdx10 {
            tee_tcb_svn: [0u8; 16],
            mr_seam: [0u8; 48],
            mr_signer_seam: [0u8; 48],
            seam_attributes: [0u8; 8],
            td_attributes: [0u8; 8],
            xfam: [0u8; 8],
            mr_td: [0u8; 48],
            mr_config_id: [0u8; 48],
            mr_owner: [0u8; 48],
            mr_owner_config: [0u8; 48],
            rtmr0: [0u8; 48],
            rtmr1: [0u8; 48],
            rtmr2: [0u8; 48],
            rtmr3: [0u8; 48],
            report_data: [0u8; 64],
        }
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let len = content.len();
        if len < 0x80 {
            v.push(len as u8);
        } else if len <= 0xFF {
            v.push(0x81);
            v.push(len as u8);
        } else if len <= 0xFFFF {
            v.push(0x82);
            v.push((len >> 8) as u8);
            v.push(len as u8);
        } else {
            panic!("test cert too large");
        }
        v.extend_from_slice(content);
        v
    }

    /// Build a minimal X.509 DER cert that contains the Intel SGX extension
    /// with the given FMSPC. The structure is intentionally stripped down to
    /// only what the FMSPC walker needs (outer Certificate SEQUENCE wrapping
    /// a TBSCertificate that exposes the `[3] EXPLICIT` extensions block).
    fn build_cert_with_fmspc(fmspc: [u8; FMSPC_LEN]) -> Vec<u8> {
        let fmspc_entry = {
            let mut e = Vec::new();
            e.extend_from_slice(&der_tlv(DER_TAG_OID, OID_INTEL_SGX_FMSPC));
            e.extend_from_slice(&der_tlv(DER_TAG_OCTET_STRING, &fmspc));
            der_tlv(DER_TAG_SEQUENCE, &e)
        };
        let sgx_seq = der_tlv(DER_TAG_SEQUENCE, &fmspc_entry);

        let sgx_ext = {
            let mut e = Vec::new();
            e.extend_from_slice(&der_tlv(DER_TAG_OID, OID_INTEL_SGX_EXTENSION));
            e.extend_from_slice(&der_tlv(DER_TAG_OCTET_STRING, &sgx_seq));
            der_tlv(DER_TAG_SEQUENCE, &e)
        };
        let extensions = der_tlv(DER_TAG_SEQUENCE, &sgx_ext);
        let tagged_extensions = der_tlv(DER_TAG_CONTEXT_3_EXPLICIT, &extensions);
        let tbs = der_tlv(DER_TAG_SEQUENCE, &tagged_extensions);

        let sig_alg = der_tlv(DER_TAG_SEQUENCE, &[]);
        let sig_value = der_tlv(0x03, &[0x00]);

        let mut cert_inner = Vec::new();
        cert_inner.extend_from_slice(&tbs);
        cert_inner.extend_from_slice(&sig_alg);
        cert_inner.extend_from_slice(&sig_value);
        der_tlv(DER_TAG_SEQUENCE, &cert_inner)
    }

    fn cert_to_pem(cert_der: &[u8]) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
        let mut wrapped = String::new();
        for chunk in b64.as_bytes().chunks(64) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap());
            wrapped.push('\n');
        }
        format!("-----BEGIN CERTIFICATE-----\n{wrapped}-----END CERTIFICATE-----\n")
    }

    #[test]
    fn extract_fmspc_from_synthetic_der_cert() {
        let want = [0x30, 0xC0, 0x6F, 0x00, 0x00, 0x00];
        let cert = build_cert_with_fmspc(want);
        let got = extract_fmspc_from_cert_der(&cert).expect("fmspc");
        assert_eq!(got, want);
    }

    #[test]
    fn first_certificate_der_unwraps_pem() {
        let want = [0xAA; FMSPC_LEN];
        let cert = build_cert_with_fmspc(want);
        let pem = cert_to_pem(&cert);
        let extracted = first_certificate_der(pem.as_bytes()).expect("first cert");
        assert_eq!(extracted, cert);
    }

    #[test]
    fn first_certificate_der_passes_through_raw_der() {
        let cert = build_cert_with_fmspc([1, 2, 3, 4, 5, 6]);
        let mut buf = cert.clone();
        // Append a second cert's bytes; the helper should only return the first TLV.
        buf.extend_from_slice(&build_cert_with_fmspc([9; FMSPC_LEN]));
        let first = first_certificate_der(&buf).expect("first der");
        assert_eq!(first, cert);
    }

    #[test]
    fn fmspc_extraction_rejects_wrong_length() {
        // Build a cert whose FMSPC OCTET STRING is 4 bytes instead of 6.
        let fmspc_entry = {
            let mut e = Vec::new();
            e.extend_from_slice(&der_tlv(DER_TAG_OID, OID_INTEL_SGX_FMSPC));
            e.extend_from_slice(&der_tlv(DER_TAG_OCTET_STRING, &[0u8; 4]));
            der_tlv(DER_TAG_SEQUENCE, &e)
        };
        let sgx_seq = der_tlv(DER_TAG_SEQUENCE, &fmspc_entry);
        let sgx_ext = {
            let mut e = Vec::new();
            e.extend_from_slice(&der_tlv(DER_TAG_OID, OID_INTEL_SGX_EXTENSION));
            e.extend_from_slice(&der_tlv(DER_TAG_OCTET_STRING, &sgx_seq));
            der_tlv(DER_TAG_SEQUENCE, &e)
        };
        let extensions = der_tlv(DER_TAG_SEQUENCE, &sgx_ext);
        let tagged_extensions = der_tlv(DER_TAG_CONTEXT_3_EXPLICIT, &extensions);
        let tbs = der_tlv(DER_TAG_SEQUENCE, &tagged_extensions);
        let sig_alg = der_tlv(DER_TAG_SEQUENCE, &[]);
        let sig_value = der_tlv(0x03, &[0x00]);
        let mut inner = Vec::new();
        inner.extend_from_slice(&tbs);
        inner.extend_from_slice(&sig_alg);
        inner.extend_from_slice(&sig_value);
        let cert = der_tlv(DER_TAG_SEQUENCE, &inner);
        match extract_fmspc_from_cert_der(&cert) {
            Err(FmspcExtractError::InvalidFmspcLength(4)) => {}
            other => panic!("expected InvalidFmspcLength(4), got {other:?}"),
        }
    }

    #[test]
    fn fmspc_extraction_reports_missing_sgx_extension() {
        // Cert with an extensions block but no SGX extension OID.
        let other_ext = {
            let mut e = Vec::new();
            // arbitrary OID: 2.5.29.17 (subject alt name) — 0x55, 0x1D, 0x11
            e.extend_from_slice(&der_tlv(DER_TAG_OID, &[0x55, 0x1D, 0x11]));
            e.extend_from_slice(&der_tlv(DER_TAG_OCTET_STRING, &[]));
            der_tlv(DER_TAG_SEQUENCE, &e)
        };
        let extensions = der_tlv(DER_TAG_SEQUENCE, &other_ext);
        let tagged_extensions = der_tlv(DER_TAG_CONTEXT_3_EXPLICIT, &extensions);
        let tbs = der_tlv(DER_TAG_SEQUENCE, &tagged_extensions);
        let cert = der_tlv(DER_TAG_SEQUENCE, &tbs);
        match extract_fmspc_from_cert_der(&cert) {
            Err(FmspcExtractError::NoSgxExtension) => {}
            other => panic!("expected NoSgxExtension, got {other:?}"),
        }
    }

    #[test]
    fn parsed_td_quote_fmspc_round_trip() {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: TdQuoteBodyType::Tdx10 as u16,
            body_size: TD_QUOTE_BODY_V1_0_SIZE as u32,
        };
        let body = zero_tdx10_body();

        let want_fmspc = [0x10, 0xA0, 0x6B, 0x00, 0x00, 0x00];
        let pck_pem = cert_to_pem(&build_cert_with_fmspc(want_fmspc));
        let pck_chain_bytes = pck_pem.as_bytes();

        let mut sig_blob = Vec::new();
        sig_blob.extend_from_slice(&[0xAA; SGX_ECDSA_SIGNATURE_SIZE]);
        sig_blob.extend_from_slice(&[0xBB; SGX_EC_P256_POINT_SIZE]);

        let mut cert_payload = Vec::new();
        cert_payload.extend_from_slice(&[0x11; SGX_REPORT_BODY_SIZE]);
        cert_payload.extend_from_slice(&[0x22; SGX_ECDSA_SIGNATURE_SIZE]);
        cert_payload.extend_from_slice(&u16::to_le_bytes(0));
        cert_payload.extend_from_slice(&SGX_QL_CERT_KEY_TYPE_PCK_CERT_CHAIN.to_le_bytes());
        cert_payload.extend_from_slice(&(pck_chain_bytes.len() as u32).to_le_bytes());
        cert_payload.extend_from_slice(pck_chain_bytes);

        sig_blob.extend_from_slice(&SGX_QL_CERT_KEY_TYPE_ECDSA_SIG_AUX_DATA.to_le_bytes());
        sig_blob.extend_from_slice(&(cert_payload.len() as u32).to_le_bytes());
        sig_blob.extend_from_slice(&cert_payload);

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&(sig_blob.len() as u32).to_le_bytes());
        quote.extend_from_slice(&sig_blob);

        let parsed = parse_td_quote(&quote).expect("parse quote");
        assert_eq!(parsed.pck_cert_chain(), Some(pck_chain_bytes));
        assert_eq!(parsed.fmspc().expect("fmspc"), want_fmspc);
    }

    #[test]
    fn parsed_td_quote_fmspc_missing_chain() {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: TdQuoteBodyType::Tdx10 as u16,
            body_size: TD_QUOTE_BODY_V1_0_SIZE as u32,
        };
        let body = zero_tdx10_body();

        let mut quote = Vec::new();
        append_header_bytes(&mut quote, &header);
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_td_quote(&quote).expect("parse quote");
        assert!(parsed.pck_cert_chain().is_none());
        match parsed.fmspc() {
            Err(FmspcExtractError::NoPckCertChain) => {}
            other => panic!("expected NoPckCertChain, got {other:?}"),
        }
    }
}
