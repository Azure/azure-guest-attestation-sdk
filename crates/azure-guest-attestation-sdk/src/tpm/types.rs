// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// TPM wire-format structures — per-field documentation deferred.
#![allow(missing_docs)]

//! Minimal TPM2 type definitions with binary (un)marshalling helpers.
//! These are intentionally partial and only cover what current code paths need.

// Command structs now mirror the TPM wire format as (header, handles, parameters)
// to make command construction and parsing more explicit.
use bitfield_struct::bitfield;
use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::OnceLock;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const ALG_SHA1: u16 = 0x0004;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_SHA384: u16 = 0x000C;
pub const ALG_RSAES: u16 = 0x0015;
pub const ALG_OAEP: u16 = 0x0017;
pub const ALG_ECC: u16 = 0x0023;
pub const ALG_ECDSA: u16 = 0x0018;

/// ECC curve identifiers
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_ECC_NIST_P384: u16 = 0x0004;
pub const TPMA_NV_OWNERWRITE: u32 = 1 << 1;
pub const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
pub const TPMA_NV_OWNERREAD: u32 = 1 << 17;
pub const TPMA_NV_AUTHREAD: u32 = 1 << 18;

#[derive(Copy, Clone, Debug)]
pub enum Hierarchy {
    Null,
    Owner,
    Endorsement,
}

impl Hierarchy {
    pub fn handle(self) -> u32 {
        match self {
            Hierarchy::Owner => 0x4000_0001,
            Hierarchy::Null => 0x4000_0007,
            Hierarchy::Endorsement => 0x4000_000B,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcrAlgorithm {
    Sha1,
    Sha256,
    Sha384,
}

impl PcrAlgorithm {
    pub fn to_alg_id(self) -> u16 {
        match self {
            PcrAlgorithm::Sha1 => ALG_SHA1,
            PcrAlgorithm::Sha256 => ALG_SHA256,
            PcrAlgorithm::Sha384 => ALG_SHA384,
        }
    }

    pub fn digest_len(self) -> usize {
        match self {
            PcrAlgorithm::Sha1 => 20,
            PcrAlgorithm::Sha256 => 32,
            PcrAlgorithm::Sha384 => 48,
        }
    }

    pub fn from_alg_id(id: u16) -> Option<Self> {
        match id {
            ALG_SHA1 => Some(PcrAlgorithm::Sha1),
            ALG_SHA256 => Some(PcrAlgorithm::Sha256),
            ALG_SHA384 => Some(PcrAlgorithm::Sha384),
            _ => None,
        }
    }
}

impl fmt::Display for PcrAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcrAlgorithm::Sha1 => write!(f, "sha1"),
            PcrAlgorithm::Sha256 => write!(f, "sha256"),
            PcrAlgorithm::Sha384 => write!(f, "sha384"),
        }
    }
}

impl FromStr for PcrAlgorithm {
    type Err = (); // caller maps to user-facing error

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Ok(PcrAlgorithm::Sha1),
            "sha256" => Ok(PcrAlgorithm::Sha256),
            "sha384" => Ok(PcrAlgorithm::Sha384),
            _ => Err(()),
        }
    }
}

#[bitfield(u32)]
pub struct TpmaNvBits {
    pub nv_ppwrite: bool,
    pub nv_ownerwrite: bool,
    pub nv_authwrite: bool,
    pub nv_policywrite: bool,
    // bits 7:4: `TPM_NT`
    // 0001 - `tpm_nt_counter`
    pub nt_counter: bool,
    // 0010 - `tpm_nt_bits`
    pub nt_bits: bool,
    // 0100 - `tpm_nt_extend`
    pub nt_extend: bool,
    _unused0: bool,
    // bits 9:8 are reserved
    #[bits(2)]
    _reserved1: u8,
    pub nv_policy_delete: bool,
    pub nv_writelocked: bool,
    pub nv_writeall: bool,
    pub nv_writedefine: bool,
    pub nv_write_stclear: bool,
    pub nv_globallock: bool,
    pub nv_ppread: bool,
    pub nv_ownerread: bool,
    pub nv_authread: bool,
    pub nv_policyread: bool,
    // bits 24:20 are reserved
    #[bits(5)]
    _reserved2: u8,
    pub nv_no_da: bool,
    pub nv_orderly: bool,
    pub nv_clear_stclear: bool,
    pub nv_readlocked: bool,
    pub nv_written: bool,
    pub nv_platformcreate: bool,
    pub nv_read_stclear: bool,
}

#[bitfield(u32)]
pub struct TpmaObjectBits {
    _reserved0: bool,
    pub fixed_tpm: bool,
    pub st_clear: bool,
    _reserved1: bool,
    pub fixed_parent: bool,
    pub sensitive_data_origin: bool,
    pub user_with_auth: bool,
    pub admin_with_policy: bool,
    #[bits(2)]
    _reserved2: u8,
    pub no_da: bool,
    pub encrypted_duplication: bool,
    #[bits(4)]
    _reserved3: u8,
    pub restricted: bool,
    pub decrypt: bool,
    pub sign_encrypt: bool,
    #[bits(13)]
    _reserved4: u16,
}

#[repr(u16)]
pub enum TpmAlgId {
    Rsa = 0x0001,
    Sha256 = 0x000b,
    Null = 0x0010,
    RsaSsa = 0x0014,
    Ecdsa = 0x0018,
    Ecc = 0x0023,
}

impl From<TpmAlgId> for u16 {
    fn from(value: TpmAlgId) -> Self {
        value as u16
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmCommandCode {
    CreatePrimary = 0x00000131,
    Load = 0x00000157,
    Quote = 0x00000158,
    RsaDecrypt = 0x00000159,
    Sign = 0x0000015D,
    FlushContext = 0x00000165,
    Unseal = 0x0000015E,
    VerifySignature = 0x00000177,
    ReadPublic = 0x00000173,
    PcrRead = 0x0000017E,
    PolicyPCR = 0x0000017F,
    Certify = 0x00000148,
    StartAuthSession = 0x00000176,
    PolicyGetDigest = 0x00000189,
    NvReadPublic = 0x00000169,
    NvRead = 0x0000014E,
    NvWrite = 0x00000137,
    NvDefineSpace = 0x0000012A,
    NvUndefineSpace = 0x00000122,
    NvExtend = 0x00000136,
    NvCertify = 0x00000184,
    EvictControl = 0x00000120,
}

#[derive(Debug, Clone, Copy)]
pub struct TpmCommandHeader {
    pub tag: u16,
    pub size: u32,
    pub command_code: TpmCommandCode,
}

impl TpmCommandHeader {
    pub fn no_sessions(command_code: TpmCommandCode) -> Self {
        Self {
            tag: TPM_ST_NO_SESSIONS,
            size: 0,
            command_code,
        }
    }

    pub fn sessions(command_code: TpmCommandCode) -> Self {
        Self {
            tag: TPM_ST_SESSIONS,
            size: 0,
            command_code,
        }
    }

    pub fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    pub fn marshal_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.tag.to_be_bytes());
        buf.extend_from_slice(&self.size.to_be_bytes());
        buf.extend_from_slice(&(self.command_code as u32).to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TpmResponseHeader {
    pub tag: u16,
    pub size: u32,
    pub return_code: u32,
}

impl TpmResponseHeader {
    pub fn parse(bytes: &[u8]) -> io::Result<(Self, usize)> {
        if bytes.len() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TPM response header truncated",
            ));
        }
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        if size as usize > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TPM response size larger than buffer",
            ));
        }
        let return_code = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        Ok((
            TpmResponseHeader {
                tag,
                size,
                return_code,
            },
            10,
        ))
    }

    pub fn has_sessions(&self) -> bool {
        self.tag == TPM_ST_SESSIONS
    }
}

macro_rules! count_fields {
    ($($field:ident),+ $(,)?) => {
        0usize $(+ { let _ = stringify!($field); 1usize })+
    };
}

macro_rules! define_handle_struct {
    ($(#[$meta:meta])* $name:ident { $($field:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            $(pub $field: u32,)*
        }

        impl $name {
            pub fn to_array(&self) -> [u32; count_fields!($($field),+)] {
                [$(self.$field),*]
            }
        }
    };
    ($(#[$meta:meta])* $name:ident;) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name;

        impl $name {
            pub fn to_array(&self) -> [u32; 0] {
                []
            }
        }
    };
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryCommandHandles {
    pub hierarchy: Hierarchy,
}

impl CreatePrimaryCommandHandles {
    pub fn to_array(&self) -> [u32; 1] {
        [self.hierarchy.handle()]
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryCommandParameters {
    pub in_sensitive: Tpm2bSensitiveCreate,
    pub in_public: Tpm2bPublic,
    pub outside_info: Tpm2bBytes,
    pub creation_pcr: PcrSelectionList,
}

impl TpmMarshal for CreatePrimaryCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.in_sensitive.marshal(buf);
        self.in_public.marshal(buf);
        self.outside_info.marshal(buf);
        self.creation_pcr.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryCommand {
    pub header: TpmCommandHeader,
    pub handles: CreatePrimaryCommandHandles,
    pub parameters: CreatePrimaryCommandParameters,
}

impl CreatePrimaryCommand {
    pub fn new(hierarchy: Hierarchy, parameters: CreatePrimaryCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::CreatePrimary),
            handles: CreatePrimaryCommandHandles { hierarchy },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryResponseHandles {
    pub object_handle: u32,
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryResponseParameters {
    pub out_public: Tpm2bPublic,
    pub creation_data: Tpm2bBytes,
    pub creation_hash: Tpm2bBytes,
    pub creation_ticket: Vec<u8>,
    pub name: Tpm2bBytes,
    pub qualified_name: Tpm2bBytes,
}

impl CreatePrimaryResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let _param_size = u32::unmarshal(d, c)?;

        let out_public = Tpm2bPublic::unmarshal(d, c)?;
        let creation_data = Tpm2bBytes::unmarshal(d, c)?;
        let creation_hash = Tpm2bBytes::unmarshal(d, c)?;
        if *c + 2 + 4 > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ticket header",
            ));
        }
        let start = *c;
        *c += 2 + 4;
        let digest = Tpm2bBytes::unmarshal(d, c)?;
        let ticket_slice = &d[start..start + 2 + 4 + 2 + digest.0.len()];
        let creation_ticket = ticket_slice.to_vec();
        let name = Tpm2bBytes::unmarshal(d, c)?;
        let qualified_name = Tpm2bBytes::unmarshal(d, c)?;
        Ok(CreatePrimaryResponseParameters {
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
            name,
            qualified_name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrimaryResponse {
    pub header: TpmResponseHeader,
    pub handles: CreatePrimaryResponseHandles,
    pub parameters: CreatePrimaryResponseParameters,
}

impl CreatePrimaryResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "CreatePrimary returned error 0x{:08x}",
                header.return_code
            )));
        }
        if cursor + 4 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "CreatePrimary response missing object handle",
            ));
        }
        let object_handle = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let mut param_cursor = cursor;
        let parameters = CreatePrimaryResponseParameters::unmarshal(bytes, &mut param_cursor)?;

        Ok(CreatePrimaryResponse {
            header,
            handles: CreatePrimaryResponseHandles { object_handle },
            parameters,
        })
    }
}

// TPM2_Load --------------------------------------------------------------
define_handle_struct!(LoadCommandHandles { parent_handle });

#[derive(Debug, Clone)]
pub struct LoadCommandParameters {
    pub in_private: Tpm2bPrivate,
    pub in_public: Tpm2bPublic,
}

impl TpmMarshal for LoadCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.in_private.marshal(buf);
        self.in_public.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand {
    pub header: TpmCommandHeader,
    pub handles: LoadCommandHandles,
    pub parameters: LoadCommandParameters,
}

impl LoadCommand {
    pub fn new(parent_handle: u32, parameters: LoadCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Load),
            handles: LoadCommandHandles { parent_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

define_handle_struct!(LoadResponseHandles { object_handle });

#[derive(Debug, Clone)]
pub struct LoadResponseParameters {
    pub name: Tpm2bBytes,
}

impl TpmUnmarshal for LoadResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let name = Tpm2bBytes::unmarshal(d, c)?;
        Ok(LoadResponseParameters { name })
    }
}

#[derive(Debug, Clone)]
pub struct LoadResponse {
    pub header: TpmResponseHeader,
    pub handles: LoadResponseHandles,
    pub parameters: LoadResponseParameters,
}

impl LoadResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Load returned error 0x{:08x}",
                header.return_code
            )));
        }

        if cursor + 4 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Load response missing object handle",
            ));
        }
        let object_handle = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Load response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = LoadResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Load response parameter size mismatch",
                ));
            }
        }

        Ok(LoadResponse {
            header,
            handles: LoadResponseHandles { object_handle },
            parameters,
        })
    }
}

define_handle_struct!(QuoteCommandHandles { sign_handle });

#[derive(Debug, Clone)]
pub struct QuoteCommandParameters {
    pub qualifying_data: Tpm2bBytes,
    pub scheme: TpmtSigScheme,
    pub pcr_selection: PcrSelectionList,
}

impl TpmMarshal for QuoteCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.qualifying_data.marshal(buf);
        self.scheme.marshal(buf);
        self.pcr_selection.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct QuoteCommand {
    pub header: TpmCommandHeader,
    pub handles: QuoteCommandHandles,
    pub parameters: QuoteCommandParameters,
}

impl QuoteCommand {
    pub fn new(sign_handle: u32, parameters: QuoteCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Quote),
            handles: QuoteCommandHandles { sign_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct QuoteResponseParameters {
    pub attest: Vec<u8>,
    pub signature: TpmtSignature,
}

impl TpmUnmarshal for QuoteResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let attest = Tpm2bAttest::unmarshal(d, c)?.0;
        let signature = TpmtSignature::unmarshal(d, c)?;
        Ok(QuoteResponseParameters { attest, signature })
    }
}

#[derive(Debug, Clone)]
pub struct QuoteResponse {
    pub header: TpmResponseHeader,
    pub parameters: QuoteResponseParameters,
}

impl QuoteResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Quote returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Quote response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = QuoteResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Quote response parameter size mismatch",
                ));
            }
        }

        Ok(QuoteResponse { header, parameters })
    }
}

// CERTIFY command ---------------------------------------------------------
define_handle_struct!(CertifyCommandHandles {
    object_handle,
    sign_handle
});

#[derive(Debug, Clone)]
pub struct CertifyCommandParameters {
    pub qualifying_data: Tpm2bBytes,
    pub scheme: TpmtSigScheme,
}

impl TpmMarshal for CertifyCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.qualifying_data.marshal(buf);
        self.scheme.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct CertifyCommand {
    pub header: TpmCommandHeader,
    pub handles: CertifyCommandHandles,
    pub parameters: CertifyCommandParameters,
}

impl CertifyCommand {
    pub fn new(object_handle: u32, sign_handle: u32, parameters: CertifyCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Certify),
            handles: CertifyCommandHandles {
                object_handle,
                sign_handle,
            },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct CertifyResponseParameters {
    pub certify_info: Vec<u8>,
    pub signature: TpmtSignature,
}

impl TpmUnmarshal for CertifyResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let certify_info = Tpm2bAttest::unmarshal(d, c)?.0;
        let signature = TpmtSignature::unmarshal(d, c)?;
        Ok(CertifyResponseParameters {
            certify_info,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CertifyResponse {
    pub header: TpmResponseHeader,
    pub parameters: CertifyResponseParameters,
}

impl CertifyResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Certify returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Certify response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = CertifyResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Certify response parameter size mismatch",
                ));
            }
        }

        Ok(CertifyResponse { header, parameters })
    }
}

// StartAuthSession minimal (trial policy) ----------------------------------
// Handles: tpm_key (TPM_RH_NULL for trial), bind (TPM_RH_NULL)
define_handle_struct!(StartAuthSessionCommandHandles { tpm_key, bind });

#[derive(Debug, Clone)]
pub struct StartAuthSessionCommandParameters {
    pub nonce_caller: Tpm2bBytes,
    pub encrypted_salt: Tpm2bBytes,
    pub session_type: u8, // TPM_SE_POLICY = 0x03, trial also uses policy but will be indicated by attributes
    pub symmetric: SymDefObject,
    pub auth_hash: u16, // e.g. SHA256
}

impl TpmMarshal for StartAuthSessionCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.nonce_caller.marshal(buf);
        self.encrypted_salt.marshal(buf);
        buf.push(self.session_type);
        self.symmetric.marshal(buf);
        self.auth_hash.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionCommand {
    pub header: TpmCommandHeader,
    pub handles: StartAuthSessionCommandHandles,
    pub parameters: StartAuthSessionCommandParameters,
}

impl StartAuthSessionCommand {
    pub fn new(tpm_key: u32, bind: u32, parameters: StartAuthSessionCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::StartAuthSession),
            handles: StartAuthSessionCommandHandles { tpm_key, bind },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionResponseHandles {
    pub session_handle: u32,
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionResponseParameters {
    pub nonce_tpm: Tpm2bBytes,
}

impl TpmUnmarshal for StartAuthSessionResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let nonce = Tpm2bBytes::unmarshal(d, c)?;
        Ok(StartAuthSessionResponseParameters { nonce_tpm: nonce })
    }
}

#[derive(Debug, Clone)]
pub struct StartAuthSessionResponse {
    pub header: TpmResponseHeader,
    pub handles: StartAuthSessionResponseHandles,
    pub parameters: StartAuthSessionResponseParameters,
}

impl StartAuthSessionResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "StartAuthSession returned error 0x{:08x}",
                header.return_code
            )));
        }
        if cursor + 4 > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "StartAuthSession response missing session handle",
            ));
        }
        let session_handle = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "StartAuthSession response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = StartAuthSessionResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "StartAuthSession response parameter size mismatch",
                ));
            }
        }

        Ok(StartAuthSessionResponse {
            header,
            handles: StartAuthSessionResponseHandles { session_handle },
            parameters,
        })
    }
}

// PolicyPCR ----------------------------------------------------------------
define_handle_struct!(PolicyPcrCommandHandles { session_handle });

#[derive(Debug, Clone)]
pub struct PolicyPcrCommandParameters {
    pub pcr_digest: Tpm2bBytes, // often empty
    pub pcr_selection: PcrSelectionList,
}

impl TpmMarshal for PolicyPcrCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.pcr_digest.marshal(buf);
        self.pcr_selection.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct PolicyPcrCommand {
    pub header: TpmCommandHeader,
    pub handles: PolicyPcrCommandHandles,
    pub parameters: PolicyPcrCommandParameters,
}

impl PolicyPcrCommand {
    pub fn new(session_handle: u32, parameters: PolicyPcrCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::PolicyPCR),
            handles: PolicyPcrCommandHandles { session_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

// PolicyGetDigest ----------------------------------------------------------
define_handle_struct!(PolicyGetDigestCommandHandles { session_handle });

#[derive(Debug, Clone, Default)]
pub struct PolicyGetDigestCommandParameters;

impl TpmMarshal for PolicyGetDigestCommandParameters {
    fn marshal(&self, _buf: &mut Vec<u8>) {}
}

#[derive(Debug, Clone)]
pub struct PolicyGetDigestCommand {
    pub header: TpmCommandHeader,
    pub handles: PolicyGetDigestCommandHandles,
    pub parameters: PolicyGetDigestCommandParameters,
}

impl PolicyGetDigestCommand {
    pub fn new(session_handle: u32) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::PolicyGetDigest),
            handles: PolicyGetDigestCommandHandles { session_handle },
            parameters: PolicyGetDigestCommandParameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct PolicyGetDigestResponseParameters {
    pub policy_digest: Tpm2bBytes,
}

impl TpmUnmarshal for PolicyGetDigestResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let digest = Tpm2bBytes::unmarshal(d, c)?;
        Ok(PolicyGetDigestResponseParameters {
            policy_digest: digest,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PolicyGetDigestResponse {
    pub header: TpmResponseHeader,
    pub parameters: PolicyGetDigestResponseParameters,
}

impl PolicyGetDigestResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "PolicyGetDigest returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "PolicyGetDigest response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = PolicyGetDigestResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PolicyGetDigest response parameter size mismatch",
                ));
            }
        }

        Ok(PolicyGetDigestResponse { header, parameters })
    }
}

#[derive(Debug, Clone)]
pub enum TpmtSigScheme {
    Null,
    Rsassa(u16),
}

impl TpmMarshal for TpmtSigScheme {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            TpmtSigScheme::Null => {
                0x0010u16.marshal(buf); /* details omitted */
            }
            TpmtSigScheme::Rsassa(hash) => {
                0x0014u16.marshal(buf);
                hash.marshal(buf);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum TpmtRsaDecryptScheme {
    Rsaes,
    /// OAEP with the given hash algorithm (e.g. `ALG_SHA256`).
    Oaep(u16),
}

impl TpmMarshal for TpmtRsaDecryptScheme {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            TpmtRsaDecryptScheme::Rsaes => {
                ALG_RSAES.marshal(buf);
                // No additional scheme-specific bytes for RSAES
            }
            TpmtRsaDecryptScheme::Oaep(hash_alg) => {
                ALG_OAEP.marshal(buf);
                hash_alg.marshal(buf);
            }
        }
    }
}

// FlushContext has no parameter area (only a single handle). Provide an empty params struct for symmetry.
define_handle_struct!(FlushContextCommandHandles { flush_handle });

#[derive(Debug, Clone, Default)]
pub struct FlushContextCommandParameters;

impl TpmMarshal for FlushContextCommandParameters {
    fn marshal(&self, _buf: &mut Vec<u8>) {}
}

#[derive(Debug, Clone)]
pub struct FlushContextCommand {
    pub header: TpmCommandHeader,
    pub handles: FlushContextCommandHandles,
    pub parameters: FlushContextCommandParameters,
}

impl FlushContextCommand {
    pub fn new(flush_handle: u32) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::FlushContext),
            handles: FlushContextCommandHandles { flush_handle },
            parameters: FlushContextCommandParameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

// TPM2_EvictControl --------------------------------------------------------
define_handle_struct!(EvictControlCommandHandles {
    auth_handle,
    object_handle
});

#[derive(Debug, Clone)]
pub struct EvictControlCommandParameters {
    pub persistent_handle: u32,
}

impl TpmMarshal for EvictControlCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.persistent_handle.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct EvictControlCommand {
    pub header: TpmCommandHeader,
    pub handles: EvictControlCommandHandles,
    pub parameters: EvictControlCommandParameters,
}

impl EvictControlCommand {
    pub fn new(auth_handle: u32, object_handle: u32, persistent_handle: u32) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::EvictControl),
            handles: EvictControlCommandHandles {
                auth_handle,
                object_handle,
            },
            parameters: EvictControlCommandParameters { persistent_handle },
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvictControlResponseParameters;

impl TpmUnmarshal for EvictControlResponseParameters {
    fn unmarshal(_d: &[u8], _c: &mut usize) -> io::Result<Self> {
        Ok(EvictControlResponseParameters)
    }
}

#[derive(Debug, Clone)]
pub struct EvictControlResponse {
    pub header: TpmResponseHeader,
    pub parameters: EvictControlResponseParameters,
}

impl EvictControlResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "EvictControl returned error 0x{:08x}",
                header.return_code
            )));
        }

        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EvictControl response parameter size exceeds buffer",
                ));
            }
        }

        Ok(EvictControlResponse {
            header,
            parameters: EvictControlResponseParameters,
        })
    }
}

// TPM2_RSA_Decrypt ---------------------------------------------------------
define_handle_struct!(RsaDecryptCommandHandles { key_handle });

#[derive(Debug, Clone)]
pub struct RsaDecryptCommandParameters {
    pub cipher_text: Vec<u8>,
    pub scheme: TpmtRsaDecryptScheme,
    pub label: Vec<u8>,
}

impl TpmMarshal for RsaDecryptCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        // inData (TPM2B_PUBLIC_KEY_RSA)
        (self.cipher_text.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.cipher_text);
        // scheme (TPMT_RSA_DECRYPT)
        self.scheme.marshal(buf);
        // label (TPM2B_DATA)
        (self.label.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.label);
    }
}

#[derive(Debug, Clone)]
pub struct RsaDecryptCommand {
    pub header: TpmCommandHeader,
    pub handles: RsaDecryptCommandHandles,
    pub parameters: RsaDecryptCommandParameters,
}

impl RsaDecryptCommand {
    pub fn new(key_handle: u32, parameters: RsaDecryptCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::RsaDecrypt),
            handles: RsaDecryptCommandHandles { key_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct RsaDecryptResponseParameters {
    pub out_data: Tpm2bBytes,
}

impl TpmUnmarshal for RsaDecryptResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let out = Tpm2bBytes::unmarshal(d, c)?;
        Ok(RsaDecryptResponseParameters { out_data: out })
    }
}

#[derive(Debug, Clone)]
pub struct RsaDecryptResponse {
    pub header: TpmResponseHeader,
    pub parameters: RsaDecryptResponseParameters,
}

impl RsaDecryptResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "RsaDecrypt returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "RsaDecrypt response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = RsaDecryptResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RsaDecrypt response parameter size mismatch",
                ));
            }
        }

        Ok(RsaDecryptResponse { header, parameters })
    }
}

// TPM2_Unseal ------------------------------------------------------------
define_handle_struct!(UnsealCommandHandles { item_handle });

#[derive(Debug, Clone, Default)]
pub struct UnsealCommandParameters;

impl TpmMarshal for UnsealCommandParameters {
    fn marshal(&self, _buf: &mut Vec<u8>) {}
}

#[derive(Debug, Clone)]
pub struct UnsealCommand {
    pub header: TpmCommandHeader,
    pub handles: UnsealCommandHandles,
    pub parameters: UnsealCommandParameters,
}

impl UnsealCommand {
    pub fn new(item_handle: u32) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Unseal),
            handles: UnsealCommandHandles { item_handle },
            parameters: UnsealCommandParameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct UnsealResponseParameters {
    pub out_data: Tpm2bSensitiveData,
}

impl TpmUnmarshal for UnsealResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let data = Tpm2bBytes::unmarshal(d, c)?;
        Ok(UnsealResponseParameters { out_data: data })
    }
}

#[derive(Debug, Clone)]
pub struct UnsealResponse {
    pub header: TpmResponseHeader,
    pub parameters: UnsealResponseParameters,
}

impl UnsealResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Unseal returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unseal response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = UnsealResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unseal response parameter size mismatch",
                ));
            }
        }

        Ok(UnsealResponse { header, parameters })
    }
}

// TPM2_ReadPublic -----------------------------------------------------------
define_handle_struct!(ReadPublicCommandHandles { object_handle });

#[derive(Debug, Clone, Default)]
pub struct ReadPublicCommandParameters;

impl TpmMarshal for ReadPublicCommandParameters {
    fn marshal(&self, _buf: &mut Vec<u8>) {}
}

#[derive(Debug, Clone)]
pub struct ReadPublicCommand {
    pub header: TpmCommandHeader,
    pub handles: ReadPublicCommandHandles,
    pub parameters: ReadPublicCommandParameters,
}

impl ReadPublicCommand {
    pub fn new(object_handle: u32) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::ReadPublic),
            handles: ReadPublicCommandHandles { object_handle },
            parameters: ReadPublicCommandParameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct ReadPublicResponseParameters {
    pub out_public: Tpm2bPublic,
    pub name: Tpm2bBytes,
    pub qualified_name: Tpm2bBytes,
}

impl TpmUnmarshal for ReadPublicResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let out_public = Tpm2bPublic::unmarshal(d, c)?;
        let name = Tpm2bBytes::unmarshal(d, c)?;
        let qualified_name = Tpm2bBytes::unmarshal(d, c)?;
        Ok(ReadPublicResponseParameters {
            out_public,
            name,
            qualified_name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReadPublicResponse {
    pub header: TpmResponseHeader,
    pub parameters: ReadPublicResponseParameters,
}

impl ReadPublicResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "ReadPublic returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ReadPublic response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = ReadPublicResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ReadPublic response parameter size mismatch",
                ));
            }
        }

        Ok(ReadPublicResponse { header, parameters })
    }
}

pub trait TpmMarshal {
    fn marshal(&self, buf: &mut Vec<u8>);
}

pub trait TpmUnmarshal: Sized {
    fn unmarshal(data: &[u8], cursor: &mut usize) -> io::Result<Self>;
}

// Primitive helpers
impl TpmMarshal for u8 {
    fn marshal(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}
impl TpmMarshal for u16 {
    fn marshal(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}
impl TpmMarshal for u32 {
    fn marshal(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl TpmUnmarshal for u8 {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        if *c + 1 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u8"));
        }
        let v = d[*c];
        *c += 1;
        Ok(v)
    }
}
impl TpmUnmarshal for u16 {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        if *c + 2 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u16"));
        }
        let v = u16::from_be_bytes([d[*c], d[*c + 1]]);
        *c += 2;
        Ok(v)
    }
}
impl TpmUnmarshal for u32 {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        if *c + 4 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "u32"));
        }
        let v = u32::from_be_bytes([d[*c], d[*c + 1], d[*c + 2], d[*c + 3]]);
        *c += 4;
        Ok(v)
    }
}

// Sized buffer wrapper for TPM2B_* style structures.
// Layout on the wire: 2-byte big-endian length (u16) followed by the raw marshaled bytes of `inner`.
// Many TPM commands need the length-prefixed encoding multiple times (e.g. size calculations
// before final command assembly). Recomputing the inner marshaling each time adds avoidable
// allocations and length math, so we lazily cache the complete length-prefixed byte vector the
// first time it is produced.
//
// Why RefCell<Option<Vec<u8>>> instead of precomputing eagerly:
//   * Not every constructed value is marshaled (some are only inspected); lazy avoids wasted work.
//   * We want to cache while taking only &self in marshal(); RefCell provides interior mutability.
//   * Option distinguishes "not yet built" vs "cached".
// Safety / invariants:
//   * `inner` is never exposed mutably after construction, so cached bytes stay valid.
//   * If mutation were ever added, the cache would need invalidation (not currently required).
// Threading:
//   * OnceLock is Sync, so Tpm2b<T> is Send + Sync when T is.
#[derive(Debug)]
pub struct Tpm2b<T: TpmMarshal + Clone> {
    pub inner: T,
    /* cached length-prefixed bytes */ cached: OnceLock<Vec<u8>>,
}

impl<T: TpmMarshal + Clone> Clone for Tpm2b<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cached: OnceLock::new(),
        }
    }
}

impl<T: TpmMarshal + Clone> Tpm2b<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cached: OnceLock::new(),
        }
    }

    /// Return the full TPM2B encoding (length prefix + payload) as an owned Vec.
    /// This clones the cached Vec if already built; otherwise it marshals `inner`,
    /// constructs the prefixed form, stores it, then returns it.
    pub fn bytes(&self) -> Vec<u8> {
        self.cached
            .get_or_init(|| {
                // Marshal the inner structure (without size) into a temporary buffer.
                let mut tmp = Vec::new();
                self.inner.marshal(&mut tmp);
                // Allocate the final buffer with exact capacity (2 bytes length + payload).
                let mut full = Vec::with_capacity(2 + tmp.len());
                (tmp.len() as u16).marshal(&mut full); // write length prefix
                full.extend_from_slice(&tmp); // append payload
                full
            })
            .clone()
    }
}

impl<T: TpmMarshal + Clone> TpmMarshal for Tpm2b<T> {
    fn marshal(&self, buf: &mut Vec<u8>) {
        let b = self.bytes();
        buf.extend_from_slice(&b);
    }
}

// TPM2B with raw bytes
#[derive(Debug, Clone)]
pub struct Tpm2bBytes(pub Vec<u8>);

impl TpmMarshal for Tpm2bBytes {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.0.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.0);
    }
}

/// TPM2B_PRIVATE wrapper (alias to raw TPM2B bytes container).
pub type Tpm2bPrivate = Tpm2bBytes;

/// TPM2B_SENSITIVE_DATA wrapper (alias to raw TPM2B bytes container).
pub type Tpm2bSensitiveData = Tpm2bBytes;
impl TpmUnmarshal for Tpm2bBytes {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let sz = u16::unmarshal(d, c)? as usize;
        if *c + sz > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "2b bytes"));
        }
        let v = d[*c..*c + sz].to_vec();
        *c += sz;
        Ok(Tpm2bBytes(v))
    }
}

// TPML_PCR_SELECTION (only single-bank usage is needed now but we generalize)
#[derive(Debug, Clone)]
pub struct PcrSelectionList(pub Vec<PcrSelection>);

impl PcrSelectionList {
    pub fn from_pcrs_with_alg(pcrs: &[u32], hash_alg: u16) -> Self {
        if pcrs.is_empty() {
            return Self(Vec::new());
        }

        let mut bitmap = [0u8; 3];
        for &p in pcrs {
            if p <= 23 {
                let byte = (p / 8) as usize;
                let bit = p % 8;
                bitmap[byte] |= 1u8 << bit;
            }
        }

        Self(vec![PcrSelection {
            hash_alg,
            size_of_select: 3,
            select: bitmap,
        }])
    }

    pub fn from_pcrs(pcrs: &[u32]) -> Self {
        Self::from_pcrs_with_alg(pcrs, ALG_SHA256)
    }
}

#[derive(Debug, Clone)]
pub struct PcrSelection {
    pub hash_alg: u16,
    pub size_of_select: u8,
    pub select: [u8; 3],
}

impl TpmMarshal for PcrSelectionList {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.0.len() as u32).marshal(buf);
        for s in &self.0 {
            s.marshal(buf);
        }
    }
}
impl TpmMarshal for PcrSelection {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.hash_alg.marshal(buf);
        self.size_of_select.marshal(buf);
        buf.extend_from_slice(&self.select[..self.size_of_select as usize]);
    }
}

impl TpmUnmarshal for PcrSelectionList {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let count = u32::unmarshal(d, c)? as usize;
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            let hash_alg = u16::unmarshal(d, c)?;
            let size = u8::unmarshal(d, c)?;
            if size as usize > 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pcr select size>3",
                ));
            }
            if *c + size as usize > d.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "pcr select bytes",
                ));
            }
            let mut arr = [0u8; 3];
            for i in 0..size as usize {
                arr[i] = d[*c + i];
            }
            *c += size as usize;
            v.push(PcrSelection {
                hash_alg,
                size_of_select: size,
                select: arr,
            });
        }
        Ok(PcrSelectionList(v))
    }
}

// Minimal TPMT_RSA_SCHEME (only RSASSA and NULL supported)
#[derive(Debug, Clone)]
pub enum RsaScheme {
    Null,
    Rsassa(u16),
    Other(u16, Vec<u8>), // preserve raw scheme id + remaining bytes (if any)
}
impl TpmMarshal for RsaScheme {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            RsaScheme::Null => {
                0x0010u16.marshal(buf); /* details omitted */
            }
            RsaScheme::Rsassa(hash) => {
                0x0014u16.marshal(buf);
                hash.marshal(buf);
            }
            RsaScheme::Other(id, rest) => {
                id.marshal(buf);
                buf.extend_from_slice(rest);
            }
        }
    }
}

// TPMT_SYM_DEF_OBJECT (only NULL)
#[derive(Debug, Clone)]
pub struct SymDefObject {
    pub alg: u16,
    pub key_bits: u16,
    pub mode: u16,
}
impl TpmMarshal for SymDefObject {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.alg.marshal(buf);
        if self.alg != 0x0010 {
            self.key_bits.marshal(buf);
            self.mode.marshal(buf);
        }
    }
}

impl TpmUnmarshal for SymDefObject {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let alg = u16::unmarshal(d, c)?;
        if alg == 0x0010 {
            return Ok(Self {
                alg,
                key_bits: 0,
                mode: 0,
            });
        }

        let key_bits = u16::unmarshal(d, c)?;
        let mode = u16::unmarshal(d, c)?;

        Ok(Self {
            alg,
            key_bits,
            mode,
        })
    }
}

// TPMT_PUBLIC (RSA limited subset)
#[derive(Debug, Clone)]
pub struct TpmtPublic {
    pub type_alg: u16, // 0x0001 RSA
    pub name_alg: u16, // typically 0x000B SHA256
    pub object_attributes: u32,
    pub auth_policy: Tpm2bBytes,
    pub symmetric: SymDefObject,
    pub scheme: RsaScheme,
    pub key_bits: u16,
    pub exponent: u32,
    pub unique: Tpm2bBytes,
}

impl TpmMarshal for TpmtPublic {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.type_alg.marshal(buf);
        self.name_alg.marshal(buf);
        self.object_attributes.marshal(buf);
        self.auth_policy.marshal(buf);
        self.symmetric.marshal(buf);
        self.scheme.marshal(buf);
        self.key_bits.marshal(buf);
        self.exponent.marshal(buf);
        self.unique.marshal(buf);
    }
}

pub type Tpm2bPublic = Tpm2b<TpmtPublic>;

impl TpmUnmarshal for TpmtPublic {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let type_alg = u16::unmarshal(d, c)?;
        let name_alg = u16::unmarshal(d, c)?;
        let object_attributes = u32::unmarshal(d, c)?;
        let auth_policy = Tpm2bBytes::unmarshal(d, c)?;
        let symmetric = SymDefObject::unmarshal(d, c)?;
        // if symmetric.alg != 0x0010 {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidData,
        //         "unexpected symmetric alg",
        //     ));
        // }
        // scheme
        let scheme_id = u16::unmarshal(d, c)?;
        let scheme = match scheme_id {
            0x0010 => RsaScheme::Null,
            0x0014 => {
                let hash = u16::unmarshal(d, c)?;
                RsaScheme::Rsassa(hash)
            }
            other => {
                // Capture remaining bytes for unique parsing stability: for RSA public template, after scheme comes key_bits (u16), exponent (u32), unique (TPM2B)
                // We don't know internal layout for unknown scheme; treat as opaque (no extra bytes consumed beyond id).
                RsaScheme::Other(other, Vec::new())
            }
        };
        let key_bits = u16::unmarshal(d, c)?;
        let exponent = u32::unmarshal(d, c)?;
        let unique = Tpm2bBytes::unmarshal(d, c)?;
        Ok(TpmtPublic {
            type_alg,
            name_alg,
            object_attributes,
            auth_policy,
            symmetric,
            scheme,
            key_bits,
            exponent,
            unique,
        })
    }
}

impl TpmUnmarshal for Tpm2bPublic {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let sz = u16::unmarshal(d, c)? as usize;
        if *c + sz > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "public size"));
        }
        let start = *c;
        let mut inner_cursor = *c;
        let inner = TpmtPublic::unmarshal(d, &mut inner_cursor)?;
        *c = start + sz;
        Ok(Tpm2b {
            inner,
            cached: OnceLock::new(),
        })
    }
}

// TPMS_SENSITIVE_CREATE (only empty usage)
#[derive(Debug, Clone)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bBytes,
    pub data: Tpm2bBytes,
}

impl TpmMarshal for TpmsSensitiveCreate {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.user_auth.marshal(buf);
        self.data.marshal(buf);
    }
}

pub type Tpm2bSensitiveCreate = Tpm2b<TpmsSensitiveCreate>;

pub fn empty_sensitive_create() -> Tpm2bSensitiveCreate {
    Tpm2b::new(TpmsSensitiveCreate {
        user_auth: Tpm2bBytes(Vec::new()),
        data: Tpm2bBytes(Vec::new()),
    })
}

pub fn empty_public_unique() -> Tpm2bBytes {
    Tpm2bBytes(Vec::new())
}

pub fn rsa_unrestricted_sign_decrypt_public_with_policy(policy: Vec<u8>) -> Tpm2bPublic {
    let object_attributes = TpmaObjectBits::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_no_da(true)
        .with_decrypt(true);

    Tpm2b::new(TpmtPublic {
        type_alg: TpmAlgId::Rsa.into(),
        name_alg: TpmAlgId::Sha256.into(),
        object_attributes: object_attributes.into(),
        auth_policy: Tpm2bBytes(policy),
        symmetric: SymDefObject {
            alg: TpmAlgId::Null.into(),
            key_bits: 0,
            mode: 0,
        },
        scheme: RsaScheme::Null,
        key_bits: 2048,
        exponent: 0,
        unique: empty_public_unique(),
    })
}

pub fn rsa_unrestricted_sign_decrypt_public() -> Tpm2bPublic {
    rsa_unrestricted_sign_decrypt_public_with_policy(Vec::new())
}

/// Restricted signing (AK-like) RSA template: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|sign
pub fn rsa_restricted_signing_public() -> Tpm2bPublic {
    let object_attributes = TpmaObjectBits::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_sign_encrypt(true);

    Tpm2b::new(TpmtPublic {
        type_alg: TpmAlgId::Rsa.into(),
        name_alg: TpmAlgId::Sha256.into(),
        object_attributes: object_attributes.into(),
        auth_policy: Tpm2bBytes(Vec::new()),
        symmetric: SymDefObject {
            alg: TpmAlgId::Null.into(),
            key_bits: 0,
            mode: 0,
        },
        scheme: RsaScheme::Rsassa(0x000b),
        key_bits: 2048,
        exponent: 0,
        unique: Tpm2bBytes(vec![0u8; 256]),
    })
}

// ECC public template structure (TPMT_PUBLIC for ECC keys)
#[derive(Debug, Clone)]
pub struct TpmtPublicEcc {
    pub type_alg: u16, // 0x0023 for ECC
    pub name_alg: u16, // typically 0x000B SHA256
    pub object_attributes: u32,
    pub auth_policy: Tpm2bBytes,
    pub symmetric: SymDefObject,
    pub scheme: EccScheme,
    pub curve_id: u16,   // TPM_ECC_NIST_P256 = 0x0003
    pub kdf_scheme: u16, // typically TPM_ALG_NULL
    pub unique: TpmsEccPoint,
}

/// ECC Signature Scheme
#[derive(Debug, Clone)]
pub enum EccScheme {
    Null,
    Ecdsa(u16), // hash algorithm
}

impl TpmMarshal for EccScheme {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            EccScheme::Null => {
                0x0010u16.marshal(buf); // TPM_ALG_NULL
            }
            EccScheme::Ecdsa(hash) => {
                0x0018u16.marshal(buf); // TPM_ALG_ECDSA
                hash.marshal(buf);
            }
        }
    }
}

impl TpmMarshal for TpmtPublicEcc {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.type_alg.marshal(buf);
        self.name_alg.marshal(buf);
        self.object_attributes.marshal(buf);
        self.auth_policy.marshal(buf);
        self.symmetric.marshal(buf);
        self.scheme.marshal(buf);
        self.curve_id.marshal(buf);
        self.kdf_scheme.marshal(buf);
        self.unique.marshal(buf);
    }
}

pub type Tpm2bPublicEcc = Tpm2b<TpmtPublicEcc>;

/// Unrestricted signing ECC P-256 template: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign
pub fn ecc_unrestricted_signing_public() -> Tpm2bPublicEcc {
    ecc_unrestricted_signing_public_with_policy(Vec::new())
}

/// Unrestricted signing ECC P-256 template with policy
pub fn ecc_unrestricted_signing_public_with_policy(policy: Vec<u8>) -> Tpm2bPublicEcc {
    let object_attributes = TpmaObjectBits::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_sign_encrypt(true);

    Tpm2b::new(TpmtPublicEcc {
        type_alg: ALG_ECC,
        name_alg: ALG_SHA256,
        object_attributes: object_attributes.into(),
        auth_policy: Tpm2bBytes(policy),
        symmetric: SymDefObject {
            alg: TpmAlgId::Null.into(),
            key_bits: 0,
            mode: 0,
        },
        scheme: EccScheme::Ecdsa(ALG_SHA256),
        curve_id: TPM_ECC_NIST_P256,
        kdf_scheme: TpmAlgId::Null.into(),
        unique: TpmsEccPoint {
            x: vec![0u8; 32],
            y: vec![0u8; 32],
        },
    })
}

// TPML_DIGEST values (simplified parser to collect first digest list)
#[derive(Debug, Clone)]
pub struct DigestList(pub Vec<Vec<u8>>);
impl TpmUnmarshal for DigestList {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let count = u32::unmarshal(d, c)?;
        let mut out = Vec::new();
        for _ in 0..count {
            let sz = u16::unmarshal(d, c)? as usize;
            if *c + sz > d.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "digest"));
            }
            out.push(d[*c..*c + sz].to_vec());
            *c += sz;
        }
        Ok(DigestList(out))
    }
}

// TPM2B_ATTEST wrapper (opaque blob)
#[derive(Debug, Clone)]
pub struct Tpm2bAttest(pub Vec<u8>);
impl TpmUnmarshal for Tpm2bAttest {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let sz = u16::unmarshal(d, c)? as usize;
        if *c + sz > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "attest"));
        }
        let v = d[*c..*c + sz].to_vec();
        *c += sz;
        Ok(Tpm2bAttest(v))
    }
}

impl TpmMarshal for Tpm2bAttest {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.0.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.0);
    }
}

/// ECC Point structure (TPMS_ECC_POINT)
#[derive(Debug, Clone)]
pub struct TpmsEccPoint {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl TpmMarshal for TpmsEccPoint {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.x.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.x);
        (self.y.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.y);
    }
}

impl TpmUnmarshal for TpmsEccPoint {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let x_size = u16::unmarshal(d, c)? as usize;
        if *c + x_size > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ecc point x"));
        }
        let x = d[*c..*c + x_size].to_vec();
        *c += x_size;
        let y_size = u16::unmarshal(d, c)? as usize;
        if *c + y_size > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ecc point y"));
        }
        let y = d[*c..*c + y_size].to_vec();
        *c += y_size;
        Ok(TpmsEccPoint { x, y })
    }
}

/// ECDSA signature (TPMS_SIGNATURE_ECDSA)
#[derive(Debug, Clone)]
pub struct TpmsSignatureEcdsa {
    pub hash_alg: u16,
    pub signature_r: Vec<u8>,
    pub signature_s: Vec<u8>,
}

impl TpmMarshal for TpmsSignatureEcdsa {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.hash_alg.marshal(buf);
        (self.signature_r.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.signature_r);
        (self.signature_s.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.signature_s);
    }
}

impl TpmUnmarshal for TpmsSignatureEcdsa {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let hash_alg = u16::unmarshal(d, c)?;
        let r_size = u16::unmarshal(d, c)? as usize;
        if *c + r_size > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ecdsa r"));
        }
        let signature_r = d[*c..*c + r_size].to_vec();
        *c += r_size;
        let s_size = u16::unmarshal(d, c)? as usize;
        if *c + s_size > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ecdsa s"));
        }
        let signature_s = d[*c..*c + s_size].to_vec();
        *c += s_size;
        Ok(TpmsSignatureEcdsa {
            hash_alg,
            signature_r,
            signature_s,
        })
    }
}

// TPMT_SIGNATURE (support RSASSA and ECDSA)
#[derive(Debug, Clone)]
pub enum TpmtSignature {
    Rsassa { hash_alg: u16, sig: Vec<u8> },
    Ecdsa(TpmsSignatureEcdsa),
    Null,
    OtherRaw(Vec<u8>),
}

impl TpmUnmarshal for TpmtSignature {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        // scheme
        if *c + 2 > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sig scheme"));
        }
        let scheme = u16::unmarshal(d, c)?;
        match scheme {
            0x0014 => {
                // RSASSA
                let hash_alg = u16::unmarshal(d, c)?; // hashAlg
                let size = u16::unmarshal(d, c)? as usize;
                if *c + size > d.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sig rsassa"));
                }
                let sig = d[*c..*c + size].to_vec();
                *c += size;
                Ok(TpmtSignature::Rsassa { hash_alg, sig })
            }
            0x0018 => {
                // ECDSA
                let ecdsa = TpmsSignatureEcdsa::unmarshal(d, c)?;
                Ok(TpmtSignature::Ecdsa(ecdsa))
            }
            0x0010 => {
                // TPM_ALG_NULL
                Ok(TpmtSignature::Null)
            }
            _ => {
                // fallback: capture rest
                let rest = d[*c..].to_vec();
                *c = d.len();
                Ok(TpmtSignature::OtherRaw(rest))
            }
        }
    }
}

impl TpmMarshal for TpmtSignature {
    fn marshal(&self, buf: &mut Vec<u8>) {
        match self {
            TpmtSignature::Rsassa { hash_alg, sig } => {
                0x0014u16.marshal(buf); // RSASSA
                hash_alg.marshal(buf);
                (sig.len() as u16).marshal(buf);
                buf.extend_from_slice(sig);
            }
            TpmtSignature::Ecdsa(ecdsa) => {
                0x0018u16.marshal(buf); // ECDSA
                ecdsa.marshal(buf);
            }
            TpmtSignature::Null => {
                0x0010u16.marshal(buf); // TPM_ALG_NULL
            }
            TpmtSignature::OtherRaw(raw) => {
                buf.extend_from_slice(raw); // Already raw TPMT_SIGNATURE bytes
            }
        }
    }
}

// NV helpers
#[derive(Debug, Clone)]
pub struct Tpm2bMaxNvBuffer(pub Vec<u8>);
impl TpmMarshal for Tpm2bMaxNvBuffer {
    fn marshal(&self, buf: &mut Vec<u8>) {
        (self.0.len() as u16).marshal(buf);
        buf.extend_from_slice(&self.0);
    }
}

impl TpmUnmarshal for Tpm2bMaxNvBuffer {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let sz = u16::unmarshal(d, c)? as usize;
        if *c + sz > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "nvbuf"));
        }
        let v = d[*c..*c + sz].to_vec();
        *c += sz;
        Ok(Tpm2bMaxNvBuffer(v))
    }
}

#[derive(Debug, Clone)]
pub struct NvPublic {
    pub nv_index: u32,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub data_size: u16,
}

impl TpmMarshal for NvPublic {
    fn marshal(&self, buf: &mut Vec<u8>) {
        // We produce the inner structure first then size prefix (TPM2B_NV_PUBLIC-like without the outer name field)
        let mut inner = Vec::new();
        // Enforce masking out of nv_platformcreate (bit 30) and nv_written (bit 29) if inadvertently set.
        // Spec: These bits are set by the TPM, not the caller, and presence (especially platformcreate)
        // changes which hierarchy can authorize NV undefine. Stripping ensures owner-defined indices behave.
        let masked_attributes = self.attributes & !(1u32 << 30) & !(1u32 << 29);
        if masked_attributes != self.attributes {
            tracing::trace!(target: "guest_attest", orig = format_args!("0x{:08x}", self.attributes), masked = format_args!("0x{:08x}", masked_attributes), "NvPublic.marshal masking attributes");
        } else {
            tracing::trace!(target: "guest_attest", attrs = format_args!("0x{:08x}", self.attributes), "NvPublic.marshal attributes");
        }
        self.nv_index.marshal(&mut inner);
        self.name_alg.marshal(&mut inner);
        masked_attributes.marshal(&mut inner);
        (self.auth_policy.len() as u16).marshal(&mut inner);
        inner.extend_from_slice(&self.auth_policy);
        self.data_size.marshal(&mut inner);
        (inner.len() as u16).marshal(buf); // size of nvPublic
        buf.extend_from_slice(&inner);
    }
}

impl NvPublic {
    /// Create an NvPublic for an extend-type NV index (like a PCR).
    /// This is suitable for guest measurement logging where values are extended.
    ///
    /// Attributes set (matching Python tpm2-pytss version):
    /// - OWNERWRITE: Owner can extend
    /// - AUTHREAD: Auth can read
    /// - NO_DA: No dictionary attack protection
    /// - CLEAR_STCLEAR: Cleared on TPM2_Clear with ST_CLEAR
    /// - NT_EXTEND: NV type is extend (value = SHA256(old || new))
    pub fn new_extend_index(nv_index: u32, data_size: u16) -> Self {
        // Build attributes using TpmaNvBits - matches Python:
        // TPMA_NV.OWNERWRITE | TPMA_NV.AUTHREAD | TPMA_NV.NO_DA | TPMA_NV.CLEAR_STCLEAR | TPM2_NT.EXTEND
        let attrs = TpmaNvBits::new()
            .with_nv_ownerwrite(true)
            .with_nv_authread(true)
            .with_nv_no_da(true)
            .with_nv_clear_stclear(true)
            .with_nt_extend(true); // TPM2_NT_EXTEND = 0x4 in bits 7:4

        NvPublic {
            nv_index,
            name_alg: ALG_SHA256,
            attributes: attrs.into(),
            auth_policy: Vec::new(),
            data_size,
        }
    }

    /// Create an NvPublic for a standard (ordinary) NV index for read/write storage.
    ///
    /// Attributes set:
    /// - OWNERWRITE: Owner can write
    /// - OWNERREAD: Owner can read
    /// - AUTHREAD: Auth can read
    /// - AUTHWRITE: Auth can write
    /// - NO_DA: No dictionary attack protection
    pub fn new_ordinary_index(nv_index: u32, data_size: u16) -> Self {
        let attrs = TpmaNvBits::new()
            .with_nv_ownerwrite(true)
            .with_nv_ownerread(true)
            .with_nv_authread(true)
            .with_nv_authwrite(true)
            .with_nv_no_da(true);

        NvPublic {
            nv_index,
            name_alg: ALG_SHA256,
            attributes: attrs.into(),
            auth_policy: Vec::new(),
            data_size,
        }
    }

    /// Check if this NV index is an extend-type index.
    pub fn is_extend_type(&self) -> bool {
        // TPM2_NT is in bits 7:4, EXTEND = 0x4
        let nt = (self.attributes >> 4) & 0xF;
        nt == 0x4
    }
}

// NV refined command structures -------------------------------------------
define_handle_struct!(NvReadPublicCommandHandles;);

#[derive(Debug, Clone)]
pub struct NvReadPublicCommandParameters {
    pub nv_index: u32,
}

impl TpmMarshal for NvReadPublicCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.nv_index.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct NvReadPublicCommand {
    pub header: TpmCommandHeader,
    pub handles: NvReadPublicCommandHandles,
    pub parameters: NvReadPublicCommandParameters,
}

impl NvReadPublicCommand {
    pub fn new(nv_index: u32) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::NvReadPublic),
            handles: NvReadPublicCommandHandles,
            parameters: NvReadPublicCommandParameters { nv_index },
        }
    }

    pub fn handle_values(&self) -> [u32; 0] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct NvReadPublicResponseParameters {
    pub public: NvPublic,
    pub name: Tpm2bBytes, // trailing name (TPM2B_NAME) if present
}

impl TpmUnmarshal for NvReadPublicResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        // nvPublic size
        let nv_pub_size = u16::unmarshal(d, c)? as usize;
        if *c + nv_pub_size > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "nvPublic truncated",
            ));
        }
        let start = *c;
        let mut inner = *c;
        if inner + 12 > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "nvPublic header",
            ));
        }
        let nv_index = u32::unmarshal(d, &mut inner)?;
        let name_alg = u16::unmarshal(d, &mut inner)?;
        let attributes = u32::unmarshal(d, &mut inner)?;
        let policy_size = u16::unmarshal(d, &mut inner)? as usize;
        if inner + policy_size > d.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "authPolicy"));
        }
        let auth_policy = d[inner..inner + policy_size].to_vec();
        inner += policy_size;
        let data_size = u16::unmarshal(d, &mut inner)?;
        // Advance overall cursor to end of nvPublic block
        *c = start + nv_pub_size;
        // Following is name (TPM2B_NAME)
        let name = if *c + 2 <= d.len() {
            Tpm2bBytes::unmarshal(d, c)?
        } else {
            Tpm2bBytes(Vec::new())
        };

        Ok(NvReadPublicResponseParameters {
            public: NvPublic {
                nv_index,
                name_alg,
                attributes,
                auth_policy,
                data_size,
            },
            name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NvReadPublicResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvReadPublicResponseParameters,
}

impl NvReadPublicResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvReadPublic returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvReadPublic response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = NvReadPublicResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NvReadPublic response parameter size mismatch",
                ));
            }
        }

        Ok(NvReadPublicResponse { header, parameters })
    }
}

// Handles: auth_handle (typically owner or index auth), nv_index
define_handle_struct!(NvReadCommandHandles {
    auth_handle,
    nv_index
});

#[derive(Debug, Clone)]
pub struct NvReadCommandParameters {
    pub size: u16,
    pub offset: u16,
}

impl TpmMarshal for NvReadCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.size.marshal(buf);
        self.offset.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct NvReadCommand {
    pub header: TpmCommandHeader,
    pub handles: NvReadCommandHandles,
    pub parameters: NvReadCommandParameters,
}

impl NvReadCommand {
    pub fn new(auth_handle: u32, nv_index: u32, parameters: NvReadCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::NvRead),
            handles: NvReadCommandHandles {
                auth_handle,
                nv_index,
            },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct NvReadResponseParameters {
    pub data: Vec<u8>,
}

impl TpmUnmarshal for NvReadResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let nv_buf = Tpm2bMaxNvBuffer::unmarshal(d, c)?;
        Ok(NvReadResponseParameters { data: nv_buf.0 })
    }
}

#[derive(Debug, Clone)]
pub struct NvReadResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvReadResponseParameters,
}

impl NvReadResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvRead returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvRead response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = NvReadResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NvRead response parameter size mismatch",
                ));
            }
        }

        Ok(NvReadResponse { header, parameters })
    }
}

define_handle_struct!(NvWriteCommandHandles {
    auth_handle,
    nv_index
});

#[derive(Debug, Clone)]
pub struct NvWriteCommandParameters {
    pub data: Tpm2bMaxNvBuffer,
    pub offset: u16,
}

impl TpmMarshal for NvWriteCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.data.marshal(buf);
        self.offset.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct NvWriteCommand {
    pub header: TpmCommandHeader,
    pub handles: NvWriteCommandHandles,
    pub parameters: NvWriteCommandParameters,
}

impl NvWriteCommand {
    pub fn new(auth_handle: u32, nv_index: u32, parameters: NvWriteCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::NvWrite),
            handles: NvWriteCommandHandles {
                auth_handle,
                nv_index,
            },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NvWriteResponseParameters;

impl TpmUnmarshal for NvWriteResponseParameters {
    fn unmarshal(_d: &[u8], _c: &mut usize) -> io::Result<Self> {
        Ok(NvWriteResponseParameters)
    }
}

#[derive(Debug, Clone)]
pub struct NvWriteResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvWriteResponseParameters,
}

impl NvWriteResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvWrite returned error 0x{:08x}",
                header.return_code
            )));
        }

        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvWrite response parameter size exceeds buffer",
                ));
            }
        }

        Ok(NvWriteResponse {
            header,
            parameters: NvWriteResponseParameters,
        })
    }
}

define_handle_struct!(NvDefineSpaceCommandHandles { auth_handle });

#[derive(Debug, Clone)]
pub struct NvDefineSpaceCommandParameters {
    pub auth: Tpm2bBytes,      // TPM2B_AUTH
    pub public_info: NvPublic, // nvPublic structure
}

impl TpmMarshal for NvDefineSpaceCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.auth.marshal(buf);
        self.public_info.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct NvDefineSpaceCommand {
    pub header: TpmCommandHeader,
    pub handles: NvDefineSpaceCommandHandles,
    pub parameters: NvDefineSpaceCommandParameters,
}

impl NvDefineSpaceCommand {
    pub fn new(auth_handle: u32, parameters: NvDefineSpaceCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::NvDefineSpace),
            handles: NvDefineSpaceCommandHandles { auth_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NvDefineSpaceResponseParameters;

impl TpmUnmarshal for NvDefineSpaceResponseParameters {
    fn unmarshal(_d: &[u8], _c: &mut usize) -> io::Result<Self> {
        Ok(NvDefineSpaceResponseParameters)
    }
}

#[derive(Debug, Clone)]
pub struct NvDefineSpaceResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvDefineSpaceResponseParameters,
}

impl NvDefineSpaceResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvDefineSpace returned error 0x{:08x}",
                header.return_code
            )));
        }

        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvDefineSpace response parameter size exceeds buffer",
                ));
            }
        }

        Ok(NvDefineSpaceResponse {
            header,
            parameters: NvDefineSpaceResponseParameters,
        })
    }
}

define_handle_struct!(NvUndefineSpaceCommandHandles {
    auth_handle,
    nv_index
});

#[derive(Debug, Clone, Default)]
pub struct NvUndefineSpaceCommandParameters;

impl TpmMarshal for NvUndefineSpaceCommandParameters {
    fn marshal(&self, _buf: &mut Vec<u8>) {}
}

#[derive(Debug, Clone)]
pub struct NvUndefineSpaceCommand {
    pub header: TpmCommandHeader,
    pub handles: NvUndefineSpaceCommandHandles,
    pub parameters: NvUndefineSpaceCommandParameters,
}

impl NvUndefineSpaceCommand {
    pub fn new(auth_handle: u32, nv_index: u32) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::NvUndefineSpace),
            handles: NvUndefineSpaceCommandHandles {
                auth_handle,
                nv_index,
            },
            parameters: NvUndefineSpaceCommandParameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NvUndefineSpaceResponseParameters;

impl TpmUnmarshal for NvUndefineSpaceResponseParameters {
    fn unmarshal(_d: &[u8], _c: &mut usize) -> io::Result<Self> {
        Ok(NvUndefineSpaceResponseParameters)
    }
}

#[derive(Debug, Clone)]
pub struct NvUndefineSpaceResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvUndefineSpaceResponseParameters,
}

impl NvUndefineSpaceResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvUndefineSpace returned error 0x{:08x}",
                header.return_code
            )));
        }

        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvUndefineSpace response parameter size exceeds buffer",
                ));
            }
        }

        Ok(NvUndefineSpaceResponse {
            header,
            parameters: NvUndefineSpaceResponseParameters,
        })
    }
}

// TPM2_NV_Extend command & response ----------------------------------------
define_handle_struct!(NvExtendCommandHandles {
    auth_handle,
    nv_index
});

#[derive(Debug, Clone)]
pub struct NvExtendCommandParameters {
    pub data: Tpm2bMaxNvBuffer,
}

impl TpmMarshal for NvExtendCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.data.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct NvExtendCommand {
    pub header: TpmCommandHeader,
    pub handles: NvExtendCommandHandles,
    pub parameters: NvExtendCommandParameters,
}

impl NvExtendCommand {
    pub fn new(auth_handle: u32, nv_index: u32, data: Vec<u8>) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::NvExtend),
            handles: NvExtendCommandHandles {
                auth_handle,
                nv_index,
            },
            parameters: NvExtendCommandParameters {
                data: Tpm2bMaxNvBuffer(data),
            },
        }
    }

    pub fn handle_values(&self) -> [u32; 2] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NvExtendResponseParameters;

impl TpmUnmarshal for NvExtendResponseParameters {
    fn unmarshal(_d: &[u8], _c: &mut usize) -> io::Result<Self> {
        Ok(NvExtendResponseParameters)
    }
}

#[derive(Debug, Clone)]
pub struct NvExtendResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvExtendResponseParameters,
}

impl NvExtendResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvExtend returned error 0x{:08x}",
                header.return_code
            )));
        }

        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvExtend response parameter size exceeds buffer",
                ));
            }
        }

        Ok(NvExtendResponse {
            header,
            parameters: NvExtendResponseParameters,
        })
    }
}

// TPM2_NV_Certify command & response ----------------------------------------
define_handle_struct!(NvCertifyCommandHandles {
    sign_handle,
    auth_handle,
    nv_index
});

#[derive(Debug, Clone)]
pub struct NvCertifyCommandParameters {
    pub qualifying_data: Tpm2bBytes,
    pub in_scheme: TpmtSigScheme,
    pub size: u16,
    pub offset: u16,
}

impl TpmMarshal for NvCertifyCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.qualifying_data.marshal(buf);
        self.in_scheme.marshal(buf);
        self.size.marshal(buf);
        self.offset.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct NvCertifyCommand {
    pub header: TpmCommandHeader,
    pub handles: NvCertifyCommandHandles,
    pub parameters: NvCertifyCommandParameters,
}

impl NvCertifyCommand {
    pub fn new(
        sign_handle: u32,
        auth_handle: u32,
        nv_index: u32,
        qualifying_data: Vec<u8>,
        size: u16,
        offset: u16,
    ) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::NvCertify),
            handles: NvCertifyCommandHandles {
                sign_handle,
                auth_handle,
                nv_index,
            },
            parameters: NvCertifyCommandParameters {
                qualifying_data: Tpm2bBytes(qualifying_data),
                in_scheme: TpmtSigScheme::Rsassa(ALG_SHA256),
                size,
                offset,
            },
        }
    }

    pub fn handle_values(&self) -> [u32; 3] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct NvCertifyResponseParameters {
    pub certify_info: Vec<u8>,
    pub signature: TpmtSignature,
}

impl TpmUnmarshal for NvCertifyResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        // TPM2B_ATTEST
        let attest_size = u16::unmarshal(d, c)? as usize;
        if *c + attest_size > d.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NvCertify attest truncated",
            ));
        }
        let certify_info = d[*c..*c + attest_size].to_vec();
        *c += attest_size;
        // TPMT_SIGNATURE
        let signature = TpmtSignature::unmarshal(d, c)?;
        Ok(NvCertifyResponseParameters {
            certify_info,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NvCertifyResponse {
    pub header: TpmResponseHeader,
    pub parameters: NvCertifyResponseParameters,
}

impl NvCertifyResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "NvCertify returned error 0x{:08x}",
                header.return_code
            )));
        }

        if header.has_sessions() {
            let param_size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + param_size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NvCertify response parameter size exceeds buffer",
                ));
            }
        }

        let parameters = NvCertifyResponseParameters::unmarshal(bytes, &mut cursor)?;
        Ok(NvCertifyResponse { header, parameters })
    }
}

// PCR_Read command & response (single selection list already marshaled separately)
define_handle_struct!(PcrReadCommandHandles;);

#[derive(Debug, Clone)]
pub struct PcrReadCommandParameters {
    pub pcr_select: PcrSelectionList,
}

impl TpmMarshal for PcrReadCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.pcr_select.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct PcrReadCommand {
    pub header: TpmCommandHeader,
    pub handles: PcrReadCommandHandles,
    pub parameters: PcrReadCommandParameters,
}

impl PcrReadCommand {
    pub fn new(pcr_select: PcrSelectionList) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::PcrRead),
            handles: PcrReadCommandHandles,
            parameters: PcrReadCommandParameters { pcr_select },
        }
    }

    pub fn handle_values(&self) -> [u32; 0] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct PcrReadResponseParameters {
    pub update_counter: u32,
    pub selections: Vec<PcrSelection>,
    pub digests: Vec<Vec<u8>>,
}

impl TpmUnmarshal for PcrReadResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let update_counter = u32::unmarshal(d, c)?;
        // Selections: TPML_PCR_SELECTION
        let sel_list = PcrSelectionList::unmarshal(d, c)?;
        // Digests: TPML_DIGEST (reuse existing DigestList)
        let digests = DigestList::unmarshal(d, c)?;

        Ok(PcrReadResponseParameters {
            update_counter,
            selections: sel_list.0,
            digests: digests.0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PcrReadResponse {
    pub header: TpmResponseHeader,
    pub parameters: PcrReadResponseParameters,
}

impl PcrReadResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "PcrRead returned error 0x{:08x}",
                header.return_code
            )));
        }

        let mut param_start = cursor;
        let mut param_size = None;
        if header.has_sessions() {
            let size = u32::unmarshal(bytes, &mut cursor)? as usize;
            if cursor + size > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "PcrRead response parameter size exceeds buffer",
                ));
            }
            param_start = cursor;
            param_size = Some(size);
        }

        let mut param_cursor = cursor;
        let parameters = PcrReadResponseParameters::unmarshal(bytes, &mut param_cursor)?;
        if let Some(size) = param_size {
            if param_cursor - param_start != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PcrRead response parameter size mismatch",
                ));
            }
        }

        Ok(PcrReadResponse { header, parameters })
    }
}

// --- Attestation Parsing --------------------------------------------------

#[derive(Debug, Clone)]
pub struct ParsedQuoteAttest {
    pub pcr_selections: Vec<PcrSelection>,
    pub pcr_digests: Vec<Vec<u8>>,
    pub extra_data: Vec<u8>,
}

impl TpmtPublic {
    pub fn rsa_unique_modulus(&self) -> Option<&[u8]> {
        if self.type_alg == 0x0001 {
            Some(&self.unique.0)
        } else {
            None
        }
    }
}

pub fn parse_quote_attestation(attest_body: &[u8]) -> io::Result<ParsedQuoteAttest> {
    // Expect TPMS_ATTEST for QUOTE: magic(4) type(2)=0x8018 ...
    let mut c = 0usize;
    if attest_body.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "attest too small",
        ));
    }
    let _magic = u32::unmarshal(attest_body, &mut c)?; // could verify 0xff544347
    let atype = u16::unmarshal(attest_body, &mut c)?;
    if atype != 0x8018 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected attest type {:04x}", atype),
        ));
    }
    // qualifiedSigner (TPM2B_NAME)
    let qsz = u16::unmarshal(attest_body, &mut c)? as usize;
    if c + qsz > attest_body.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "qualifiedSigner",
        ));
    }
    c += qsz;
    // extraData (TPM2B_DATA)
    let ed_sz = u16::unmarshal(attest_body, &mut c)? as usize;
    if c + ed_sz > attest_body.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "extraData"));
    }
    let extra = attest_body[c..c + ed_sz].to_vec();
    c += ed_sz;
    // clockInfo
    if c + 17 > attest_body.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "clockInfo"));
    }
    c += 17; // skip
             // firmwareVersion
    if c + 8 > attest_body.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "firmwareVersion",
        ));
    }
    c += 8;
    // TPMS_QUOTE_INFO
    let pcr_sel_list = PcrSelectionList::unmarshal(attest_body, &mut c)?;
    // TPML_DIGEST
    let digests = DigestList::unmarshal(attest_body, &mut c)?;
    Ok(ParsedQuoteAttest {
        pcr_selections: pcr_sel_list.0,
        pcr_digests: digests.0,
        extra_data: extra,
    })
}

// TPM2_Sign command -----------------------------------------------------------
define_handle_struct!(SignCommandHandles { key_handle });

/// TPMT_TK_HASHCHECK structure for Sign command validation ticket
#[derive(Debug, Clone)]
pub struct TpmtTkHashcheck {
    pub tag: u16,
    pub hierarchy: u32,
    pub digest: Tpm2bBytes,
}

impl TpmMarshal for TpmtTkHashcheck {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.tag.marshal(buf);
        self.hierarchy.marshal(buf);
        self.digest.marshal(buf);
    }
}

impl TpmtTkHashcheck {
    /// Create a NULL ticket (for unrestricted keys)
    pub fn null_ticket() -> Self {
        Self {
            tag: 0x8024,            // TPM_ST_HASHCHECK
            hierarchy: 0x4000_0007, // TPM_RH_NULL
            digest: Tpm2bBytes(Vec::new()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignCommandParameters {
    pub digest: Tpm2bBytes,
    pub scheme: TpmtSigScheme,
    pub validation: TpmtTkHashcheck,
}

impl TpmMarshal for SignCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.digest.marshal(buf);
        self.scheme.marshal(buf);
        self.validation.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct SignCommand {
    pub header: TpmCommandHeader,
    pub handles: SignCommandHandles,
    pub parameters: SignCommandParameters,
}

impl SignCommand {
    pub fn new(key_handle: u32, parameters: SignCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::sessions(TpmCommandCode::Sign),
            handles: SignCommandHandles { key_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

#[derive(Debug, Clone)]
pub struct SignResponseParameters {
    pub signature: TpmtSignature,
}

impl TpmUnmarshal for SignResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let signature = TpmtSignature::unmarshal(d, c)?;
        Ok(SignResponseParameters { signature })
    }
}

#[derive(Debug, Clone)]
pub struct SignResponse {
    pub header: TpmResponseHeader,
    pub parameters: SignResponseParameters,
}

impl SignResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "Sign returned error 0x{:08x}",
                header.return_code
            )));
        }

        // Skip paramSize for sessions response
        if header.has_sessions() {
            let _param_size = u32::unmarshal(bytes, &mut cursor)?;
        }

        let parameters = SignResponseParameters::unmarshal(bytes, &mut cursor)?;
        Ok(SignResponse { header, parameters })
    }
}

// TPM2_VerifySignature command ------------------------------------------------
define_handle_struct!(VerifySignatureCommandHandles { key_handle });

#[derive(Debug, Clone)]
pub struct VerifySignatureCommandParameters {
    pub digest: Tpm2bBytes,
    pub signature: TpmtSignature,
}

impl TpmMarshal for VerifySignatureCommandParameters {
    fn marshal(&self, buf: &mut Vec<u8>) {
        self.digest.marshal(buf);
        self.signature.marshal(buf);
    }
}

#[derive(Debug, Clone)]
pub struct VerifySignatureCommand {
    pub header: TpmCommandHeader,
    pub handles: VerifySignatureCommandHandles,
    pub parameters: VerifySignatureCommandParameters,
}

impl VerifySignatureCommand {
    pub fn new(key_handle: u32, parameters: VerifySignatureCommandParameters) -> Self {
        Self {
            header: TpmCommandHeader::no_sessions(TpmCommandCode::VerifySignature),
            handles: VerifySignatureCommandHandles { key_handle },
            parameters,
        }
    }

    pub fn handle_values(&self) -> [u32; 1] {
        self.handles.to_array()
    }
}

/// TPMT_TK_VERIFIED structure returned by VerifySignature
#[derive(Debug, Clone)]
pub struct TpmtTkVerified {
    pub tag: u16,
    pub hierarchy: u32,
    pub digest: Tpm2bBytes,
}

impl TpmUnmarshal for TpmtTkVerified {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let tag = u16::unmarshal(d, c)?;
        let hierarchy = u32::unmarshal(d, c)?;
        let digest = Tpm2bBytes::unmarshal(d, c)?;
        Ok(TpmtTkVerified {
            tag,
            hierarchy,
            digest,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerifySignatureResponseParameters {
    pub validation: TpmtTkVerified,
}

impl TpmUnmarshal for VerifySignatureResponseParameters {
    fn unmarshal(d: &[u8], c: &mut usize) -> io::Result<Self> {
        let validation = TpmtTkVerified::unmarshal(d, c)?;
        Ok(VerifySignatureResponseParameters { validation })
    }
}

#[derive(Debug, Clone)]
pub struct VerifySignatureResponse {
    pub header: TpmResponseHeader,
    pub parameters: VerifySignatureResponseParameters,
}

impl VerifySignatureResponse {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, mut cursor) = TpmResponseHeader::parse(bytes)?;
        if header.return_code != 0 {
            return Err(io::Error::other(format!(
                "VerifySignature returned error 0x{:08x}",
                header.return_code
            )));
        }

        // VerifySignature uses no sessions so no paramSize
        let parameters = VerifySignatureResponseParameters::unmarshal(bytes, &mut cursor)?;
        Ok(VerifySignatureResponse { header, parameters })
    }
}

pub mod command_prelude {
    pub use super::{
        ecc_unrestricted_signing_public, ecc_unrestricted_signing_public_with_policy,
        empty_sensitive_create, CertifyCommand, CertifyCommandHandles, CertifyCommandParameters,
        CertifyResponse, CertifyResponseParameters, CreatePrimaryCommand,
        CreatePrimaryCommandHandles, CreatePrimaryCommandParameters, CreatePrimaryResponse,
        CreatePrimaryResponseHandles, CreatePrimaryResponseParameters, EccScheme,
        EvictControlCommand, EvictControlCommandHandles, EvictControlCommandParameters,
        EvictControlResponse, EvictControlResponseParameters, FlushContextCommand,
        FlushContextCommandHandles, FlushContextCommandParameters, Hierarchy, LoadCommand,
        LoadCommandHandles, LoadCommandParameters, LoadResponse, LoadResponseHandles,
        LoadResponseParameters, NvCertifyCommand, NvCertifyCommandHandles,
        NvCertifyCommandParameters, NvCertifyResponse, NvCertifyResponseParameters,
        NvDefineSpaceCommand, NvDefineSpaceCommandHandles, NvDefineSpaceCommandParameters,
        NvDefineSpaceResponse, NvDefineSpaceResponseParameters, NvExtendCommand,
        NvExtendCommandHandles, NvExtendCommandParameters, NvExtendResponse,
        NvExtendResponseParameters, NvPublic, NvReadCommand, NvReadCommandHandles,
        NvReadCommandParameters, NvReadPublicCommand, NvReadPublicCommandHandles,
        NvReadPublicCommandParameters, NvReadPublicResponse, NvReadPublicResponseParameters,
        NvReadResponse, NvReadResponseParameters, NvUndefineSpaceCommand,
        NvUndefineSpaceCommandHandles, NvUndefineSpaceCommandParameters, NvUndefineSpaceResponse,
        NvUndefineSpaceResponseParameters, NvWriteCommand, NvWriteCommandHandles,
        NvWriteCommandParameters, NvWriteResponse, NvWriteResponseParameters, PcrReadCommand,
        PcrReadCommandHandles, PcrReadCommandParameters, PcrReadResponse,
        PcrReadResponseParameters, PcrSelectionList, PolicyGetDigestCommand,
        PolicyGetDigestCommandHandles, PolicyGetDigestCommandParameters, PolicyGetDigestResponse,
        PolicyGetDigestResponseParameters, PolicyPcrCommand, PolicyPcrCommandHandles,
        PolicyPcrCommandParameters, QuoteCommand, QuoteCommandHandles, QuoteCommandParameters,
        QuoteResponse, QuoteResponseParameters, ReadPublicCommand, ReadPublicCommandHandles,
        ReadPublicCommandParameters, ReadPublicResponse, ReadPublicResponseParameters,
        RsaDecryptCommand, RsaDecryptCommandHandles, RsaDecryptCommandParameters,
        RsaDecryptResponse, RsaDecryptResponseParameters, SignCommand, SignCommandHandles,
        SignCommandParameters, SignResponse, SignResponseParameters, StartAuthSessionCommand,
        StartAuthSessionCommandHandles, StartAuthSessionCommandParameters,
        StartAuthSessionResponse, StartAuthSessionResponseHandles,
        StartAuthSessionResponseParameters, SymDefObject, Tpm2bBytes, Tpm2bMaxNvBuffer,
        Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicEcc, Tpm2bSensitiveData, TpmAlgId, TpmCommandCode,
        TpmMarshal, TpmUnmarshal, TpmaNvBits, TpmsEccPoint, TpmsSignatureEcdsa, TpmtPublicEcc,
        TpmtRsaDecryptScheme, TpmtSigScheme, TpmtSignature, TpmtTkHashcheck, TpmtTkVerified,
        UnsealCommand, UnsealCommandHandles, UnsealCommandParameters, UnsealResponse,
        UnsealResponseParameters, VerifySignatureCommand, VerifySignatureCommandHandles,
        VerifySignatureCommandParameters, VerifySignatureResponse,
        VerifySignatureResponseParameters, ALG_ECC, ALG_ECDSA, ALG_SHA256, TPM_ECC_NIST_P256,
        TPM_ECC_NIST_P384,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marshal_rsa_restricted_public_nonzero() {
        let pub_area = rsa_unrestricted_sign_decrypt_public();
        let mut buf = Vec::new();
        pub_area.marshal(&mut buf);
        assert!(buf.len() > 10, "expected reasonably sized public area");
        // size prefix matches
        let sz = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(sz + 2, buf.len());
    }

    #[test]
    fn marshal_empty_sensitive_create_size() {
        let sc = empty_sensitive_create();
        let mut buf = Vec::new();
        sc.marshal(&mut buf);
        // inner structure has two empty size fields (0,0) so total inner size = 4
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 4);
        assert_eq!(&buf[2..6], &[0, 0, 0, 0]);
    }

    #[test]
    fn marshal_pcr_selection_list() {
        let mut sel = [0u8; 3];
        sel[0] = 0b0000_0011; // PCR0, PCR1
        let list = PcrSelectionList(vec![PcrSelection {
            hash_alg: 0x000B,
            size_of_select: 3,
            select: sel,
        }]);
        let mut buf = Vec::new();
        list.marshal(&mut buf);
        // count
        assert_eq!(&buf[0..4], &1u32.to_be_bytes());
        // hash alg
        assert_eq!(&buf[4..6], &0x000B_u16.to_be_bytes());
        assert_eq!(buf[6], 3);
        assert_eq!(&buf[7..10], &sel);
    }

    #[test]
    fn unmarshal_public_roundtrip() {
        let p = rsa_unrestricted_sign_decrypt_public();
        let mut buf = Vec::new();
        p.marshal(&mut buf);
        let mut c = 0usize;
        let parsed = super::Tpm2bPublic::unmarshal(&buf, &mut c).expect("unmarshal public");
        assert_eq!(c, buf.len());
        assert_eq!(parsed.inner.key_bits, 2048);
    }

    #[test]
    fn unmarshal_signature_rsassa() {
        // Build a fake RSASSA signature blob: scheme=0x0014, hash=0x000B, size=4, data=deadbeef
        let mut blob = Vec::new();
        0x0014u16.marshal(&mut blob);
        0x000Bu16.marshal(&mut blob);
        (4u16).marshal(&mut blob);
        blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut cur = 0usize;
        let sig = super::TpmtSignature::unmarshal(&blob, &mut cur).expect("sig parse");
        match sig {
            super::TpmtSignature::Rsassa { hash_alg, ref sig } => {
                assert_eq!(hash_alg, 0x000B);
                assert_eq!(sig, &vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("unexpected variant"),
        }
        assert_eq!(cur, blob.len());
    }

    #[test]
    fn rsa_unique_helper() {
        let p = rsa_unrestricted_sign_decrypt_public();
        let m = p.inner.rsa_unique_modulus();
        assert!(m.is_some());
        assert!(m.unwrap().is_empty()); // empty unique until created by TPM
    }

    #[test]
    fn parse_quote_attest_minimal() {
        // Build a synthetic minimal TPMS_ATTEST QUOTE body
        // magic(FF544347) type(8018) qualifiedSigner(0) extraData(0) clockInfo(17 bytes) firmware(8 bytes)
        // PCR selection list: count=0 ; digest list: count=0
        let mut b = Vec::new();
        0xFF544347u32.marshal(&mut b);
        0x8018u16.marshal(&mut b);
        (0u16).marshal(&mut b); // qualifiedSigner
        (0u16).marshal(&mut b); // extraData
                                // clockInfo: clock(u64)=0, resetCount(u32)=0, restartCount(u32)=0, safe(u8)=1
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&[0; 4]);
        b.push(1);
        b.extend_from_slice(&[0; 8]); // firmwareVersion
        (0u32).marshal(&mut b); // PCR selection count
        (0u32).marshal(&mut b); // digest count
        let parsed = parse_quote_attestation(&b).expect("parse attest");
        assert_eq!(parsed.pcr_selections.len(), 0);
        assert_eq!(parsed.pcr_digests.len(), 0);
        assert!(parsed.extra_data.is_empty());
    }

    #[test]
    fn nv_read_response_unmarshal() {
        // Build a synthetic NV_Read response with sessions tag (so paramSize is present)
        let data = b"hello".to_vec();
        let mut params = Vec::new();
        (data.len() as u16).marshal(&mut params);
        params.extend_from_slice(&data);
        let param_size = params.len() as u32;

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = NvReadResponse::from_bytes(&response).expect("nv read resp");
        assert_eq!(parsed.parameters.data, data);
    }

    #[test]
    fn pcr_read_response_unmarshal() {
        // Build synthetic PCR_Read response body (after header): updateCounter, selections, digests
        let mut body = Vec::new();
        42u32.marshal(&mut body); // update counter
                                  // TPML_PCR_SELECTION with one selection for hash SHA256 selecting PCR0
        let mut sel = [0u8; 3];
        sel[0] = 1; // PCR 0
        PcrSelectionList(vec![PcrSelection {
            hash_alg: 0x000B,
            size_of_select: 3,
            select: sel,
        }])
        .marshal(&mut body);
        // TPML_DIGEST count=1, digest size=32 (all zero)
        1u32.marshal(&mut body);
        (32u16).marshal(&mut body);
        body.extend_from_slice(&[0u8; 32]);
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        let total_size = (10 + body.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&body);

        let parsed = PcrReadResponse::from_bytes(&response).expect("pcr read resp");
        assert_eq!(parsed.parameters.update_counter, 42);
        assert_eq!(parsed.parameters.selections.len(), 1);
        assert_eq!(parsed.parameters.digests.len(), 1);
        assert_eq!(parsed.parameters.digests[0].len(), 32);
    }

    #[test]
    fn nv_read_public_response_unmarshal() {
        // Build nvPublic: nvIndex(4) nameAlg(2) attributes(4) authPolicySize(2) authPolicy bytes(0) dataSize(2)
        let mut nv_public = Vec::new();
        0x0150_0016u32.marshal(&mut nv_public); // nvIndex
        0x000Bu16.marshal(&mut nv_public); // nameAlg SHA256
        0x0020_0002u32.marshal(&mut nv_public); // attributes (arbitrary test)
        (0u16).marshal(&mut nv_public); // authPolicy size
        (64u16).marshal(&mut nv_public); // dataSize
        let mut blob = Vec::new();
        (nv_public.len() as u16).marshal(&mut blob);
        blob.extend_from_slice(&nv_public);
        // name (TPM2B_NAME) -> empty for simplicity
        (0u16).marshal(&mut blob);
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        let total_size = (10 + blob.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&blob);

        let parsed = NvReadPublicResponse::from_bytes(&response).expect("nv read public resp");
        assert_eq!(parsed.parameters.public.nv_index, 0x0150_0016);
        assert_eq!(parsed.parameters.public.data_size, 64);
        assert!(parsed.parameters.name.0.is_empty());
    }

    #[test]
    fn load_response_unmarshal() {
        let object_handle: u32 = 0x8100_1001;
        let name = b"test-name";
        let mut params = Vec::new();
        (name.len() as u16).marshal(&mut params);
        params.extend_from_slice(name);
        let param_size = params.len() as u32;

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&object_handle.to_be_bytes());
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = LoadResponse::from_bytes(&response).expect("load resp");
        assert_eq!(parsed.handles.object_handle, object_handle);
        assert_eq!(parsed.parameters.name.0, name);
    }

    #[test]
    fn unseal_response_unmarshal() {
        let data = b"sealed-data";
        let mut params = Vec::new();
        (data.len() as u16).marshal(&mut params);
        params.extend_from_slice(data);
        let param_size = params.len() as u32;

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = UnsealResponse::from_bytes(&response).expect("unseal resp");
        assert_eq!(parsed.parameters.out_data.0, data);
    }

    #[test]
    fn create_primary_response_unmarshal() {
        // Synthesize a minimal CreatePrimaryResponse parameter section after header.
        // Layout: handle, paramSize, outPublic, creationData, creationHash, ticket, name, qualifiedName.
        let handle: u32 = 0x8100_0001;
        let pub_area = rsa_unrestricted_sign_decrypt_public();
        // Build the parameter area (excluding handle + paramSize) first so we can compute paramSize.
        let mut param_tail = Vec::new();
        pub_area.marshal(&mut param_tail); // TPM2B_PUBLIC
                                           // creationData (empty TPM2B -> size=0)
        (0u16).marshal(&mut param_tail);
        // creationHash (empty TPM2B)
        (0u16).marshal(&mut param_tail);
        // ticket: tag(u16)=0x8021 (TPM_ST_CREATION), hierarchy(u32)=0, digest(empty TPM2B_DIGEST)
        0x8021u16.marshal(&mut param_tail);
        0u32.marshal(&mut param_tail);
        (0u16).marshal(&mut param_tail); // digest size 0
                                         // name (empty TPM2B_NAME)
        (0u16).marshal(&mut param_tail);
        // qualifiedName (empty TPM2B_NAME)
        (0u16).marshal(&mut param_tail);

        let param_size = param_tail.len() as u32;
        let mut params = Vec::new();
        handle.marshal(&mut params);
        param_size.marshal(&mut params);
        params.extend_from_slice(&param_tail);

        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes()); // SUCCESS
        response.extend_from_slice(&params);

        let parsed = CreatePrimaryResponse::from_bytes(&response).expect("create primary parse");
        assert_eq!(parsed.header.tag, TPM_ST_SESSIONS);
        assert_eq!(parsed.handles.object_handle, handle);
        assert_eq!(parsed.parameters.out_public.inner.key_bits, 2048);
        assert!(parsed.parameters.creation_data.0.is_empty());
        assert!(parsed.parameters.creation_hash.0.is_empty());
        assert!(parsed.parameters.name.0.is_empty());
        assert!(parsed.parameters.qualified_name.0.is_empty());
    }

    #[test]
    fn quote_response_unmarshal() {
        // Build a synthetic QuoteResponse: TPM2B_ATTEST + TPMT_SIGNATURE(RSASSA SHA256)
        let attest_body = {
            // minimal TPMS_ATTEST QUOTE body reused from earlier test
            let mut b = Vec::new();
            0xFF544347u32.marshal(&mut b); // magic
            0x8018u16.marshal(&mut b); // type QUOTE
            (0u16).marshal(&mut b); // qualifiedSigner
            (0u16).marshal(&mut b); // extraData
            b.extend_from_slice(&[0; 8]); // clock
            b.extend_from_slice(&[0; 4]); // resetCount
            b.extend_from_slice(&[0; 4]); // restartCount
            b.push(1); // safe
            b.extend_from_slice(&[0; 8]); // firmware
            (0u32).marshal(&mut b); // PCR selection count
            (0u32).marshal(&mut b); // digest count
            b
        };
        let mut params = Vec::new();
        (attest_body.len() as u16).marshal(&mut params);
        params.extend_from_slice(&attest_body); // TPM2B_ATTEST
                                                // Signature: RSASSA, hash=SHA256, size=4, data=deadbeef
        0x0014u16.marshal(&mut params); // scheme RSASSA
        0x000Bu16.marshal(&mut params); // hash SHA256
        (4u16).marshal(&mut params); // sig size
        params.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let param_size = params.len() as u32;
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = QuoteResponse::from_bytes(&response).expect("quote parse");
        assert_eq!(parsed.parameters.attest.len(), attest_body.len());
        match parsed.parameters.signature {
            TpmtSignature::Rsassa { hash_alg, ref sig } => {
                assert_eq!(hash_alg, 0x000B);
                assert_eq!(sig, &vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("expected RSASSA signature"),
        }
    }

    #[test]
    fn read_public_response_unmarshal() {
        // Build a synthetic outPublic using existing helper
        let pub_area = rsa_unrestricted_sign_decrypt_public();
        let mut body = Vec::new();
        pub_area.marshal(&mut body); // TPM2B_PUBLIC
        (0u16).marshal(&mut body); // name (empty TPM2B_NAME)
        (0u16).marshal(&mut body); // qualifiedName (empty TPM2B_NAME)
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        let total_size = (10 + body.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&body);
        let parsed = ReadPublicResponse::from_bytes(&response).expect("read public resp");
        assert_eq!(parsed.parameters.out_public.inner.key_bits, 2048);
        assert!(parsed.parameters.name.0.is_empty());
        assert!(parsed.parameters.qualified_name.0.is_empty());
    }

    // ==================== ECC Type Tests ====================

    #[test]
    fn ecc_unrestricted_signing_public_marshals_correctly() {
        let pub_area = ecc_unrestricted_signing_public();
        let mut buf = Vec::new();
        pub_area.marshal(&mut buf);
        assert!(buf.len() > 10, "expected reasonably sized ECC public area");
        // size prefix matches
        let sz = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(sz + 2, buf.len());
        // Verify algorithm type is ECC
        let alg_type = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(alg_type, ALG_ECC, "expected ECC algorithm type");
    }

    #[test]
    fn tpms_ecc_point_marshal_roundtrip() {
        let point = TpmsEccPoint {
            x: vec![0x01, 0x02, 0x03, 0x04],
            y: vec![0x05, 0x06, 0x07, 0x08],
        };
        let mut buf = Vec::new();
        point.marshal(&mut buf);
        // Expect: size_x(2) + x(4) + size_y(2) + y(4) = 12 bytes
        assert_eq!(buf.len(), 12);
        let mut cur = 0usize;
        let parsed = TpmsEccPoint::unmarshal(&buf, &mut cur).expect("unmarshal ecc point");
        assert_eq!(cur, buf.len());
        assert_eq!(parsed.x, point.x);
        assert_eq!(parsed.y, point.y);
    }

    #[test]
    fn tpms_ecc_point_empty_coords() {
        let point = TpmsEccPoint {
            x: vec![],
            y: vec![],
        };
        let mut buf = Vec::new();
        point.marshal(&mut buf);
        // Expect: size_x(2) + size_y(2) = 4 bytes
        assert_eq!(buf.len(), 4);
        let mut cur = 0usize;
        let parsed = TpmsEccPoint::unmarshal(&buf, &mut cur).expect("unmarshal empty ecc point");
        assert!(parsed.x.is_empty());
        assert!(parsed.y.is_empty());
    }

    #[test]
    fn unmarshal_signature_ecdsa() {
        // Build a fake ECDSA signature blob: scheme=ALG_ECDSA, hash=SHA256, r_size, r, s_size, s
        let mut blob = Vec::new();
        ALG_ECDSA.marshal(&mut blob); // signature algorithm
        ALG_SHA256.marshal(&mut blob); // hash algorithm
        (4u16).marshal(&mut blob); // r size
        blob.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // r
        (4u16).marshal(&mut blob); // s size
        blob.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]); // s
        let mut cur = 0usize;
        let sig = TpmtSignature::unmarshal(&blob, &mut cur).expect("sig parse");
        match sig {
            TpmtSignature::Ecdsa(ecdsa) => {
                assert_eq!(ecdsa.hash_alg, ALG_SHA256);
                assert_eq!(ecdsa.signature_r, vec![0x11, 0x22, 0x33, 0x44]);
                assert_eq!(ecdsa.signature_s, vec![0x55, 0x66, 0x77, 0x88]);
            }
            _ => panic!("expected ECDSA signature variant"),
        }
        assert_eq!(cur, blob.len());
    }

    #[test]
    fn tpmt_signature_ecdsa_marshal_roundtrip() {
        let sig = TpmtSignature::Ecdsa(TpmsSignatureEcdsa {
            hash_alg: ALG_SHA256,
            signature_r: vec![0xAA; 32],
            signature_s: vec![0xBB; 32],
        });
        let mut buf = Vec::new();
        sig.marshal(&mut buf);
        // Expect: scheme(2) + hash(2) + r_size(2) + r(32) + s_size(2) + s(32) = 72 bytes
        assert_eq!(buf.len(), 72);
        let mut cur = 0usize;
        let parsed = TpmtSignature::unmarshal(&buf, &mut cur).expect("unmarshal ecdsa sig");
        assert_eq!(cur, buf.len());
        match parsed {
            TpmtSignature::Ecdsa(ecdsa) => {
                assert_eq!(ecdsa.hash_alg, ALG_SHA256);
                assert_eq!(ecdsa.signature_r.len(), 32);
                assert_eq!(ecdsa.signature_s.len(), 32);
            }
            _ => panic!("expected ECDSA variant after roundtrip"),
        }
    }

    #[test]
    fn tpmt_signature_null_marshal_unmarshal() {
        let sig = TpmtSignature::Null;
        let mut buf = Vec::new();
        sig.marshal(&mut buf);
        // Null signature: just the algorithm (0x0010)
        assert_eq!(buf.len(), 2);
        let mut cur = 0usize;
        let parsed = TpmtSignature::unmarshal(&buf, &mut cur).expect("unmarshal null sig");
        assert!(matches!(parsed, TpmtSignature::Null));
    }

    #[test]
    fn tpmt_tk_hashcheck_null_marshals_correctly() {
        let ticket = TpmtTkHashcheck::null_ticket();
        let mut buf = Vec::new();
        ticket.marshal(&mut buf);
        // Expect: tag(2) + hierarchy(4) + digest_size(2) = 8 bytes for null ticket
        assert_eq!(buf.len(), 8);
        // Verify tag is TPM_ST_HASHCHECK (0x8024)
        let tag = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(tag, 0x8024);
        // Verify hierarchy is TPM_RH_NULL (0x40000007)
        let hierarchy = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(hierarchy, 0x40000007);
    }

    #[test]
    fn tpm2b_public_ecc_marshal_includes_size_prefix() {
        let ecc_pub = ecc_unrestricted_signing_public();
        let mut buf = Vec::new();
        ecc_pub.marshal(&mut buf);
        // First 2 bytes should be size of inner content
        let size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(
            size + 2,
            buf.len(),
            "TPM2B size prefix should match content"
        );
    }

    // ==================== NvExtend Type Tests ====================

    #[test]
    fn nv_extend_command_marshal() {
        let cmd = NvExtendCommand::new(
            0x4000_0001,                  // auth handle (owner)
            0x0150_0030,                  // nv index
            vec![0xDE, 0xAD, 0xBE, 0xEF], // data to extend
        );
        // Verify handles are captured
        let handles = cmd.handle_values();
        assert_eq!(handles.len(), 2);
        assert_eq!(handles[0], 0x4000_0001);
        assert_eq!(handles[1], 0x0150_0030);
        // Verify parameters marshal correctly
        let mut buf = Vec::new();
        cmd.parameters.marshal(&mut buf);
        // Expect: size(2) + data(4) = 6 bytes
        assert_eq!(buf.len(), 6);
        let size = u16::from_be_bytes([buf[0], buf[1]]);
        assert_eq!(size, 4);
        assert_eq!(&buf[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn nv_extend_response_unmarshal_success() {
        // Build a synthetic NvExtend response (success, no output parameters)
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = 10u32 + 4; // header + paramSize only (no params)
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes()); // SUCCESS
        response.extend_from_slice(&0u32.to_be_bytes()); // paramSize = 0

        let parsed = NvExtendResponse::from_bytes(&response).expect("nv extend resp");
        assert_eq!(parsed.header.return_code, 0);
    }

    // ==================== NvCertify Type Tests ====================

    #[test]
    fn nv_certify_command_marshal() {
        let cmd = NvCertifyCommand::new(
            0x8100_0001,                  // signing key handle
            0x0150_0031,                  // auth handle (nv index)
            0x0150_0031,                  // nv index
            vec![0x01, 0x02, 0x03, 0x04], // qualifying data
            32,                           // size
            0,                            // offset
        );
        // Verify handles are captured
        let handles = cmd.handle_values();
        assert_eq!(handles.len(), 3);
        assert_eq!(handles[0], 0x8100_0001);
        assert_eq!(handles[1], 0x0150_0031);
        assert_eq!(handles[2], 0x0150_0031);
        // Verify parameters marshal correctly
        let mut buf = Vec::new();
        cmd.parameters.marshal(&mut buf);
        // Parameters: qualifying_data(2+4) + scheme(4 for RSASSA) + size(2) + offset(2) = 14 bytes
        assert!(buf.len() >= 10, "parameters should have minimum size");
    }

    #[test]
    fn nv_certify_response_unmarshal() {
        // Build a synthetic NvCertify response with attestation data and signature
        let attest_body = {
            let mut b = Vec::new();
            0xFF544347u32.marshal(&mut b); // magic
            0x8016u16.marshal(&mut b); // type NV_CERTIFY (TPM_ST_ATTEST_NV = 0x8016)
            (0u16).marshal(&mut b); // qualifiedSigner
            (0u16).marshal(&mut b); // extraData
            b.extend_from_slice(&[0; 8]); // clock
            b.extend_from_slice(&[0; 4]); // resetCount
            b.extend_from_slice(&[0; 4]); // restartCount
            b.push(1); // safe
            b.extend_from_slice(&[0; 8]); // firmware
                                          // TPMS_NV_CERTIFY_INFO: indexName + offset + nvContents
            (4u16).marshal(&mut b); // indexName size
            b.extend_from_slice(&[0x00, 0x0B, 0xAA, 0xBB]); // fake name
            (0u16).marshal(&mut b); // offset
            (4u16).marshal(&mut b); // nvContents size
            b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // nvContents
            b
        };
        let mut params = Vec::new();
        (attest_body.len() as u16).marshal(&mut params);
        params.extend_from_slice(&attest_body); // TPM2B_ATTEST
                                                // Signature: RSASSA, hash=SHA256, size=4, data=cafebabe
        0x0014u16.marshal(&mut params); // scheme RSASSA
        0x000Bu16.marshal(&mut params); // hash SHA256
        (4u16).marshal(&mut params); // sig size
        params.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);

        let param_size = params.len() as u32;
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        let total_size = (10 + 4 + params.len()) as u32;
        response.extend_from_slice(&total_size.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes()); // SUCCESS
        response.extend_from_slice(&param_size.to_be_bytes());
        response.extend_from_slice(&params);

        let parsed = NvCertifyResponse::from_bytes(&response).expect("nv certify resp");
        assert_eq!(parsed.header.return_code, 0);
        assert_eq!(parsed.parameters.certify_info.len(), attest_body.len());
        match parsed.parameters.signature {
            TpmtSignature::Rsassa { hash_alg, ref sig } => {
                assert_eq!(hash_alg, 0x000B);
                assert_eq!(sig, &vec![0xCA, 0xFE, 0xBA, 0xBE]);
            }
            _ => panic!("expected RSASSA signature for NvCertify"),
        }
    }

    // ==================== PcrAlgorithm Tests ====================

    #[test]
    fn pcr_algorithm_to_alg_id() {
        assert_eq!(PcrAlgorithm::Sha1.to_alg_id(), ALG_SHA1);
        assert_eq!(PcrAlgorithm::Sha256.to_alg_id(), ALG_SHA256);
        assert_eq!(PcrAlgorithm::Sha384.to_alg_id(), 0x000C);
    }

    #[test]
    fn pcr_algorithm_digest_len() {
        assert_eq!(PcrAlgorithm::Sha1.digest_len(), 20);
        assert_eq!(PcrAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(PcrAlgorithm::Sha384.digest_len(), 48);
    }

    #[test]
    fn pcr_algorithm_from_alg_id() {
        assert_eq!(
            PcrAlgorithm::from_alg_id(ALG_SHA1),
            Some(PcrAlgorithm::Sha1)
        );
        assert_eq!(
            PcrAlgorithm::from_alg_id(ALG_SHA256),
            Some(PcrAlgorithm::Sha256)
        );
        assert_eq!(
            PcrAlgorithm::from_alg_id(0x000C),
            Some(PcrAlgorithm::Sha384)
        );
        assert_eq!(PcrAlgorithm::from_alg_id(0xFFFF), None);
    }

    #[test]
    fn pcr_algorithm_display() {
        assert_eq!(format!("{}", PcrAlgorithm::Sha1), "sha1");
        assert_eq!(format!("{}", PcrAlgorithm::Sha256), "sha256");
        assert_eq!(format!("{}", PcrAlgorithm::Sha384), "sha384");
    }

    #[test]
    fn pcr_algorithm_from_str() {
        assert_eq!("sha1".parse::<PcrAlgorithm>(), Ok(PcrAlgorithm::Sha1));
        assert_eq!("SHA256".parse::<PcrAlgorithm>(), Ok(PcrAlgorithm::Sha256));
        assert_eq!("Sha384".parse::<PcrAlgorithm>(), Ok(PcrAlgorithm::Sha384));
        assert!("md5".parse::<PcrAlgorithm>().is_err());
        assert!("".parse::<PcrAlgorithm>().is_err());
    }

    // ==================== TpmaNvBits Tests ====================

    #[test]
    fn tpma_nv_bits_construction() {
        let bits = TpmaNvBits::new()
            .with_nv_ownerwrite(true)
            .with_nv_authwrite(true)
            .with_nv_ownerread(true)
            .with_nv_authread(true);
        let raw: u32 = bits.into();
        assert_ne!(raw, 0);
        assert!(bits.nv_ownerwrite());
        assert!(bits.nv_authwrite());
        assert!(bits.nv_ownerread());
        assert!(bits.nv_authread());
        assert!(!bits.nv_ppwrite());
    }

    #[test]
    fn tpma_nv_bits_extend() {
        let bits = TpmaNvBits::new().with_nt_extend(true);
        assert!(bits.nt_extend());
        assert!(!bits.nt_counter());
        assert!(!bits.nt_bits());
    }

    // ==================== Hierarchy Tests ====================

    #[test]
    fn hierarchy_handles() {
        assert_eq!(Hierarchy::Owner.handle(), 0x4000_0001);
        assert_eq!(Hierarchy::Null.handle(), 0x4000_0007);
        assert_eq!(Hierarchy::Endorsement.handle(), 0x4000_000B);
    }

    // ==================== TpmtRsaDecryptScheme Tests ====================

    #[test]
    fn rsa_decrypt_scheme_marshal() {
        let rsaes = TpmtRsaDecryptScheme::Rsaes;
        let mut buf = Vec::new();
        rsaes.marshal(&mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), ALG_RSAES);

        let oaep = TpmtRsaDecryptScheme::Oaep(ALG_SHA256);
        let mut buf2 = Vec::new();
        oaep.marshal(&mut buf2);
        // OAEP: alg_id(2) + hash_alg(2) = 4 bytes
        assert_eq!(buf2.len(), 4);
        assert_eq!(u16::from_be_bytes([buf2[0], buf2[1]]), ALG_OAEP);
        assert_eq!(u16::from_be_bytes([buf2[2], buf2[3]]), ALG_SHA256);
    }

    // ==================== SymDefObject Tests ====================

    #[test]
    fn sym_def_object_null_marshal() {
        let sym = SymDefObject {
            alg: 0x0010,
            key_bits: 0,
            mode: 0,
        };
        let mut buf = Vec::new();
        sym.marshal(&mut buf);
        // Null: just the algorithm (0x0010) = 2 bytes
        assert_eq!(buf.len(), 2);
    }

    // ==================== NvPublic Tests ====================

    #[test]
    fn nv_public_marshal_correct_size() {
        let np = NvPublic {
            nv_index: 0x0140_0001,
            name_alg: ALG_SHA256,
            attributes: TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD,
            auth_policy: vec![],
            data_size: 64,
        };
        let mut buf = Vec::new();
        np.marshal(&mut buf);
        // size_prefix(2) + nvIndex(4) + nameAlg(2) + attributes(4) + authPolicySize(2) + dataSize(2) = 16
        assert_eq!(buf.len(), 16);
        // Verify the size prefix matches inner content length
        let size_prefix = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(size_prefix + 2, buf.len());
    }

    #[test]
    fn nv_public_with_auth_policy_marshal() {
        let policy = vec![0xAA; 32];
        let np = NvPublic {
            nv_index: 0x0150_0030,
            name_alg: ALG_SHA256,
            attributes: 0,
            auth_policy: policy.clone(),
            data_size: 32,
        };
        let mut buf = Vec::new();
        np.marshal(&mut buf);
        // size_prefix(2) + nvIndex(4) + nameAlg(2) + attributes(4) + authPolicySize(2) + policy(32) + dataSize(2) = 48
        assert_eq!(buf.len(), 48);
    }

    #[test]
    fn nv_public_new_extend_index() {
        let np = NvPublic::new_extend_index(0x0150_0030, 32);
        assert_eq!(np.nv_index, 0x0150_0030);
        assert_eq!(np.data_size, 32);
        assert_eq!(np.name_alg, ALG_SHA256);
        // nt_extend bit should be set
        let bits = TpmaNvBits::from(np.attributes);
        assert!(bits.nt_extend());
    }

    #[test]
    fn nv_public_new_ordinary_index() {
        let np = NvPublic::new_ordinary_index(0x0140_0001, 64);
        assert_eq!(np.nv_index, 0x0140_0001);
        assert_eq!(np.data_size, 64);
        assert_eq!(np.name_alg, ALG_SHA256);
    }

    // ==================== Tpm2bBytes Tests ====================

    #[test]
    fn tpm2b_bytes_marshal_unmarshal() {
        let b = Tpm2bBytes(vec![0x01, 0x02, 0x03]);
        let mut buf = Vec::new();
        b.marshal(&mut buf);
        assert_eq!(buf.len(), 5); // 2 (size) + 3 (data)
        let mut cur = 0usize;
        let parsed = Tpm2bBytes::unmarshal(&buf, &mut cur).expect("unmarshal bytes");
        assert_eq!(parsed.0, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn tpm2b_bytes_empty() {
        let b = Tpm2bBytes(vec![]);
        let mut buf = Vec::new();
        b.marshal(&mut buf);
        assert_eq!(buf.len(), 2);
        let mut cur = 0usize;
        let parsed = Tpm2bBytes::unmarshal(&buf, &mut cur).expect("unmarshal empty bytes");
        assert!(parsed.0.is_empty());
    }
}
