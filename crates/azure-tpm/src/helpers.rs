// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Internal implementation — documentation deferred.
#![allow(missing_docs)]

use crate::types::TpmCommandCode;
use crate::types::TpmMarshal;
use crate::types::TPM_RS_PW;
use crate::types::TPM_ST_NO_SESSIONS;
use crate::types::TPM_ST_SESSIONS;
use std::fmt;
use std::io;

/// Structured TPM error carrying the raw response code (rc), decoded description,
/// and optional originating command code.
#[derive(Debug)]
pub struct TpmError {
    pub rc: u32,
    pub decoded: String,
    pub command: Option<TpmCommandCode>,
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(cmd) = &self.command {
            write!(
                f,
                "TPM error 0x{:08x} (command={:?}/0x{:08x}): {}",
                self.rc, cmd, *cmd as u32, self.decoded
            )
        } else {
            write!(f, "TPM error 0x{:08x}: {}", self.rc, self.decoded)
        }
    }
}

impl std::error::Error for TpmError {}

pub fn build_header_no_sessions(code: TpmCommandCode, out: &mut Vec<u8>) {
    out.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(code as u32).to_be_bytes());
}

pub fn finalize_size(out: &mut [u8]) {
    let len = out.len() as u32;
    out[2..6].copy_from_slice(&len.to_be_bytes());
}

pub fn build_header_sessions(code: TpmCommandCode, out: &mut Vec<u8>) {
    out.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(code as u32).to_be_bytes());
}

/// Build a TPM command without sessions given the code, handles and parameter payload marshaler closure.
pub fn build_command_no_sessions<F>(
    code: TpmCommandCode,
    handles: &[u32],
    mut marshal_params: F,
) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>),
{
    let mut buf = Vec::new();
    build_header_no_sessions(code, &mut buf);
    for h in handles {
        h.marshal(&mut buf);
    }
    marshal_params(&mut buf);
    finalize_size(&mut buf);
    buf
}

/// Build a TPM command with one or more password sessions (TPM_RS_PW) – one per entry in `session_auths`.
/// Each slice in `session_auths` is the authValue (may be empty) for the corresponding authorized handle.
/// The number of password sessions should match the number of authorized handles for the command,
/// but this function does not enforce semantic correctness beyond encoding.
pub fn build_command_pw_sessions<F>(
    code: TpmCommandCode,
    handles: &[u32],
    session_auths: &[&[u8]],
    mut marshal_params: F,
) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>),
{
    let mut buf = Vec::new();
    build_header_sessions(code, &mut buf);
    // Handle area
    for h in handles {
        h.marshal(&mut buf);
    }
    // Authorization area size is sum of session structures (excluding the u32 authorizationSize itself)
    // Each PW session structure = 4 (handle) + 2 (nonceSize=0) + 1 (attrs) + 2 (authSize) + auth.len()
    let mut auth_area_size: u32 = 0;
    for auth in session_auths {
        auth_area_size = auth_area_size
            .checked_add(4 + 2 + 1 + 2 + auth.len() as u32)
            .expect("auth area size overflow");
    }
    buf.extend_from_slice(&auth_area_size.to_be_bytes());
    for auth in session_auths {
        // sessionHandle = TPM_RS_PW
        buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        // nonceSize = 0
        buf.extend_from_slice(&0u16.to_be_bytes());
        // sessionAttributes = 0
        buf.push(0u8);
        // authSize
        buf.extend_from_slice(&(auth.len() as u16).to_be_bytes());
        // auth bytes
        if !auth.is_empty() {
            buf.extend_from_slice(auth);
        }
    }
    // Parameters
    marshal_params(&mut buf);
    finalize_size(&mut buf);
    buf
}

/// Session entry for `build_command_custom_sessions` allowing arbitrary session handles (e.g. policy sessions)
pub struct SessionEntry<'a> {
    pub handle: u32,
    pub auth: &'a [u8], // authValue or HMAC (empty for policy session with no auth)
    pub attrs: u8,      // sessionAttributes bitfield
}

/// Build a TPM command with arbitrary pre-existing session handles (e.g., policy session) plus optional auth bytes.
/// Caller is responsible for ensuring the session handles are valid and bound to the required policy or auth state.
pub fn build_command_custom_sessions<F>(
    code: TpmCommandCode,
    handles: &[u32],
    sessions: &[SessionEntry<'_>],
    mut marshal_params: F,
) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>),
{
    let mut buf = Vec::new();
    build_header_sessions(code, &mut buf);
    for h in handles {
        h.marshal(&mut buf);
    }
    // Compute auth area size (sum of session structs excluding the u32 size field itself)
    let mut auth_area_size: u32 = 0;
    for s in sessions {
        auth_area_size = auth_area_size
            .checked_add(4 + 2 + 1 + 2 + s.auth.len() as u32)
            .expect("auth area overflow");
    }
    buf.extend_from_slice(&auth_area_size.to_be_bytes());
    for s in sessions {
        buf.extend_from_slice(&s.handle.to_be_bytes()); // sessionHandle
        buf.extend_from_slice(&0u16.to_be_bytes()); // nonceSize=0
        buf.push(s.attrs); // sessionAttributes
        buf.extend_from_slice(&(s.auth.len() as u16).to_be_bytes());
        if !s.auth.is_empty() {
            buf.extend_from_slice(s.auth);
        }
    }
    marshal_params(&mut buf);
    finalize_size(&mut buf);
    buf
}

// NOTE: response_param_offset helper and legacy append_handles_* helpers removed after refactor.

/// Parse a TPM response code, associating it with a specific command.
pub(crate) fn parse_tpm_rc_with_cmd(resp: &[u8], command: TpmCommandCode) -> io::Result<()> {
    if resp.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "TPM response too short",
        ));
    }
    // Basic length check first so we don't decode nonsense
    let declared = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    if declared != resp.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "response length mismatch (declared {declared} actual {})",
                resp.len()
            ),
        ));
    }
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if rc != 0 {
        let decoded = decode_tpm_rc(rc);
        return Err(io::Error::other(TpmError {
            rc,
            decoded,
            command: Some(command),
        }));
    }
    Ok(())
}

/// Decode a TPM2 response code into a human-readable classification. Based on
/// TPM 2.0 Part 2 spec (response code structure). This is intentionally
/// partial; unknown codes are still surfaced with structural hints.
fn decode_tpm_rc(rc: u32) -> String {
    // Quick special cases
    if rc == 0 {
        return "SUCCESS".to_string();
    }

    // Format bit (bit 7)
    let is_format1 = (rc & 0x80) != 0; // TPM_RC_FMT1
                                       // Parameter / session / handle indicator bits
    let is_session = (rc & 0x800) != 0; // TPM_RC_S (bit 11)
    let is_handle = (rc & 0x100) != 0; // TPM_RC_H (bit 8)
                                       // If format1 and neither session nor handle bits set => parameter code
    let is_parameter = is_format1 && !is_session && !is_handle;
    let index = if is_format1 {
        ((rc >> 8) & 0x7) as u8
    } else {
        0
    };
    let base = (rc & 0x3F) as u16; // lower 6 bits for FMT1, also useful subset for FMT0 mapping

    // Vendor or warning codes (bit 10 for warnings in spec, we just surface)
    let is_warning = (rc & 0x900) == 0x900; // simplistic detection (bit 11 clear? / combine) – best-effort

    // Known Format 1 base codes (partial set) mapping
    let fmt1_name = match base {
        0x01 => "ASYMMETRIC",
        0x02 => "ATTRIBUTES",
        0x03 => "HASH",
        0x04 => "VALUE",
        0x05 => "HIERARCHY",
        0x07 => "KEY_SIZE",
        0x08 => "MGF",
        0x09 => "MODE",
        0x0A => "TYPE",
        0x0B => "HANDLE",
        0x0C => "KDF",
        0x0D => "RANGE",
        0x0E => "AUTH_FAIL",
        0x0F => "NONCE",
        0x10 => "PP",
        0x12 => "SCHEME",
        0x15 => "SIZE",
        0x16 => "SYMMETRIC",
        0x17 => "CURVE",
        0x18 => "KEY",
        _ => "UNKNOWN_FMT1_BASE",
    };

    // Selected Format 0 codes (subset focusing on NV + common)
    let fmt0_name = match rc & 0x7F {
        // mask to low 7 bits when format0
        0x01 => "INITIALIZE",
        0x03 => "SEQUENCE",
        0x09 => "HMAC",
        0x0B => "DISABLED",
        0x12 => "COMMAND_SIZE",
        0x14 => "COMMAND_CODE",
        0x15 => "AUTH_SIZE",
        0x16 => "AUTH_CONTEXT",
        0x20 => "NV_RANGE",
        0x22 => "NV_SIZE",
        0x24 => "NV_LOCKED",
        0x25 => "NV_AUTHORIZATION",
        0x26 => "NV_UNINITIALIZED",
        0x28 => "NV_SPACE",
        0x2C => "NV_DEFINED",
        _ => "UNKNOWN_FMT0_BASE",
    };

    if is_format1 {
        let target = if is_parameter {
            "PARAM"
        } else if is_handle {
            "HANDLE"
        } else if is_session {
            "SESSION"
        } else {
            "BASE"
        };
        return format!(
            "FMT1 base={fmt1_name}({base:#04x}) target={target} index={index} warning={is_warning}"
        );
    }
    // Format 0
    format!("FMT0 base={fmt0_name}({:#04x})", rc & 0x7F)
}

pub(crate) fn tpm_rc_from_io_error(e: &io::Error) -> Option<u32> {
    if let Some(inner) = e.get_ref() {
        if let Some(te) = inner.downcast_ref::<TpmError>() {
            return Some(te.rc);
        }
    }
    None
}

// Removed unused interpret_auth_string / hex_decode_lossy utilities.

pub fn hex_fmt(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TpmCommandCode, TPM_RS_PW, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS};

    // -----------------------------------------------------------------------
    // hex_fmt tests
    // -----------------------------------------------------------------------

    #[test]
    fn hex_fmt_empty() {
        assert_eq!(hex_fmt(&[]), "");
    }

    #[test]
    fn hex_fmt_single_byte() {
        assert_eq!(hex_fmt(&[0xff]), "ff");
        assert_eq!(hex_fmt(&[0x00]), "00");
        assert_eq!(hex_fmt(&[0x0a]), "0a");
    }

    #[test]
    fn hex_fmt_multiple_bytes() {
        assert_eq!(hex_fmt(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_fmt(&[0x01, 0x23, 0x45, 0x67]), "01234567");
    }

    // -----------------------------------------------------------------------
    // build_header_no_sessions tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_header_no_sessions_layout() {
        let mut buf = Vec::new();
        build_header_no_sessions(TpmCommandCode::PcrRead, &mut buf);
        assert_eq!(buf.len(), 10);
        // Tag = TPM_ST_NO_SESSIONS (0x8001)
        assert_eq!(&buf[0..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
        // Size placeholder = 0
        assert_eq!(&buf[2..6], &[0u8; 4]);
        // Command code = PcrRead (0x0000017E)
        assert_eq!(&buf[6..10], &(TpmCommandCode::PcrRead as u32).to_be_bytes());
    }

    // -----------------------------------------------------------------------
    // build_header_sessions tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_header_sessions_layout() {
        let mut buf = Vec::new();
        build_header_sessions(TpmCommandCode::Quote, &mut buf);
        assert_eq!(buf.len(), 10);
        // Tag = TPM_ST_SESSIONS (0x8002)
        assert_eq!(&buf[0..2], &TPM_ST_SESSIONS.to_be_bytes());
        // Command code = Quote (0x00000158)
        assert_eq!(&buf[6..10], &(TpmCommandCode::Quote as u32).to_be_bytes());
    }

    // -----------------------------------------------------------------------
    // finalize_size tests
    // -----------------------------------------------------------------------

    #[test]
    fn finalize_size_writes_length() {
        let mut buf = vec![0u8; 20];
        finalize_size(&mut buf);
        let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(len, 20);
    }

    #[test]
    fn finalize_size_minimum() {
        let mut buf = vec![0u8; 10];
        finalize_size(&mut buf);
        let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        assert_eq!(len, 10);
    }

    // -----------------------------------------------------------------------
    // build_command_no_sessions tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_command_no_sessions_no_handles_no_params() {
        let cmd = build_command_no_sessions(TpmCommandCode::FlushContext, &[], |_| {});
        assert_eq!(cmd.len(), 10);
        // Tag
        assert_eq!(&cmd[0..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
        // Size matches actual length
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        assert_eq!(size as usize, cmd.len());
        // Command code
        assert_eq!(
            &cmd[6..10],
            &(TpmCommandCode::FlushContext as u32).to_be_bytes()
        );
    }

    #[test]
    fn build_command_no_sessions_with_handles() {
        let handle: u32 = 0x80000001;
        let cmd = build_command_no_sessions(TpmCommandCode::ReadPublic, &[handle], |_| {});
        // 10 (header) + 4 (handle) = 14
        assert_eq!(cmd.len(), 14);
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        assert_eq!(size, 14);
        // Handle at offset 10
        assert_eq!(
            u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]),
            handle
        );
    }

    #[test]
    fn build_command_no_sessions_with_params() {
        let cmd = build_command_no_sessions(TpmCommandCode::PcrRead, &[], |buf| {
            buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        });
        // 10 (header) + 3 (params) = 13
        assert_eq!(cmd.len(), 13);
        assert_eq!(&cmd[10..13], &[0xAA, 0xBB, 0xCC]);
    }

    // -----------------------------------------------------------------------
    // build_command_pw_sessions tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_command_pw_sessions_empty_auth() {
        let handle: u32 = 0x80000000;
        let cmd = build_command_pw_sessions(TpmCommandCode::Quote, &[handle], &[&[]], |_| {});
        // 10 (header) + 4 (handle) + 4 (auth area size) + 9 (pw session: 4+2+1+2+0) = 27
        assert_eq!(cmd.len(), 27);
        assert_eq!(&cmd[0..2], &TPM_ST_SESSIONS.to_be_bytes());
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        assert_eq!(size as usize, cmd.len());
        // Handle
        assert_eq!(
            u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]),
            handle
        );
        // Auth area size = 9
        let auth_area_size = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
        assert_eq!(auth_area_size, 9);
        // Session handle = TPM_RS_PW
        assert_eq!(
            u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]),
            TPM_RS_PW
        );
    }

    #[test]
    fn build_command_pw_sessions_with_auth_value() {
        let auth = [0x01, 0x02, 0x03, 0x04];
        let cmd =
            build_command_pw_sessions(TpmCommandCode::Unseal, &[0x80000001], &[&auth], |_| {});
        // 10 + 4 + 4 + (4+2+1+2+4) = 31
        assert_eq!(cmd.len(), 31);
        // Auth area size = 4+2+1+2+4 = 13
        let auth_area_size = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
        assert_eq!(auth_area_size, 13);
    }

    #[test]
    fn build_command_pw_sessions_multiple_sessions() {
        let auth1 = [0xAA];
        let auth2 = [0xBB, 0xCC];
        let cmd = build_command_pw_sessions(
            TpmCommandCode::Certify,
            &[0x80000000, 0x80000001],
            &[&auth1, &auth2],
            |_| {},
        );
        // 10 + 8 (2 handles) + 4 (auth area size) + 10 (session1: 4+2+1+2+1) + 11 (session2: 4+2+1+2+2) = 43
        assert_eq!(cmd.len(), 43);
        let auth_area_size = u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]);
        assert_eq!(auth_area_size, 10 + 11);
    }

    // -----------------------------------------------------------------------
    // build_command_custom_sessions tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_command_custom_sessions_single() {
        let session = SessionEntry {
            handle: 0x02000000,
            auth: &[],
            attrs: 0x01,
        };
        let cmd = build_command_custom_sessions(
            TpmCommandCode::Unseal,
            &[0x80000001],
            &[session],
            |_| {},
        );
        // 10 + 4 (handle) + 4 (auth area size) + 9 (session: 4+2+1+2+0) = 27
        assert_eq!(cmd.len(), 27);
        // Session attributes byte
        assert_eq!(cmd[24], 0x01);
    }

    #[test]
    fn build_command_custom_sessions_with_auth() {
        let session = SessionEntry {
            handle: 0x02000000,
            auth: &[0xDE, 0xAD],
            attrs: 0x21,
        };
        let cmd = build_command_custom_sessions(
            TpmCommandCode::Unseal,
            &[0x80000001],
            &[session],
            |_| {},
        );
        // 10 + 4 + 4 + (4+2+1+2+2) = 29
        assert_eq!(cmd.len(), 29);
        // Auth size = 2
        let auth_size = u16::from_be_bytes([cmd[25], cmd[26]]);
        assert_eq!(auth_size, 2);
        assert_eq!(&cmd[27..29], &[0xDE, 0xAD]);
    }

    // -----------------------------------------------------------------------
    // parse_tpm_rc_with_cmd tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tpm_rc_success() {
        // Build a valid 10-byte response with rc=0
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes()); // size
        resp.extend_from_slice(&0u32.to_be_bytes()); // rc = 0
        assert!(parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).is_ok());
    }

    #[test]
    fn parse_tpm_rc_too_short() {
        let resp = vec![0u8; 5];
        let err = parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn parse_tpm_rc_length_mismatch() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&20u32.to_be_bytes()); // declared=20
        resp.extend_from_slice(&0u32.to_be_bytes());
        // actual length is 10, declared is 20
        let err = parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("length mismatch"));
    }

    #[test]
    fn parse_tpm_rc_nonzero_rc() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&0x00000101u32.to_be_bytes()); // some error code
        let err = parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).unwrap_err();
        // Should contain the decoded error
        let inner = err.get_ref().unwrap();
        let tpm_err = inner.downcast_ref::<TpmError>().unwrap();
        assert_eq!(tpm_err.rc, 0x00000101);
        assert_eq!(tpm_err.command, Some(TpmCommandCode::PcrRead));
    }

    // -----------------------------------------------------------------------
    // tpm_rc_from_io_error tests
    // -----------------------------------------------------------------------

    #[test]
    fn tpm_rc_from_io_error_with_tpm_error() {
        let tpm_err = TpmError {
            rc: 0x00000922,
            decoded: "test".into(),
            command: Some(TpmCommandCode::Quote),
        };
        let io_err = io::Error::other(tpm_err);
        assert_eq!(tpm_rc_from_io_error(&io_err), Some(0x00000922));
    }

    #[test]
    fn tpm_rc_from_io_error_without_tpm_error() {
        let io_err = io::Error::other("plain error");
        assert_eq!(tpm_rc_from_io_error(&io_err), None);
    }

    // -----------------------------------------------------------------------
    // TpmError Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn tpm_error_display_with_command() {
        let err = TpmError {
            rc: 0x0000_0922,
            decoded: "test description".into(),
            command: Some(TpmCommandCode::Quote),
        };
        let s = format!("{err}");
        assert!(s.contains("0x00000922"));
        assert!(s.contains("Quote"));
        assert!(s.contains("test description"));
    }

    #[test]
    fn tpm_error_display_without_command() {
        let err = TpmError {
            rc: 0x0000_0101,
            decoded: "INITIALIZE".into(),
            command: None,
        };
        let s = format!("{err}");
        assert!(s.contains("0x00000101"));
        assert!(s.contains("INITIALIZE"));
        assert!(!s.contains("command="));
    }

    // -----------------------------------------------------------------------
    // decode_tpm_rc tests (tested indirectly via parse_tpm_rc_with_cmd)
    // -----------------------------------------------------------------------

    #[test]
    fn decode_tpm_rc_format0_initialize() {
        // RC 0x00000101 should map to FMT0 INITIALIZE
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&0x00000101u32.to_be_bytes());
        let err = parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).unwrap_err();
        let inner = err.get_ref().unwrap();
        let tpm_err = inner.downcast_ref::<TpmError>().unwrap();
        assert!(tpm_err.decoded.contains("INITIALIZE"));
    }

    #[test]
    fn decode_tpm_rc_format1_value_parameter() {
        // FMT1 base=VALUE(0x04), PARAM target: bit 7 set, no handle bit (8) or session bit (11)
        let rc: u32 = 0x84; // format1, base=VALUE, no handle/session bits => PARAM
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&rc.to_be_bytes());
        let err = parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).unwrap_err();
        let inner = err.get_ref().unwrap();
        let tpm_err = inner.downcast_ref::<TpmError>().unwrap();
        assert!(tpm_err.decoded.contains("FMT1"));
        assert!(tpm_err.decoded.contains("VALUE"));
        assert!(tpm_err.decoded.contains("PARAM"));
    }

    #[test]
    fn decode_tpm_rc_format1_handle() {
        // FMT1 with handle bit (bit 8) set
        let rc: u32 = 0x18B; // format1, handle, base=HANDLE(0x0B)
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&rc.to_be_bytes());
        let err = parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).unwrap_err();
        let inner = err.get_ref().unwrap();
        let tpm_err = inner.downcast_ref::<TpmError>().unwrap();
        assert!(tpm_err.decoded.contains("FMT1"));
        assert!(tpm_err.decoded.contains("HANDLE"));
    }

    #[test]
    fn decode_tpm_rc_success() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        resp.extend_from_slice(&10u32.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_tpm_rc_with_cmd(&resp, TpmCommandCode::PcrRead).is_ok());
    }
}
