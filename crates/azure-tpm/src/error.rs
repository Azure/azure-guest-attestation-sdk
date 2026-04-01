// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Dedicated error types for TPM 2.0 operations.
//!
//! [`TpmError`] is the primary error type returned by all public-facing
//! TPM operations. It distinguishes between TPM response codes, wire-format
//! parsing failures, input validation issues, and I/O transport errors.

use crate::types::TpmCommandCode;
use std::fmt;
use std::io;

/// Unified error type for TPM 2.0 operations.
///
/// This enum covers the full range of failures that can occur when
/// communicating with a TPM device:
///
/// - [`TpmError::Tpm`] — the TPM returned a non-zero response code
/// - [`TpmError::Unmarshal`] — a response could not be parsed
/// - [`TpmError::Validation`] — input parameters failed validation
/// - [`TpmError::Io`] — underlying device I/O error
#[derive(Debug)]
pub enum TpmError {
    /// The TPM returned a non-zero response code.
    ///
    /// Contains the raw response code, a human-readable decoded description,
    /// and the command that triggered it (if known).
    Tpm {
        /// Raw TPM 2.0 response code (e.g. `0x0000_018B`).
        rc: u32,
        /// Human-readable classification of the response code.
        description: String,
        /// The TPM command that produced this error.
        command: Option<TpmCommandCode>,
    },

    /// Failed to parse a TPM response (truncated, malformed, etc.).
    Unmarshal {
        /// Description of what was being parsed when the error occurred.
        context: String,
    },

    /// Input validation failed before any TPM command was sent.
    Validation {
        /// Description of what validation check failed.
        message: String,
    },

    /// Underlying I/O error from the TPM device transport.
    Io(io::Error),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Tpm {
                rc,
                description,
                command,
            } => {
                if let Some(cmd) = command {
                    write!(
                        f,
                        "TPM error 0x{rc:08x} (command={cmd:?}/0x{:08x}): {description}",
                        *cmd as u32
                    )
                } else {
                    write!(f, "TPM error 0x{rc:08x}: {description}")
                }
            }
            TpmError::Unmarshal { context } => {
                write!(f, "TPM unmarshal error: {context}")
            }
            TpmError::Validation { message } => {
                write!(f, "TPM validation error: {message}")
            }
            TpmError::Io(err) => {
                write!(f, "TPM I/O error: {err}")
            }
        }
    }
}

impl std::error::Error for TpmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TpmError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for TpmError {
    fn from(err: io::Error) -> Self {
        TpmError::Io(err)
    }
}

/// Convert a [`TpmError`] into an [`io::Error`] for backward compatibility
/// with callers that expect `io::Result`.
impl From<TpmError> for io::Error {
    fn from(err: TpmError) -> Self {
        match err {
            TpmError::Io(io_err) => io_err,
            TpmError::Tpm { .. } => io::Error::other(err),
            TpmError::Unmarshal { .. } => {
                io::Error::new(io::ErrorKind::InvalidData, err.to_string())
            }
            TpmError::Validation { .. } => {
                io::Error::new(io::ErrorKind::InvalidInput, err.to_string())
            }
        }
    }
}

/// Convenience alias for results using [`TpmError`].
pub type TpmResult<T> = Result<T, TpmError>;

impl TpmError {
    /// Create a TPM response code error.
    pub(crate) fn tpm_rc(rc: u32, description: String, command: Option<TpmCommandCode>) -> Self {
        TpmError::Tpm {
            rc,
            description,
            command,
        }
    }

    /// Create an unmarshal error.
    #[allow(dead_code)] // will be used as call sites migrate from io::Error
    pub(crate) fn unmarshal(context: impl Into<String>) -> Self {
        TpmError::Unmarshal {
            context: context.into(),
        }
    }

    /// Create a validation error.
    #[allow(dead_code)] // will be used as call sites migrate from io::Error
    pub(crate) fn validation(message: impl Into<String>) -> Self {
        TpmError::Validation {
            message: message.into(),
        }
    }

    /// Extract the TPM response code if this is a `Tpm` variant.
    pub fn tpm_rc_code(&self) -> Option<u32> {
        match self {
            TpmError::Tpm { rc, .. } => Some(*rc),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_error_display_with_command() {
        let err = TpmError::tpm_rc(
            0x0000_018B,
            "FMT1 HANDLE".to_string(),
            Some(TpmCommandCode::NvReadPublic),
        );
        let s = err.to_string();
        assert!(s.contains("0x0000018b"));
        assert!(s.contains("NvReadPublic"));
        assert!(s.contains("FMT1 HANDLE"));
    }

    #[test]
    fn tpm_error_display_without_command() {
        let err = TpmError::tpm_rc(0x101, "INITIALIZE".to_string(), None);
        let s = err.to_string();
        assert!(s.contains("0x00000101"));
        assert!(s.contains("INITIALIZE"));
        assert!(!s.contains("command="));
    }

    #[test]
    fn unmarshal_error_display() {
        let err = TpmError::unmarshal("response truncated at offset 14");
        assert!(err.to_string().contains("response truncated"));
    }

    #[test]
    fn validation_error_display() {
        let err = TpmError::validation("PCR index 24 out of range (0-23)");
        assert!(err.to_string().contains("PCR index 24"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "no TPM device");
        let tpm_err = TpmError::from(io_err);
        assert!(matches!(tpm_err, TpmError::Io(_)));
        assert!(tpm_err.to_string().contains("no TPM device"));
    }

    #[test]
    fn tpm_error_to_io_error() {
        let err = TpmError::validation("test");
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn tpm_rc_code_extraction() {
        let err = TpmError::tpm_rc(0x922, "test".into(), None);
        assert_eq!(err.tpm_rc_code(), Some(0x922));

        let err2 = TpmError::validation("test");
        assert_eq!(err2.tpm_rc_code(), None);
    }
}
