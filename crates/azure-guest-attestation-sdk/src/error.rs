// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unified error type for the Azure Guest Attestation SDK.
//!
//! [`SdkError`] is the single error type returned by all public API methods
//! on [`AttestationClient`](crate::AttestationClient) and the [`parse`](crate::parse) module.
//! It provides structured variants so callers can programmatically
//! distinguish between TPM failures, network issues, parsing problems, etc.

use crate::tee_report::td_quote::TdQuoteParseError;
use crate::tpm::TpmError;
use std::fmt;
use std::io;

/// Unified error type for the Azure Guest Attestation SDK.
///
/// Every public API method returns `Result<T, SdkError>`.  Match on the
/// variant to determine the error category, or simply format it as a
/// human-readable string with [`Display`](std::fmt::Display).
///
/// # Example
///
/// ```no_run
/// use azure_guest_attestation_sdk::{AttestationClient, Provider, SdkError};
///
/// # fn main() -> Result<(), SdkError> {
/// let client = AttestationClient::new()?;
/// match client.attest_guest(Provider::maa("https://..."), None) {
///     Ok(result) => println!("Token: {}", result.token.unwrap_or_default()),
///     Err(SdkError::Tpm(e)) => eprintln!("TPM error: {e}"),
///     Err(SdkError::Network { status, body, .. }) => {
///         eprintln!("HTTP {}: {body}", status.unwrap_or(0));
///     }
///     Err(e) => eprintln!("Other error: {e}"),
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum SdkError {
    /// A TPM command returned a non-zero response code.
    ///
    /// The inner [`TpmError`] preserves the raw RC, a human-readable
    /// description, and (when known) the originating TPM command code.
    Tpm(TpmError),

    /// An I/O error occurred while communicating with the TPM device,
    /// reading the event log, or performing other file-system operations.
    Io(io::Error),

    /// An HTTP request to a remote service (MAA, IMDS) failed.
    ///
    /// If the HTTP request completed, `status` and `body` contain the
    /// response details.  If the request could not be sent at all (DNS
    /// failure, timeout, TLS error, …), only `message` is populated.
    Network {
        /// Human-readable description of what went wrong.
        message: String,
        /// HTTP status code, if one was received.
        status: Option<u16>,
        /// Response body, if one was received.
        body: String,
    },

    /// Failed to parse a TEE report, attestation token, CVM report, or
    /// other binary/JSON structure.
    Parse(String),

    /// A TDX quote could not be parsed.
    Quote(TdQuoteParseError),

    /// An encryption or decryption operation failed (AES-GCM, base64, etc.).
    Crypto(String),

    /// An error that does not fit any other category.
    Other(String),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tpm(e) => write!(f, "TPM error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Network {
                message,
                status,
                body,
            } => {
                write!(f, "network error: {message}")?;
                if let Some(code) = status {
                    write!(f, " (HTTP {code})")?;
                }
                if !body.is_empty() {
                    write!(f, ": {body}")?;
                }
                Ok(())
            }
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::Quote(e) => write!(f, "TD quote parse error: {e}"),
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tpm(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Quote(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// From conversions — allow `?` to work seamlessly inside the SDK
// ---------------------------------------------------------------------------

impl From<io::Error> for SdkError {
    fn from(err: io::Error) -> Self {
        // If the inner error is a TpmError, promote it to the Tpm variant
        // so callers can match on it directly.
        if err.get_ref().is_some_and(|inner| inner.is::<TpmError>()) {
            let inner = err.into_inner().expect("just checked");
            let tpm_err = inner.downcast::<TpmError>().expect("just checked");
            return Self::Tpm(*tpm_err);
        }
        Self::Io(err)
    }
}

impl From<TpmError> for SdkError {
    fn from(err: TpmError) -> Self {
        Self::Tpm(err)
    }
}

impl From<TdQuoteParseError> for SdkError {
    fn from(err: TdQuoteParseError) -> Self {
        Self::Quote(err)
    }
}

/// Convenience type alias used throughout the SDK public API.
pub type Result<T> = std::result::Result<T, SdkError>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "no device");
        let sdk_err: SdkError = io_err.into();
        assert!(matches!(sdk_err, SdkError::Io(_)));
        assert!(sdk_err.to_string().contains("no device"));
    }

    #[test]
    fn tpm_error_unwrapped_from_io() {
        let tpm_err = TpmError::Tpm {
            rc: 0x100,
            description: "auth fail".into(),
            command: None,
        };
        let io_err = io::Error::other(tpm_err);
        let sdk_err: SdkError = io_err.into();
        assert!(matches!(sdk_err, SdkError::Tpm(_)));
        if let SdkError::Tpm(e) = &sdk_err {
            assert_eq!(e.tpm_rc_code(), Some(0x100));
        }
    }

    #[test]
    fn display_network_error() {
        let err = SdkError::Network {
            message: "attestation failed".into(),
            status: Some(400),
            body: "bad request".into(),
        };
        let s = err.to_string();
        assert!(s.contains("400"));
        assert!(s.contains("bad request"));
    }

    #[test]
    fn display_parse_error() {
        let err = SdkError::Parse("invalid report".into());
        assert!(err.to_string().contains("invalid report"));
    }

    #[test]
    fn quote_error_converts() {
        let qe = TdQuoteParseError::Truncated("header");
        let sdk_err: SdkError = qe.into();
        assert!(matches!(sdk_err, SdkError::Quote(_)));
    }

    #[test]
    fn error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broke");
        let sdk_err: SdkError = io_err.into();
        assert!(std::error::Error::source(&sdk_err).is_some());
    }
}
