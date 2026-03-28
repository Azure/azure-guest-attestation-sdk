// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Internal implementation — documentation deferred.
#![allow(missing_docs)]

//! The module helps preparing requests and parsing responses that are
//! sent to and received from the IGVm agent runs on the host via GET
//! `CVM` host request.

use crate::tee_report; // Provides vbs/snp/tdx report size constants
use core::mem::size_of;
use serde::Deserialize;
use serde::Serialize;
use std::io;

const ATTESTATION_VERSION: u32 = 2;
const ATTESTATION_SIGNATURE: u32 = 0x414c4348; // 'HCLA'
/// The value is based on the maximum report size of the supported isolated VM
/// Currently it's the size of a SNP report.
const ATTESTATION_REPORT_SIZE_MAX: usize = SNP_VM_REPORT_SIZE;

pub const VBS_VM_REPORT_SIZE: usize = tee_report::vbs::VBS_REPORT_SIZE;
pub const SNP_VM_REPORT_SIZE: usize = tee_report::snp::SNP_REPORT_SIZE;
pub const TDX_VM_REPORT_SIZE: usize = tee_report::tdx::TDX_REPORT_SIZE;
/// No TEE attestation report for TVM
pub const TVM_REPORT_SIZE: usize = 0;

/// Request structure (C-style)
/// The struct (includes the appended `RuntimeClaims`) also serves as the
/// attestation report in vTPM guest attestation.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CvmAttestationReport {
    /// Report Header (unmeasured)
    pub report_header: CvmAttestationReportHeader,
    /// TEE attestation report
    pub tee_report: [u8; ATTESTATION_REPORT_SIZE_MAX],
    /// Runtime Claims header (unmeasured)
    pub runtime_claims_header: RuntimeClaimsHeader,
    // Variable-length [`runtime_claims::RuntimeClaims`] (JSON string) in raw bytes will be
    // appended to here.
    // The hash of [`runtime_claims::RuntimeClaims`] in [`CvmHashType`] will be captured
    // in the `report_data` or equivalent field of the TEE attestation report.
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CvmReportType {
    Invalid = 0,
    VbsVmReport = 1,
    SnpVmReport = 2,
    TvmReport = 3,
    TdxVmReport = 4,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CvmRequestType {
    Invalid = 0,
    KeyReleaseRequest = 1,
    AkCertRequest = 2,
    WrappedKeyRequest = 3,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReportDataHashType {
    Invalid = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
}

/// Unmeasured data used to provide transport sanity and versioning
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CvmAttestationReportHeader {
    /// Signature
    pub signature: u32,
    /// Version
    pub version: u32,
    /// Report size
    pub report_size: u32,
    /// Request type
    pub request_type: CvmRequestType,
    /// Status
    pub status: u32,
    /// Reserved
    pub reserved: [u32; 3],
}

impl CvmAttestationReportHeader {
    /// Create an `CvmAttestationReportHeader` instance.
    pub fn new(report_size: u32, request_type: CvmRequestType, status: u32) -> Self {
        Self {
            signature: ATTESTATION_SIGNATURE,
            version: ATTESTATION_VERSION,
            report_size,
            request_type,
            status,
            reserved: [0u32; 3],
        }
    }
}

const CVM_VERSION_CURRENT: u32 = 2;

/// Unmeasured user data, used for host attestation requests (C-style struct)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RuntimeClaimsHeader {
    /// Data size
    pub data_size: u32,
    /// Version
    pub version: u32,
    /// Report type
    pub report_type: CvmReportType,
    /// Report data hash type
    pub report_data_hash_type: ReportDataHashType,
    /// Size of the appended raw runtime claims
    pub variable_data_size: u32,
}

impl RuntimeClaimsHeader {
    pub fn new(
        data_size: u32,
        report_type: CvmReportType,
        report_data_hash_type: ReportDataHashType,
        variable_data_size: u32,
    ) -> Self {
        Self {
            data_size,
            version: CVM_VERSION_CURRENT,
            report_type,
            report_data_hash_type,
            variable_data_size,
        }
    }
}

/// Definition of the runt-time claims, which will be appended to the
/// `CvmRequest` in raw bytes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuntimeClaims {
    pub keys: Vec<RsaJwk>,
    pub vm_configuration: AttestationVmConfig,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_data: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RsaJwk {
    pub kid: String,
    pub key_ops: Vec<String>,
    pub kty: String,
    /// Base64url-encoded RSA public exponent
    pub e: String,
    /// Base64url-encoded RSA modulus
    pub n: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AttestationVmConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_time: Option<i64>,
    pub root_cert_thumbprint: String,
    pub console_enabled: bool,
    pub secure_boot: bool,
    pub tpm_enabled: bool,
    pub tpm_persisted: bool,
    pub filtered_vpci_devices_allowed: bool,
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: String,
}

// Helper to parse appended RuntimeClaims JSON after the fixed-size report header+body.
impl CvmAttestationReport {
    pub fn parse_with_runtime_claims(full: &[u8]) -> io::Result<(Self, Option<RuntimeClaims>)> {
        if full.len() < size_of::<CvmAttestationReport>() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer shorter than report",
            ));
        }
        // Safety: CvmAttestationReport is repr(C) with no padding invariants
        // beyond alignment, and we have verified the buffer is large enough.
        // read_unaligned handles any alignment.
        let report: CvmAttestationReport =
            unsafe { core::ptr::read_unaligned(full.as_ptr() as *const CvmAttestationReport) };
        let start = size_of::<CvmAttestationReport>();
        let end = start
            .checked_add(report.runtime_claims_header.variable_data_size as usize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "variable_data_size overflow")
            })?;
        if full.len() < end {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer shorter than report",
            ));
        }
        let tail = &full[start..end];
        if tail.is_empty() {
            return Ok((report, None));
        }
        let claims = serde_json::from_slice::<RuntimeClaims>(tail).ok();
        Ok((report, claims))
    }

    pub fn get_runtime_claims_raw_bytes(&self, full: &[u8]) -> io::Result<Vec<u8>> {
        if full.len() < size_of::<CvmAttestationReport>() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer shorter than report",
            ));
        }
        let start = size_of::<CvmAttestationReport>();
        let end = start + self.runtime_claims_header.variable_data_size as usize;
        if full.len() < end {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer shorter than report",
            ));
        }
        let tail = &full[start..end];

        Ok(tail.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_report_with_claims_tail() {
        // Build a zeroed report buffer
        let fixed = vec![0u8; size_of::<CvmAttestationReport>() - size_of::<u32>()];
        // Minimal JSON runtime claims tail with a JWK key (e/n as base64url strings)
        let json = br#"{"keys":[{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"AQAB","n":"0vx7agoebGcQ"}],"vm-configuration":{"root-cert-thumbprint":"","console-enabled":false,"secure-boot":false,"tpm-enabled":false,"tpm-persisted":false,"filtered-vpci-devices-allowed":false,"vmUniqueId":""},"user-data":""}"#;
        let mut buf = fixed.clone();
        buf.extend_from_slice(&(json.len() as u32).to_le_bytes());
        buf.extend_from_slice(json);
        let (rep, claims) = CvmAttestationReport::parse_with_runtime_claims(&buf).expect("parse");
        assert_eq!(rep.tee_report.len(), super::ATTESTATION_REPORT_SIZE_MAX);
        let claims = claims.expect("claims should be Some");
        assert_eq!(claims.keys.len(), 1);
        assert_eq!(claims.keys[0].kid, "HCLAkPub");
        assert_eq!(claims.keys[0].e, "AQAB");
        assert_eq!(claims.keys[0].n, "0vx7agoebGcQ");
    }

    #[test]
    fn parse_report_too_short() {
        let buf = vec![0u8; 10]; // much shorter than CvmAttestationReport
        let err = CvmAttestationReport::parse_with_runtime_claims(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parse_report_no_runtime_claims() {
        // Exact size of the fixed-size report, variable_data_size = 0
        let buf = vec![0u8; size_of::<CvmAttestationReport>()];
        let (rep, claims) = CvmAttestationReport::parse_with_runtime_claims(&buf).expect("parse");
        // variable_data_size is 0 → tail is empty → no claims
        assert!(claims.is_none());
        assert_eq!(
            rep.runtime_claims_header.variable_data_size, 0,
            "zeroed buffer should have variable_data_size = 0"
        );
    }

    #[test]
    fn parse_report_truncated_variable_data() {
        // Build a report where variable_data_size claims 100 bytes but we provide fewer
        let mut buf = vec![0u8; size_of::<CvmAttestationReport>()];
        // Set variable_data_size to 100
        let vds_offset = size_of::<CvmAttestationReport>() - size_of::<u32>();
        buf[vds_offset..vds_offset + 4].copy_from_slice(&100u32.to_le_bytes());
        // Only provide 10 extra bytes instead of 100
        buf.extend_from_slice(&[0u8; 10]);
        let err = CvmAttestationReport::parse_with_runtime_claims(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn get_runtime_claims_raw_bytes_empty() {
        let buf = vec![0u8; size_of::<CvmAttestationReport>()];
        let (rep, _) = CvmAttestationReport::parse_with_runtime_claims(&buf).expect("parse");
        let raw = rep.get_runtime_claims_raw_bytes(&buf).expect("get raw");
        assert!(raw.is_empty());
    }

    #[test]
    fn get_runtime_claims_raw_bytes_roundtrip() {
        let fixed = vec![0u8; size_of::<CvmAttestationReport>() - size_of::<u32>()];
        let json = br#"{"keys":[],"vm-configuration":{"root-cert-thumbprint":"","console-enabled":false,"secure-boot":false,"tpm-enabled":false,"tpm-persisted":false,"filtered-vpci-devices-allowed":false,"vmUniqueId":""},"user-data":""}"#;
        let mut buf = fixed;
        buf.extend_from_slice(&(json.len() as u32).to_le_bytes());
        buf.extend_from_slice(json);
        let (rep, _) = CvmAttestationReport::parse_with_runtime_claims(&buf).expect("parse");
        let raw = rep.get_runtime_claims_raw_bytes(&buf).expect("get raw");
        assert_eq!(raw, json);
    }

    #[test]
    fn report_header_new_sets_signature_and_version() {
        let hdr = CvmAttestationReportHeader::new(1024, CvmRequestType::AkCertRequest, 0);
        assert_eq!(hdr.signature, ATTESTATION_SIGNATURE);
        assert_eq!(hdr.version, ATTESTATION_VERSION);
        assert_eq!(hdr.report_size, 1024);
        assert_eq!(hdr.request_type, CvmRequestType::AkCertRequest);
        assert_eq!(hdr.status, 0);
        assert_eq!(hdr.reserved, [0u32; 3]);
    }

    #[test]
    fn runtime_claims_header_new() {
        let hdr = RuntimeClaimsHeader::new(
            100,
            CvmReportType::SnpVmReport,
            ReportDataHashType::Sha256,
            42,
        );
        assert_eq!(hdr.data_size, 100);
        assert_eq!(hdr.version, CVM_VERSION_CURRENT);
        assert_eq!(hdr.report_type, CvmReportType::SnpVmReport);
        assert_eq!(hdr.report_data_hash_type, ReportDataHashType::Sha256);
        assert_eq!(hdr.variable_data_size, 42);
    }
}
