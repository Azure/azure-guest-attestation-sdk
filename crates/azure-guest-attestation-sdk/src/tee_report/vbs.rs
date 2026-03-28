// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VBS (Virtualization-Based Security) attestation report structures.

use bitfield_struct::bitfield;
use core::mem::size_of;

/// Size of the [`VbsReport`].
pub const VBS_REPORT_SIZE: usize = 0x230;

/// Header for a VBS report package.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VbsReportPackageHeader {
    /// Total size of the VBS report package, including this header.
    pub package_size: u32,
    /// Version of the VBS report package format.
    pub version: u32,
    /// Signature scheme used for the report.
    pub signature_scheme: u32,
    /// Size of the signature in bytes.
    pub signature_size: u32,
    /// Reserved for future use.
    pub _reserved: u32,
}

/// VBS VM identity structure.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VbsVmIdentity {
    /// Owner ID of the VM.
    pub owner_id: [u8; 32],
    /// Measurement of the VM.
    pub measurement: [u8; 32],
    /// Signer of the VM.
    pub signer: [u8; 32],
    /// Host-specific data.
    pub host_data: [u8; 32],
    /// Enabled Virtual Trust Levels bitmap.
    pub enabled_vtl: VtlBitMap,
    /// Security policy attributes.
    pub policy: SecurityAttributes,
    /// Guest Virtual Trust Level.
    pub guest_vtl: u32,
    /// Guest Security Version Number.
    pub guest_svn: u32,
    /// Guest Product ID.
    pub guest_product_id: u32,
    /// Guest Module ID.
    pub guest_module_id: u32,
    /// Reserved for future use.
    pub _reserved: [u8; 64],
}

/// VBS report structure.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VbsReport {
    /// Package header containing metadata about the report.
    pub header: VbsReportPackageHeader,
    /// Version of the VBS report.
    pub version: u32,
    /// Report data that is provided at the runtime.
    pub report_data: [u8; 64],
    /// Identity information of the VM.
    pub identity: VbsVmIdentity,
    /// Signature of the report.
    pub signature: [u8; 256],
}

const _: () = {
    assert!(VBS_REPORT_SIZE == size_of::<VbsReport>());
};

/// Virtual Trust Level bitmap.
#[bitfield(u32)]
pub struct VtlBitMap {
    pub vtl0: bool,
    pub vtl1: bool,
    pub vtl2: bool,
    #[bits(29)]
    _reserved: u32,
}

/// Security attributes for the VM.
#[bitfield(u32)]
pub struct SecurityAttributes {
    pub debug_allowed: bool,
    #[bits(31)]
    _reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn vbs_report_size_matches_spec() {
        assert_eq!(size_of::<VbsReport>(), VBS_REPORT_SIZE);
        assert_eq!(VBS_REPORT_SIZE, 0x230);
    }

    #[test]
    fn vbs_report_data_size() {
        let report: VbsReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.report_data.len(), 64);
    }

    #[test]
    fn vbs_report_signature_size() {
        let report: VbsReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.signature.len(), 256);
    }

    #[test]
    fn vbs_vm_identity_field_sizes() {
        let id: VbsVmIdentity = unsafe { core::mem::zeroed() };
        assert_eq!(id.owner_id.len(), 32);
        assert_eq!(id.measurement.len(), 32);
        assert_eq!(id.signer.len(), 32);
        assert_eq!(id.host_data.len(), 32);
    }

    #[test]
    fn vtl_bitmap_individual_flags() {
        let vtl = VtlBitMap::new().with_vtl0(true);
        assert!(vtl.vtl0());
        assert!(!vtl.vtl1());
        assert!(!vtl.vtl2());

        let vtl = VtlBitMap::new().with_vtl1(true);
        assert!(!vtl.vtl0());
        assert!(vtl.vtl1());

        let vtl = VtlBitMap::new().with_vtl2(true);
        assert!(vtl.vtl2());
    }

    #[test]
    fn vtl_bitmap_multiple_flags() {
        let vtl = VtlBitMap::new()
            .with_vtl0(true)
            .with_vtl1(true)
            .with_vtl2(true);
        assert!(vtl.vtl0());
        assert!(vtl.vtl1());
        assert!(vtl.vtl2());
    }

    #[test]
    fn vtl_bitmap_default_is_zero() {
        let vtl = VtlBitMap::new();
        assert_eq!(u32::from(vtl), 0);
    }

    #[test]
    fn security_attributes_debug_flag() {
        let attrs = SecurityAttributes::new().with_debug_allowed(true);
        assert!(attrs.debug_allowed());

        let attrs = SecurityAttributes::new().with_debug_allowed(false);
        assert!(!attrs.debug_allowed());
    }

    #[test]
    fn security_attributes_default_is_zero() {
        let attrs = SecurityAttributes::new();
        assert_eq!(u32::from(attrs), 0);
    }

    #[test]
    fn vbs_report_package_header_size() {
        assert_eq!(size_of::<VbsReportPackageHeader>(), 20);
    }

    #[test]
    fn vbs_report_alignment() {
        assert!(align_of::<VbsReport>() <= 4);
    }
}
