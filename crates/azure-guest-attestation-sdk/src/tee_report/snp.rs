// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Size of the [`SnpReport`].
pub const SNP_REPORT_SIZE: usize = 0x4a0;

/// Size of `report_data` member in [`SnpReport`].
pub const SNP_REPORT_DATA_SIZE: usize = 64;

/// Report structure.
/// See `ATTESTATION_REPORT` in Table 22, "SEV Secure Nested Paging Firmware ABI specification", Revision 1.55.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SnpReport {
    /// Version number of this attestation report.
    /// Set to 2h for this specification.
    pub version: u32,
    /// The guest SVN.
    pub guest_svn: u32,
    /// The guest policy.
    pub policy: u64,
    /// The family ID provided at launch.
    pub family: u128,
    /// The image ID provided at launch.
    pub image_id: u128,
    /// The request VMPL for the attestation
    /// report.
    pub vmpl: u32,
    /// The signature algorithm used to sign
    /// this report.
    pub signature_algo: u32,
    /// CurrentTcb.
    pub current_tcb: u64,
    /// Information about the platform.
    pub platform_info: u64,
    /// Flags
    pub flags: u32,
    /// Reserved
    pub _reserved0: u32,
    /// Guest-provided data.
    pub report_data: [u8; SNP_REPORT_DATA_SIZE],
    /// The measurement calculated at
    /// launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at
    /// launch.
    pub host_data: [u8; 32],
    /// SHA-384 digest of the ID public key
    /// that signed the ID block provided in
    /// SNP_LAUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    /// SHA-384 digest of the Author public
    /// key that certified the ID key, if
    /// provided in SNP_LAUNCH_FINISH.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest’s migration
    /// agent
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive
    /// the VCEK that signed this report.
    pub reported_tcb: u64,
    /// Reserved
    pub _reserved1: [u8; 24],
    /// If MaskChipId is set to 0, Identifier
    /// unique to the chip as output by
    /// GET_ID. Otherwise, set to 0h.
    pub chip_id: [u8; 64],
    /// CommittedTcb.
    pub committed_tcb: u64,
    /// The build number of CurrentVersion.
    pub current_build: u8,
    /// The minor number of CurrentVersion.
    pub current_minor: u8,
    /// The major number of CurrentVersion.
    pub current_major: u8,
    /// Reserved
    pub _reserved2: u8,
    /// The build number of CommittedVersion.
    pub committed_build: u8,
    /// The minor version of CommittedVersion.
    pub committed_minor: u8,
    /// The major version of CommittedVersion.
    pub committed_major: u8,
    /// Reserved
    pub _reserved3: u8,
    /// The CurrentTcb at the time the guest
    /// was launched or imported.
    pub launch_tcb: u64,
    /// Reserved
    pub _reserved4: [u8; 168],
    /// Signature of bytes inclusive of this report.
    pub signature: [u8; 512],
}

// Size check (debug only)
const _: () = {
    assert!(SNP_REPORT_SIZE == core::mem::size_of::<SnpReport>());
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn snp_report_size_matches_spec() {
        assert_eq!(size_of::<SnpReport>(), SNP_REPORT_SIZE);
        assert_eq!(SNP_REPORT_SIZE, 0x4a0);
    }

    #[test]
    fn snp_report_data_size() {
        assert_eq!(SNP_REPORT_DATA_SIZE, 64);
    }

    #[test]
    fn snp_report_data_field_size() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.report_data.len(), SNP_REPORT_DATA_SIZE);
    }

    #[test]
    fn snp_report_measurement_size() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.measurement.len(), 48);
    }

    #[test]
    fn snp_report_host_data_size() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.host_data.len(), 32);
    }

    #[test]
    fn snp_report_chip_id_size() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.chip_id.len(), 64);
    }

    #[test]
    fn snp_report_signature_size() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.signature.len(), 512);
    }

    #[test]
    fn snp_report_digest_sizes() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.id_key_digest.len(), 48);
        assert_eq!(report.author_key_digest.len(), 48);
    }

    #[test]
    fn snp_report_alignment() {
        assert!(align_of::<SnpReport>() <= 16);
    }

    #[test]
    fn snp_report_zeroed_has_default_values() {
        let report: SnpReport = unsafe { core::mem::zeroed() };
        assert_eq!(report.version, 0);
        assert_eq!(report.guest_svn, 0);
        assert_eq!(report.policy, 0);
        assert_eq!(report.vmpl, 0);
    }
}
