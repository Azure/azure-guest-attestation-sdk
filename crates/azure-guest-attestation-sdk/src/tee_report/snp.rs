// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Size of the [`SnpReport`].
pub const SNP_REPORT_SIZE: usize = 0x4a0;

/// Size of `report_data` member in [`SnpReport`].
pub const SNP_REPORT_DATA_SIZE: usize = 64;

/// Report structure, preserving the 1,184-byte wire layout for versions 2 through 6.
/// See `ATTESTATION_REPORT` in AMD 56860 revision 1.59, Table 27.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SnpReport {
    /// Version number of this attestation report.
    /// Version-dependent fields are exposed through accessors below.
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
    /// The launch/import TCB (CommittedTcb in the v6 specification).
    pub launch_tcb: u64,
    /// Version-dependent fields and reserved bytes; use the accessors below.
    pub _reserved4: [u8; 168],
    /// Signature over bytes 0x000 through 0x29f inclusive.
    pub signature: [u8; 512],
}

/// Raw extended TCB claims from a version 6 SNP report.
///
/// Each 256-bit value is preserved in wire order. Component interpretation is
/// processor-specific; these bytes do not establish minimum TCB policy or
/// certificate binding. They are authenticated only after report verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnpExtendedTcb {
    /// CURRENT_ETCB at offset 0x220.
    pub current: [u8; 32],
    /// LAUNCH_ETCB at offset 0x240.
    pub launch: [u8; 32],
    /// COMMITTED_ETCB at offset 0x260.
    pub committed: [u8; 32],
}

impl SnpReport {
    /// Signed CPUID family, model, and stepping for report versions 3 through 6.
    /// `None` means this layout does not define those fields, not zero identity.
    /// This accessor does not validate the report or authenticate its contents.
    pub fn cpuid(&self) -> Option<[u8; 3]> {
        matches!(self.version, 3..=6)
            .then(|| [self._reserved1[0], self._reserved1[1], self._reserved1[2]])
    }

    /// Launch and current mitigation bit vectors for report versions 5 and 6.
    /// Older versions do not provide mitigation-vector claims. No required-bit
    /// policy is applied and unknown bits are preserved.
    pub fn mitigation_vectors(&self) -> Option<(u64, u64)> {
        matches!(self.version, 5 | 6).then(|| {
            (
                u64::from_le_bytes(self._reserved4[..8].try_into().unwrap()),
                u64::from_le_bytes(self._reserved4[8..16].try_into().unwrap()),
            )
        })
    }

    /// Extended TCB values for report version 6, or `None` for other versions.
    ///
    /// This accessor does not validate or authenticate the report. It preserves
    /// all ETCB bits without assuming a processor-specific component layout.
    pub fn extended_tcb(&self) -> Option<SnpExtendedTcb> {
        (self.version == 6).then(|| SnpExtendedTcb {
            current: self._reserved4[0x28..0x48].try_into().unwrap(),
            launch: self._reserved4[0x48..0x68].try_into().unwrap(),
            committed: self._reserved4[0x68..0x88].try_into().unwrap(),
        })
    }
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
    fn snp_versioned_fields_preserve_wire_layout() {
        assert_eq!(core::mem::offset_of!(SnpReport, _reserved1), 0x188);
        assert_eq!(core::mem::offset_of!(SnpReport, _reserved4), 0x1f8);
        assert_eq!(core::mem::offset_of!(SnpReport, signature), 0x2a0);
        let milan =
            crate::parse::snp_report(include_bytes!("../verify/testdata/snp_report_milan.bin"))
                .unwrap();
        let mut turin =
            crate::parse::snp_report(include_bytes!("../verify/testdata/snp_report_turin.bin"))
                .unwrap();
        assert_eq!(milan.cpuid(), Some([0x19, 1, 1]));
        assert_eq!(milan.mitigation_vectors(), None);
        assert_eq!(turin.cpuid(), Some([0x1a, 2, 1]));
        assert_eq!(turin.mitigation_vectors(), Some((0x3f, 0x3f)));
        turin.version = 2;
        assert_eq!(turin.cpuid(), None);
        assert_eq!(turin.mitigation_vectors(), None);
        turin.version = 7;
        assert_eq!(turin.cpuid(), None);
        assert_eq!(turin.mitigation_vectors(), None);
    }

    #[test]
    fn snp_v6_fields_preserve_wire_bytes_and_version_gating() {
        let mut bytes = [0; SNP_REPORT_SIZE];
        bytes[..4].copy_from_slice(&6u32.to_le_bytes());
        bytes[0x188..0x18b].copy_from_slice(&[0x1a, 2, 1]);
        bytes[0x1f8..0x200].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        bytes[0x200..0x208].copy_from_slice(&0x8877_6655_4433_2211u64.to_le_bytes());
        let current = std::array::from_fn(|i| i as u8);
        let launch = std::array::from_fn(|i| 0x40 + i as u8);
        let committed = std::array::from_fn(|i| 0x80 + i as u8);
        bytes[0x220..0x240].copy_from_slice(&current);
        bytes[0x240..0x260].copy_from_slice(&launch);
        bytes[0x260..0x280].copy_from_slice(&committed);
        bytes[0x29f] = 0xfe; // parsing is permissive, unlike verification
        bytes[0x2a0] = 0xa5;
        let report = crate::parse::snp_report(&bytes).unwrap();
        assert_eq!(report.cpuid(), Some([0x1a, 2, 1]));
        assert_eq!(
            report.mitigation_vectors(),
            Some((0x0102_0304_0506_0708, 0x8877_6655_4433_2211))
        );
        assert_eq!(
            report.extended_tcb().unwrap(),
            SnpExtendedTcb {
                current,
                launch,
                committed
            }
        );
        assert_eq!(report.signature[0], 0xa5);
        for version in [0, 1, 2, 3, 4, 5, 7, u32::MAX] {
            let mut other = report;
            other.version = version;
            assert_eq!(other.extended_tcb(), None);
        }
        assert!(crate::parse::snp_report(&bytes[..SNP_REPORT_SIZE - 1]).is_err());
    }

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
