// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// AMD SEV-SNP attestation report structures.
pub mod snp;
pub mod td_quote;
/// Intel TDX attestation report structures.
pub mod tdx;
pub mod vbs;

pub use td_quote::{
    parse_td_quote, parse_td_quote_with_options, pretty_td_quote as pretty_td_quote_v5,
    ParsedTdQuote, TdQuoteBody, TdQuoteParseError, TdQuoteSignatureMode,
};

use std::fmt::Write as _;

/// Render a byte slice as grouped hex (no 0x prefix), 32 bytes per line indented.
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

/// Pretty print an SNP report.
pub fn pretty_snp(report: &snp::SnpReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "SNP Report:");
    let _ = writeln!(out, "  version: {}", report.version);
    let _ = writeln!(out, "  guest_svn: {}", report.guest_svn);
    let _ = writeln!(out, "  policy: 0x{:016x}", report.policy);
    let _ = writeln!(out, "  vmpl: {}", report.vmpl);
    let _ = writeln!(out, "  signature_algo: {}", report.signature_algo);
    let _ = writeln!(out, "  current_tcb: 0x{:016x}", report.current_tcb);
    let _ = writeln!(out, "  platform_info: 0x{:016x}", report.platform_info);
    let _ = writeln!(out, "  flags: 0x{:08x}", report.flags);
    fmt_hex_block(&mut out, "  family", &report.family.to_le_bytes());
    fmt_hex_block(&mut out, "  image_id", &report.image_id.to_le_bytes());
    fmt_hex_block(&mut out, "  report_data", &report.report_data);
    fmt_hex_block(&mut out, "  measurement", &report.measurement);
    fmt_hex_block(&mut out, "  host_data", &report.host_data);
    fmt_hex_block(&mut out, "  id_key_digest", &report.id_key_digest);
    fmt_hex_block(&mut out, "  author_key_digest", &report.author_key_digest);
    fmt_hex_block(&mut out, "  report_id", &report.report_id);
    fmt_hex_block(&mut out, "  report_id_ma", &report.report_id_ma);
    let _ = writeln!(out, "  reported_tcb: 0x{:016x}", report.reported_tcb);
    fmt_hex_block(&mut out, "  chip_id", &report.chip_id);
    let _ = writeln!(out, "  committed_tcb: 0x{:016x}", report.committed_tcb);
    let _ = writeln!(
        out,
        "  current version: {}.{}.{}",
        report.current_major, report.current_minor, report.current_build
    );
    let _ = writeln!(
        out,
        "  committed version: {}.{}.{}",
        report.committed_major, report.committed_minor, report.committed_build
    );
    let _ = writeln!(out, "  launch_tcb: 0x{:016x}", report.launch_tcb);
    fmt_hex_block(&mut out, "  signature", &report.signature);
    out
}

/// Pretty print a TDX report.
pub fn pretty_tdx(report: &tdx::TdReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "TDX Report:");
    let mac = &report.report_mac_struct;
    let _ = writeln!(
        out,
        "  report_type.tee_type: 0x{:02x}",
        mac.report_type.tee_type
    );
    let _ = writeln!(
        out,
        "  report_type.sub_type: 0x{:02x}",
        mac.report_type.sub_type
    );
    let _ = writeln!(out, "  report_type.version: {}", mac.report_type.version);
    fmt_hex_block(&mut out, "  tee_tcb_info_hash", &mac.tee_tcb_info_hash);
    fmt_hex_block(&mut out, "  tee_info_hash", &mac.tee_info_hash);
    fmt_hex_block(&mut out, "  report_data", &mac.report_data);
    fmt_hex_block(&mut out, "  mac", &mac.mac);
    let tcb = &report.tee_tcb_info;
    fmt_hex_block(&mut out, "  tee_tcb_info.valid", &tcb.valid);
    fmt_hex_block(&mut out, "  tee_tcb_info.mr_seam", &tcb.mr_seam);
    fmt_hex_block(&mut out, "  tee_tcb_info.attributes", &tcb.attributes);
    let tdinfo = &report.td_info.td_info_base;
    fmt_hex_block(&mut out, "  mr_td", &tdinfo.mr_td);
    fmt_hex_block(&mut out, "  mr_config_id", &tdinfo.mr_config_id);
    fmt_hex_block(&mut out, "  mr_owner", &tdinfo.mr_owner);
    fmt_hex_block(&mut out, "  mr_owner_config", &tdinfo.mr_owner_config);
    for (i, r) in tdinfo.rtmr.iter().enumerate() {
        fmt_hex_block(&mut out, &format!("  rtmr[{i}]"), r);
    }
    fmt_hex_block(&mut out, "  servd_hash", &tdinfo.servd_hash);
    out
}

/// Pretty print a VBS report.
pub fn pretty_vbs(report: &vbs::VbsReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "VBS Report:");
    let _ = writeln!(out, "  version: {}", report.version);
    fmt_hex_block(&mut out, "  report_data", &report.report_data);
    fmt_hex_block(&mut out, "  identity.owner_id", &report.identity.owner_id);
    fmt_hex_block(
        &mut out,
        "  identity.measurement",
        &report.identity.measurement,
    );
    fmt_hex_block(&mut out, "  identity.signer", &report.identity.signer);
    fmt_hex_block(&mut out, "  identity.host_data", &report.identity.host_data);
    let _ = writeln!(out, "  identity.guest_svn: {}", report.identity.guest_svn);
    fmt_hex_block(&mut out, "  signature", &report.signature);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{size_of, zeroed};

    // -----------------------------------------------------------------------
    // fmt_hex_block tests
    // -----------------------------------------------------------------------

    #[test]
    fn fmt_hex_block_empty() {
        let mut out = String::new();
        fmt_hex_block(&mut out, "label", &[]);
        assert!(out.contains("label (0 bytes):"));
    }

    #[test]
    fn fmt_hex_block_small() {
        let mut out = String::new();
        fmt_hex_block(&mut out, "data", &[0xAA, 0xBB]);
        assert!(out.contains("data (2 bytes):"));
        assert!(out.contains("aabb"));
    }

    #[test]
    fn fmt_hex_block_wraps_at_32_bytes() {
        let mut out = String::new();
        let data: Vec<u8> = (0..64).collect();
        fmt_hex_block(&mut out, "big", &data);
        // Should have multiple indented lines
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() >= 3); // header + at least 2 data lines
                                   // Each data line should be indented with 4 spaces
        for line in &lines[1..] {
            assert!(line.starts_with("    "));
        }
    }

    // -----------------------------------------------------------------------
    // pretty_snp tests
    // -----------------------------------------------------------------------

    #[test]
    fn pretty_snp_zeroed_report() {
        let report: snp::SnpReport = unsafe { zeroed() };
        let s = pretty_snp(&report);
        assert!(s.contains("SNP Report:"));
        assert!(s.contains("version: 0"));
        assert!(s.contains("guest_svn: 0"));
        assert!(s.contains("policy:"));
        assert!(s.contains("report_data"));
        assert!(s.contains("measurement"));
        assert!(s.contains("signature"));
    }

    #[test]
    fn pretty_snp_contains_all_fields() {
        let mut report: snp::SnpReport = unsafe { zeroed() };
        report.version = 2;
        report.guest_svn = 42;
        let s = pretty_snp(&report);
        assert!(s.contains("version: 2"));
        assert!(s.contains("guest_svn: 42"));
        assert!(s.contains("host_data"));
        assert!(s.contains("id_key_digest"));
        assert!(s.contains("author_key_digest"));
        assert!(s.contains("chip_id"));
        assert!(s.contains("launch_tcb"));
    }

    // -----------------------------------------------------------------------
    // pretty_tdx tests
    // -----------------------------------------------------------------------

    #[test]
    fn pretty_tdx_zeroed_report() {
        let report: tdx::TdReport = unsafe { zeroed() };
        let s = pretty_tdx(&report);
        assert!(s.contains("TDX Report:"));
        assert!(s.contains("report_type.tee_type:"));
        assert!(s.contains("report_data"));
        assert!(s.contains("mr_td"));
        assert!(s.contains("mr_config_id"));
        assert!(s.contains("mr_owner"));
        assert!(s.contains("rtmr[0]"));
        assert!(s.contains("rtmr[3]"));
    }

    #[test]
    fn pretty_tdx_contains_tcb_info() {
        let report: tdx::TdReport = unsafe { zeroed() };
        let s = pretty_tdx(&report);
        assert!(s.contains("tee_tcb_info_hash"));
        assert!(s.contains("tee_info_hash"));
        assert!(s.contains("mr_seam"));
        assert!(s.contains("servd_hash"));
    }

    // -----------------------------------------------------------------------
    // pretty_vbs tests
    // -----------------------------------------------------------------------

    #[test]
    fn pretty_vbs_zeroed_report() {
        let report: vbs::VbsReport = unsafe { zeroed() };
        let s = pretty_vbs(&report);
        assert!(s.contains("VBS Report:"));
        assert!(s.contains("version: 0"));
        assert!(s.contains("report_data"));
        assert!(s.contains("identity.owner_id"));
        assert!(s.contains("identity.measurement"));
        assert!(s.contains("identity.signer"));
        assert!(s.contains("identity.host_data"));
        assert!(s.contains("identity.guest_svn: 0"));
        assert!(s.contains("signature"));
    }

    // -----------------------------------------------------------------------
    // Struct size verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn snp_report_size() {
        assert_eq!(size_of::<snp::SnpReport>(), snp::SNP_REPORT_SIZE);
    }

    #[test]
    fn tdx_report_size() {
        assert_eq!(size_of::<tdx::TdReport>(), tdx::TDX_REPORT_SIZE);
    }

    #[test]
    fn vbs_report_size() {
        assert_eq!(size_of::<vbs::VbsReport>(), vbs::VBS_REPORT_SIZE);
    }
}
