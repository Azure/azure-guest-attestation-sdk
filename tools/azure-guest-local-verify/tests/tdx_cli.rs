// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(any(target_os = "linux", target_os = "windows"))]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const VALID_CERT_TIME: &str = "1790294400";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/azure-guest-attestation-sdk/src/verify/testdata")
        .join(name)
        .canonicalize()
        .unwrap()
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"));
    command.args(["--json", "tdx"]);
    command.arg(fixture("servtd_tdx_v5_quote.bin"));
    command
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={:?}, stderr={:?}",
            output.stdout, output.stderr
        )
    })
}

#[test]
fn signature_only_exposes_signed_migration_fields_without_tcb_claims() {
    let output = command()
        .args(["--verification-time", VALID_CERT_TIME])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let value = json(&output);
    assert_eq!(value["passed"], true);
    assert_eq!(value["verification_scope"], "signature_and_chain");
    assert_eq!(value["verification_time"], 1790294400i64);
    assert_eq!(value["tcb_checked"], false);
    assert_eq!(value["complete_dcap_verification"], false);
    assert_eq!(value["crl_checked"], false);
    assert_eq!(value["qe_identity_checked"], false);
    assert!(value.get("tcb").is_none());
    let fields = &value["measurements"];
    for (key, bytes) in [
        ("tee_tcb_svn_2", 16),
        ("mr_service_td", 48),
        ("td_id", 32),
        ("devinfo", 48),
        ("init_server_td_hash", 48),
        ("init_server_td_attr", 8),
        ("init_cpu_svn", 16),
        ("init_tee_tcb_svn", 16),
        ("init_tee_fmspc", 12),
        ("curr_server_td_hash", 48),
        ("curr_server_td_attr", 8),
    ] {
        assert_eq!(fields[key].as_str().unwrap().len(), bytes * 2, "{key}");
    }
    assert!(fields["vmid"].is_u64());
    assert_eq!(fields["servtd_ext"], true);
    assert_eq!(fields["init_tee_fmspc"], "00000000f0060c0000000080");
    assert_eq!(fields["init_cpu_svn"], "0404191b04ff00060000000000000000");
    assert_eq!(
        fields["init_tee_fmspc_model"]["cpuid_leaf1_eax"],
        0x000c06f0
    );
}

#[test]
fn conflicting_incomplete_and_baseline_without_collateral_flags_rejected() {
    for args in [
        vec!["--tcb-info", "info"],
        vec!["--tcb-issuer-chain", "chain"],
        vec![
            "--endorsements",
            "bundle",
            "--tcb-info",
            "info",
            "--tcb-issuer-chain",
            "chain",
        ],
        vec!["--endorsements", "bundle", "--tcb-issuer-chain", "chain"],
        vec!["--tcb-baseline-date", "123"],
        vec!["--verification-time", "-1"],
        vec!["--verification-time", "not-a-time"],
        vec!["--endorsements", "bundle", "--tcb-baseline-date", "-1"],
    ] {
        let output = command().args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }
}

#[test]
fn expired_endorsements_rejected_at_explicit_and_default_times() {
    for historical in [false, true] {
        let mut cmd = command();
        cmd.arg("--endorsements")
            .arg(fixture("servtd_tdx_v5_endorsements.bin"));
        if historical {
            cmd.args([
                "--verification-time",
                VALID_CERT_TIME,
                "--tcb-baseline-date",
                "0",
            ]);
        }
        let output = cmd.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let value = json(&output);
        assert_eq!(value["passed"], false);
        assert_eq!(
            value["verification_scope"],
            "signature_and_chain_and_tcb_info"
        );
        assert_eq!(value["complete_dcap_verification"], false);
        assert_eq!(value["tcb_checked"], false);
        // Default time can eventually fail certificate validity before freshness.
        if historical {
            assert!(value["error"].as_str().unwrap().contains("expired"));
        }
    }
}

#[test]
fn separate_collateral_files_are_accepted_but_still_enforce_freshness() {
    use azure_guest_attestation_sdk::verify::TdxCollateral;
    let bundle = std::fs::read(fixture("servtd_tdx_v5_endorsements.bin")).unwrap();
    let collateral = TdxCollateral::from_flattened_endorsements(&bundle).unwrap();
    let dir = std::env::temp_dir().join(format!("tdx-cli-collateral-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    // Only temporary copies are written; the SDK fixtures remain read-only.
    let info = dir.join("tcb-info.json");
    let chain = dir.join("issuer.pem");
    std::fs::write(&info, collateral.tcb_info).unwrap();
    std::fs::write(&chain, collateral.tcb_issuer_chain).unwrap();
    let output = command()
        .arg("--tcb-info")
        .arg(&info)
        .arg("--tcb-issuer-chain")
        .arg(&chain)
        .args([
            "--verification-time",
            VALID_CERT_TIME,
            "--tcb-baseline-date",
            "0",
        ])
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value = json(&output);
    assert!(value["error"].as_str().unwrap().contains("expired"));
    assert_eq!(value["tcb_baseline_date"], 0);
}

#[test]
fn historical_time_does_not_bypass_certificate_validity() {
    let output = command()
        .args(["--verification-time", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(json(&output)["passed"], false);
}

#[test]
fn signature_only_without_time_still_uses_existing_path() {
    let output = command().output().unwrap();
    let value = json(&output);
    assert_eq!(value["verification_scope"], "signature_and_chain");
    assert_eq!(value["tcb_checked"], false);
    assert!(value["verification_time"].is_i64());
    assert!(value.get("tcb").is_none());
    assert_eq!(output.status.success(), value["passed"].as_bool().unwrap());
}

#[test]
fn human_output_includes_migration_fields_and_verification_limits() {
    let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
        .arg("tdx")
        .arg(fixture("servtd_tdx_v5_quote.bin"))
        .args(["--verification-time", VALID_CERT_TIME])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for field in [
        "tee_tcb_svn_2",
        "mr_service_td",
        "vmid",
        "td_id",
        "devinfo",
        "init_server_td_hash",
        "init_server_td_attr",
        "init_cpu_svn",
        "init_tee_tcb_svn",
        "init_tee_fmspc",
        "init_tee_fmspc_model",
        "curr_server_td_hash",
        "curr_server_td_attr",
        "servtd_ext",
    ] {
        assert!(text.contains(&format!("  {field}:")), "{field}");
    }
    assert!(text.contains("signature_and_chain"));
    assert!(text.contains("tcb_checked: false"));
    assert!(text.contains("complete_dcap_verification: false"));
    assert!(text.contains("CRL and QE identity: not checked"));
}

#[test]
fn malformed_collateral_never_falls_back_to_signature_only() {
    let output = command()
        .arg("--endorsements")
        .arg(fixture("servtd_tdx_v5_quote.bin"))
        .args(["--verification-time", VALID_CERT_TIME])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value = json(&output);
    assert_eq!(value["passed"], false);
    assert_eq!(value["tcb_checked"], false);
    assert_eq!(
        value["verification_scope"],
        "signature_and_chain_and_tcb_info"
    );
    assert_eq!(value["error_code"], "invalid_evidence");
}
