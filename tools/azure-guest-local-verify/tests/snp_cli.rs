// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(any(target_os = "linux", target_os = "windows"))]

use std::{path::PathBuf, process::Command};

const PLATFORMS: [&str; 3] = ["milan", "genoa", "turin"];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/azure-guest-attestation-sdk/src/verify/testdata")
        .join(name)
}

#[test]
fn snp_cli_reports_binding_and_unchecked_policy_scope() {
    for generation in PLATFORMS {
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
            .args(["--json", "snp"])
            .arg(fixture(&format!("snp_report_{generation}.bin")))
            .arg("--vcek")
            .arg(fixture(&format!("snp_vcek_chain_{generation}.pem")))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["passed"], true);
        assert_eq!(json["checks"]["VCEK report binding"], true);
        assert_eq!(
            json["verification_scope"],
            "structure_signature_chain_and_vcek_binding"
        );
        assert_eq!(json["policy_checked"], false);
        assert_eq!(json["crl_checked"], false);
        assert_eq!(json["cpuid_stepping_checked"], false);
    }
}

#[test]
fn snp_cli_read_errors_are_scoped_and_redacted() {
    let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
        .args(["--json", "snp"])
        .arg(fixture("missing-report-error-context-sentinel.bin"))
        .arg("--vcek")
        .arg(fixture(&format!("snp_vcek_chain_{}.pem", PLATFORMS[0])))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["passed"], false);
    assert_eq!(json["error_code"], "input_not_found");
    assert_eq!(
        json["verification_scope"],
        "structure_signature_chain_and_vcek_binding"
    );
    assert_eq!(json["policy_checked"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("error-context-sentinel"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("error-context-sentinel"));
}

#[test]
fn snp_cli_rejects_a_mismatched_chain() {
    for report in PLATFORMS {
        for chain in PLATFORMS {
            if report == chain {
                continue;
            }
            let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
                .args(["--json", "snp"])
                .arg(fixture(&format!("snp_report_{report}.bin")))
                .arg("--vcek")
                .arg(fixture(&format!("snp_vcek_chain_{chain}.pem")))
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{report} report with {chain} chain"
            );
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["passed"], false);
            assert_eq!(json["policy_checked"], false);
            assert!(json.get("checks").is_none());
        }
    }
}
