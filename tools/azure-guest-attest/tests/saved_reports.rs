// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use azure_guest_attestation_sdk::{parse, tee_report};
use base64::Engine;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "azure-guest-attest-saved-report-{}-{}.bin",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

fn cli(command: &str, input: &TempFile, options: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
        .args(["tee-report", "--type", command])
        .arg(&input.0)
        .args(options)
        .output()
        .unwrap()
}

fn reports() -> [(&'static str, Vec<u8>, String); 2] {
    let mut snp = vec![0; tee_report::snp::SNP_REPORT_SIZE];
    snp[..4].copy_from_slice(&2u32.to_le_bytes());
    snp[80..144].fill(0xab);
    let snp_pretty = parse::snp_report_pretty(&parse::snp_report(&snp).unwrap());

    let mut tdx = vec![0; tee_report::tdx::TDX_REPORT_SIZE];
    tdx[0] = 0x81;
    tdx[128..192].fill(0xcd);
    let tdx_pretty = parse::tdx_report_pretty(&parse::tdx_report(&tdx).unwrap());

    [("snp", snp, snp_pretty), ("tdx", tdx, tdx_pretty)]
}

#[test]
fn saved_reports_pretty_print_offline() {
    for (command, bytes, expected) in reports() {
        let input = TempFile::new(&bytes);
        for options in [&[][..], &["--pretty"][..]] {
            let output = cli(command, &input, options);
            assert!(output.status.success(), "{command}: {output:?}");
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{expected}\n")
            );
        }
    }
}

#[test]
fn saved_reports_output_modes_preserve_bytes() {
    for (command, bytes, _) in reports() {
        let input = TempFile::new(&bytes);
        for (option, expected) in [
            ("--raw", bytes.clone()),
            ("--hex", format!("{}\n", hex::encode(&bytes)).into_bytes()),
            (
                "--base64",
                format!(
                    "{}\n",
                    base64::engine::general_purpose::STANDARD.encode(&bytes)
                )
                .into_bytes(),
            ),
        ] {
            let output = cli(command, &input, &[option]);
            assert!(output.status.success(), "{command} {option}: {output:?}");
            assert_eq!(output.stdout, expected, "{command} {option}");
        }
    }
}

#[test]
fn saved_reports_support_output_file() {
    for (command, bytes, expected) in reports() {
        let input = TempFile::new(&bytes);
        let destination = TempFile::new(&[]);
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
            .args(["tee-report", "--type", command])
            .arg(&input.0)
            .arg("--out")
            .arg(&destination.0)
            .output()
            .unwrap();
        assert!(output.status.success(), "{command}: {output:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            std::fs::read_to_string(&destination.0).unwrap(),
            expected + "\n"
        );
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
            .arg("--out")
            .arg(&destination.0)
            .args(["tee-report", "--type", command])
            .arg(&input.0)
            .arg("--raw")
            .output()
            .unwrap();
        assert!(output.status.success(), "{command}: {output:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read(&destination.0).unwrap(), bytes);
    }
}

#[test]
fn saved_reports_reject_wrong_lengths() {
    for (command, bytes, _) in reports() {
        for size in [0, bytes.len() - 1, bytes.len() + 1] {
            let input = TempFile::new(&vec![0; size]);
            let output = cli(command, &input, &[]);
            assert!(!output.status.success(), "{command} accepted {size} bytes");
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("report"), "{error}");
            assert!(error.contains(&size.to_string()), "{error}");
            assert!(error.contains(&bytes.len().to_string()), "{error}");
        }
    }
}

#[test]
fn saved_reports_encoding_modes_do_not_require_parsing() {
    let bytes = b"not a report";
    let input = TempFile::new(bytes);
    for command in ["snp", "tdx"] {
        for (option, expected) in [
            ("--raw", bytes.to_vec()),
            ("--hex", format!("{}\n", hex::encode(bytes)).into_bytes()),
            (
                "--base64",
                format!(
                    "{}\n",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                )
                .into_bytes(),
            ),
        ] {
            let output = cli(command, &input, &[option]);
            assert!(output.status.success(), "{command} {option}: {output:?}");
            assert_eq!(output.stdout, expected);
        }
    }
}

#[test]
fn saved_reports_require_readable_path() {
    for command in ["snp", "tdx"] {
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
            .args(["tee-report", "--type", command])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains("<PATH>"));

        let input = TempFile::new(&[]);
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
            .args(["tee-report", "--type", command])
            .arg(input.0.join("missing.bin"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("reading"), "{error}");
        assert!(error.contains("missing.bin"), "{error}");
    }
}

#[test]
fn saved_reports_reject_conflicting_encodings() {
    let input = TempFile::new(&[]);
    for command in ["snp", "tdx"] {
        for options in [
            ["--raw", "--hex"],
            ["--raw", "--base64"],
            ["--hex", "--base64"],
        ] {
            let output = cli(command, &input, &options);
            assert!(!output.status.success(), "{command} accepted {options:?}");
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("cannot be used with"), "{error}");
        }
    }
}

#[test]
fn saved_reports_require_explicit_type() {
    let input = TempFile::new(&vec![0; tee_report::snp::SNP_REPORT_SIZE]);
    let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
        .arg("tee-report")
        .arg(&input.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("--type"), "{error}");
    assert!(error.contains("required"), "{error}");
}

#[test]
fn saved_reports_reject_user_data() {
    let input = TempFile::new(&vec![0; tee_report::snp::SNP_REPORT_SIZE]);
    let output = cli("snp", &input, &["--user-data", "utf8:hello"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("cannot be used with"), "{error}");
}

#[test]
fn saved_reports_reject_unsupported_type() {
    let input = TempFile::new(&[]);
    let output = cli("vbs", &input, &[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("invalid value"), "{error}");
}

#[test]
fn standalone_report_commands_are_not_exposed() {
    for command in ["snp-report", "tdx-report"] {
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-attest"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("unrecognized subcommand"), "{error}");
    }
}
