// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `azure-guest-local-verify` — offline verification of Azure CVM attestation
//! evidence (Intel TDX quotes, AMD SEV-SNP reports) against pinned hardware
//! roots, without a round-trip to MAA.
//!
//! Verification uses the platform crypto backend: OpenSSL on Linux, CNG +
//! crypt32 on Windows.

fn main() -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        imp::run()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!("azure-guest-local-verify supports Linux and Windows only")
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod imp {
    use anyhow::{Context, Result};
    use azure_guest_attestation_sdk::verify;
    use clap::{Parser, Subcommand};
    use std::path::PathBuf;
    use std::process::exit;

    #[derive(Parser)]
    #[command(
        name = "azure-guest-local-verify",
        about = "Local (offline) verification of Azure CVM attestation evidence"
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
        /// Emit a machine-readable JSON result.
        #[arg(long, global = true)]
        json: bool,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Verify an Intel TDX quote (bare or QGS-wrapped) to the pinned Intel
        /// SGX Root CA.
        Tdx {
            /// Path to the TDX quote file.
            quote: PathBuf,
        },
        /// Verify an AMD SEV-SNP report against its VCEK certificate chain
        /// (validated to a pinned AMD ARK root).
        Snp {
            /// Path to the raw SNP attestation report (0x4a0 bytes).
            report: PathBuf,
            /// Path to the VCEK certificate chain (PEM: VCEK, ASK[, ARK]).
            #[arg(long)]
            vcek: PathBuf,
        },
    }

    /// A successful verification: the checks performed and the verified fields.
    struct Report {
        checks: Vec<(&'static str, bool)>,
        fields: Vec<(&'static str, String)>,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn run() -> Result<()> {
        let cli = Cli::parse();
        let (tee, result): (&str, Result<Report, std::io::Error>) =
            match &cli.command {
                Command::Tdx { quote } => {
                    let bytes = std::fs::read(quote)
                        .with_context(|| format!("read {}", quote.display()))?;
                    let r = verify::verify_td_quote(&bytes, &verify::TdxVerifyPolicy::default())
                        .map(|r| Report {
                            checks: vec![
                                ("body signature", r.quote_signature_valid),
                                ("attestation-key binding", r.attestation_key_bound),
                                ("QE report signature", r.qe_report_signature_valid),
                                ("PCK chain -> Intel SGX Root CA", r.pck_chain_valid),
                            ],
                            fields: vec![
                                ("mr_td", hex(&r.measurements.mr_td)),
                                ("mr_seam", hex(&r.measurements.mr_seam)),
                                ("rtmr0", hex(&r.measurements.rtmr[0])),
                                ("rtmr1", hex(&r.measurements.rtmr[1])),
                                ("rtmr2", hex(&r.measurements.rtmr[2])),
                                ("rtmr3", hex(&r.measurements.rtmr[3])),
                                ("report_data", hex(&r.measurements.report_data)),
                                ("tee_tcb_svn", hex(&r.measurements.tee_tcb_svn)),
                                ("td_attributes", hex(&r.measurements.td_attributes)),
                                ("xfam", hex(&r.measurements.xfam)),
                            ],
                        });
                    ("tdx", r)
                }
                Command::Snp { report, vcek } => {
                    let result = (|| {
                        let rep = std::fs::read(report)?;
                        let chain = std::fs::read(vcek)?;
                        verify::verify_snp_report(&rep, &chain, &verify::SnpVerifyPolicy::default())
                            .map(|r| Report {
                                checks: vec![
                                    ("VCEK chain -> AMD ARK root", r.chain_valid),
                                    ("report signature", r.signature_valid),
                                    ("VCEK report binding", r.vcek_binding_valid),
                                ],
                                fields: vec![
                                    ("measurement", hex(&r.measurements.measurement)),
                                    ("report_data", hex(&r.measurements.report_data)),
                                    (
                                        "reported_tcb",
                                        format!("{:016x}", r.measurements.reported_tcb),
                                    ),
                                    ("chip_id", hex(&r.measurements.chip_id)),
                                ],
                            })
                    })();
                    ("snp", result)
                }
            };

        let passed = result.is_ok();
        emit(cli.json, tee, &result);
        if passed {
            Ok(())
        } else {
            exit(2)
        }
    }

    fn emit(json: bool, tee: &str, result: &Result<Report, std::io::Error>) {
        if json && tee == "snp" {
            let mut output = serde_json::json!({
                "tee": "snp", "passed": result.is_ok(),
                "verification_scope": "structure_signature_chain_and_vcek_binding",
                "policy_checked": false, "crl_checked": false, "cpuid_stepping_checked": false,
            });
            match result {
                Ok(report) => {
                    output["checks"] = serde_json::Value::Object(
                        report
                            .checks
                            .iter()
                            .map(|(key, value)| ((*key).into(), serde_json::json!(value)))
                            .collect(),
                    );
                    output["measurements"] = serde_json::Value::Object(
                        report
                            .fields
                            .iter()
                            .map(|(key, value)| ((*key).into(), serde_json::json!(value)))
                            .collect(),
                    );
                }
                Err(error) => {
                    let (code, message) = snp_error(error);
                    output["error_code"] = serde_json::json!(code);
                    output["error"] = serde_json::json!(message);
                }
            }
            println!("{output}");
            return;
        }
        if json {
            match result {
                Ok(rep) => {
                    let checks = rep
                        .checks
                        .iter()
                        .map(|(k, v)| format!("\"{k}\":{v}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let fields = rep
                        .fields
                        .iter()
                        .map(|(k, v)| format!("\"{k}\":\"{v}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{{\"tee\":\"{tee}\",\"passed\":true,\"checks\":{{{checks}}},\"measurements\":{{{fields}}}}}"
                    );
                }
                Err(e) => {
                    let msg = e.to_string().replace('\\', "\\\\").replace('"', "\\\"");
                    println!("{{\"tee\":\"{tee}\",\"passed\":false,\"error\":\"{msg}\"}}");
                }
            }
            return;
        }
        if tee == "snp" {
            println!("  verification_scope: structure_signature_chain_and_vcek_binding");
            println!("  policy_checked: false; CRL and CPUID stepping equivalence: not checked");
            println!("  REPORTDATA, measurement, TCB minimums and migration authorization require caller policy.");
        }
        match result {
            Ok(rep) => {
                println!("{} verification: PASSED", tee.to_uppercase());
                for (k, _) in &rep.checks {
                    println!("  {k}: ok");
                }
                println!("measurements:");
                for (k, v) in &rep.fields {
                    println!("  {k}: {v}");
                }
            }
            Err(e) => {
                eprintln!("{} verification: FAILED", tee.to_uppercase());
                if tee == "snp" {
                    eprintln!("  reason: {}", snp_error(e).1);
                } else {
                    eprintln!("  reason: {e}");
                }
            }
        }
    }

    fn snp_error(error: &std::io::Error) -> (&'static str, &'static str) {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::NotFound => ("input_not_found", "An input file was not found"),
            ErrorKind::PermissionDenied => (
                "permission_denied",
                "Permission denied while reading an input",
            ),
            ErrorKind::InvalidInput => ("invalid_input", "Invalid verification input or time"),
            ErrorKind::InvalidData => (
                "invalid_evidence",
                "Invalid, expired, or mismatched evidence or collateral",
            ),
            _ => (
                "verification_failed",
                "Signature, certificate-chain, or verification-time validation failed",
            ),
        }
    }
}
