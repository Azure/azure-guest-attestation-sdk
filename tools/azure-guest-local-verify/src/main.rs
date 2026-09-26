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
    use clap::{Args, Parser, Subcommand};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use std::process::exit;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        /// Verify TDX signatures and chain, optionally assess authenticated TCB Info.
        /// Does not perform complete DCAP verification (no CRL or QE identity checks).
        Tdx(TdxArgs),
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

    #[derive(Args)]
    struct TdxArgs {
        /// Path to a bare or QGS-wrapped TDX quote.
        quote: PathBuf,
        /// Flattened x64 v4 endorsements bundle (only TCB Info and issuer chain used).
        #[arg(long, group = "collateral", conflicts_with_all = ["tcb_info", "tcb_issuer_chain"])]
        endorsements: Option<PathBuf>,
        /// Signed Intel TDX TCB Info JSON; requires --tcb-issuer-chain.
        #[arg(long, group = "collateral", requires = "tcb_issuer_chain")]
        tcb_info: Option<PathBuf>,
        /// PEM TCB signing-certificate chain; requires --tcb-info.
        #[arg(long, requires = "tcb_info")]
        tcb_issuer_chain: Option<PathBuf>,
        /// Nonnegative Unix seconds for certificate/collateral validation (default: now).
        /// Historical evaluation does not prove current freshness.
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        verification_time: Option<i64>,
        /// Opt-in certification-date baseline in Unix seconds (TCB policy relaxation).
        /// Requires collateral; never bypasses signature or freshness checks.
        #[arg(long, requires = "collateral", value_parser = clap::value_parser!(i64).range(0..))]
        tcb_baseline_date: Option<i64>,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn run() -> Result<()> {
        let cli = Cli::parse();
        let result = execute(&cli.command);
        emit(cli.json, &result);
        if result["passed"] == true {
            Ok(())
        } else {
            exit(2)
        }
    }

    fn read(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("read {}", path.display()))
    }

    fn execute(command: &Command) -> Value {
        match command {
            Command::Tdx(args) => {
                // Resolve once so signatures, collateral, and output use the same time.
                let now = args.verification_time.map(Ok).unwrap_or_else(|| {
                    Ok(i64::try_from(
                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    )?)
                });
                let result = now
                    .as_ref()
                    .map_err(|e: &anyhow::Error| anyhow::anyhow!("{e}"))
                    .and_then(|now| verify_tdx(args, *now));
                let mut output = result.unwrap_or_else(error_result);
                let collateral = args.endorsements.is_some() || args.tcb_info.is_some();
                output["tee"] = json!("tdx");
                output["verification_scope"] = json!(if collateral {
                    "signature_and_chain_and_tcb_info"
                } else {
                    "signature_and_chain"
                });
                output["verification_time"] = json!(now.ok());
                output["tcb_baseline_date"] = json!(args.tcb_baseline_date);
                output["tcb_checked"] = json!(output.get("tcb").is_some());
                output["complete_dcap_verification"] = json!(false);
                output["crl_checked"] = json!(false);
                output["qe_identity_checked"] = json!(false);
                output
            }
            Command::Snp { report, vcek } => {
                let mut output = verify_snp(report, vcek).unwrap_or_else(error_result);
                output["tee"] = json!("snp");
                output
            }
        }
    }

    fn error_result(error: anyhow::Error) -> Value {
        // Certificate/parser errors and their contexts can contain input bytes
        // or paths. Emit only fixed categories; never format the error chain.
        use std::io::ErrorKind;
        let kind = error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind);
        let (code, message) = match kind {
            Some(ErrorKind::NotFound) => ("input_not_found", "An input file was not found"),
            Some(ErrorKind::PermissionDenied) => (
                "permission_denied",
                "Permission denied while reading an input",
            ),
            Some(ErrorKind::InvalidInput) => {
                ("invalid_input", "Invalid verification input or time")
            }
            Some(ErrorKind::InvalidData) => (
                "invalid_evidence",
                "Invalid, expired, or mismatched evidence or collateral",
            ),
            _ => (
                "verification_failed",
                "Signature, certificate-chain, or verification-time validation failed",
            ),
        };
        json!({"passed": false, "error_code": code, "error": message})
    }

    fn verify_tdx(args: &TdxArgs, now: i64) -> Result<Value> {
        let bytes = read(&args.quote)?;
        let mut policy = verify::TdxTcbPolicy::default();
        policy.verification_time = Some(now);
        policy.baseline_date = args.tcb_baseline_date;
        if let Some(path) = &args.endorsements {
            let bundle = read(path)?;
            let collateral = verify::TdxCollateral::from_oe_endorsements(&bundle)?;
            let result = verify::verify_td_quote_with_collateral(&bytes, &collateral, &policy)?;
            Ok(collateral_result(&result))
        } else if let (Some(info), Some(chain)) = (&args.tcb_info, &args.tcb_issuer_chain) {
            let info = read(info)?;
            let chain = read(chain)?;
            let collateral = verify::TdxCollateral {
                tcb_info: &info,
                tcb_issuer_chain: &chain,
            };
            let result = verify::verify_td_quote_with_collateral(&bytes, &collateral, &policy)?;
            Ok(collateral_result(&result))
        } else {
            let mut policy = verify::TdxVerifyPolicy::default();
            policy.verification_time = Some(now);
            Ok(quote_result(&verify::verify_td_quote(&bytes, &policy)?))
        }
    }

    fn quote_result(r: &verify::TdxVerifyResult) -> Value {
        let mut fields = json!({
            "mr_td": hex(&r.measurements.mr_td),
            "mr_seam": hex(&r.measurements.mr_seam),
            "rtmr0": hex(&r.measurements.rtmr[0]),
            "rtmr1": hex(&r.measurements.rtmr[1]),
            "rtmr2": hex(&r.measurements.rtmr[2]),
            "rtmr3": hex(&r.measurements.rtmr[3]),
            "report_data": hex(&r.measurements.report_data),
            "tee_tcb_svn": hex(&r.measurements.tee_tcb_svn),
            "td_attributes": hex(&r.measurements.td_attributes),
            "xfam": hex(&r.measurements.xfam),
        });
        if let Some(body) = &r.service_td {
            let words: Vec<u32> = body
                .init_tee_fmspc
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .collect();
            let extension = json!({
                "tee_tcb_svn_2": hex(&body.base.tee_tcb_svn_2),
                "mr_service_td": hex(&body.base.mr_service_td),
                "vmid": body.vmid,
                "td_id": hex(&body.td_id),
                "devinfo": hex(&body.devinfo),
                "init_server_td_hash": hex(&body.init_server_td_hash),
                "init_server_td_attr": hex(&body.init_server_td_attr),
                "init_cpu_svn": hex(&body.init_cpu_svn),
                "init_tee_tcb_svn": hex(&body.init_tee_tcb_svn),
                "init_tee_fmspc": hex(&body.init_tee_fmspc),
                "init_tee_fmspc_model": {
                    "encoding": "three_le_u32_words_not_raw_fmspc",
                    "words": words,
                    "cpuid_leaf1_eax": words[1],
                },
                "curr_server_td_hash": hex(&body.curr_server_td_hash),
                "curr_server_td_attr": hex(&body.curr_server_td_attr),
                "servtd_ext": body.servtd_ext(),
            });
            fields
                .as_object_mut()
                .unwrap()
                .extend(extension.as_object().unwrap().clone());
        }
        json!({
            "passed": r.quote_signature_valid && r.attestation_key_bound
                && r.qe_report_signature_valid && r.pck_chain_valid,
            "checks": {
                "body signature": r.quote_signature_valid,
                "attestation-key binding": r.attestation_key_bound,
                "QE report signature": r.qe_report_signature_valid,
                "PCK chain -> Intel SGX Root CA": r.pck_chain_valid,
            },
            "measurements": fields,
        })
    }

    fn tcb_accepted(tcb: &verify::TdxTcbResult, initial_required: bool) -> bool {
        use verify::TcbStatus::UpToDate;
        tcb.current.status == UpToDate
            && tcb.launch.status == UpToDate
            && tcb.aggregate_status == UpToDate
            && match &tcb.initial {
                Some(initial) => initial.status == UpToDate,
                None => !initial_required,
            }
    }

    fn collateral_result(result: &verify::TdxCollateralVerifyResult) -> Value {
        assessed_result(&result.quote, &result.tcb, result.verification_time)
    }

    fn assessed_result(
        quote: &verify::TdxVerifyResult,
        tcb: &verify::TdxTcbResult,
        now: i64,
    ) -> Value {
        let mut output = quote_result(quote);
        // Check the signed attribute even if a required Service-TD body is absent.
        let required = u64::from_le_bytes(quote.measurements.td_attributes) & (1 << 17) != 0;
        output["passed"] = json!(output["passed"] == true && tcb_accepted(tcb, required));
        output["tcb"] = json!(tcb);
        output["verification_time"] = json!(now);
        output["tcb_acceptance_policy"] = json!("all_assessed_components_up_to_date");
        output
    }

    fn verify_snp(report: &Path, vcek: &Path) -> Result<Value> {
        let r = verify::verify_snp_report(
            &read(report)?,
            &read(vcek)?,
            &verify::SnpVerifyPolicy::default(),
        )?;
        Ok(json!({
            "passed": r.chain_valid && r.signature_valid,
            "checks": {
                "VCEK chain -> AMD ARK root": r.chain_valid,
                "report signature": r.signature_valid,
            },
            "measurements": {
                "measurement": hex(&r.measurements.measurement),
                "report_data": hex(&r.measurements.report_data),
                "reported_tcb": format!("{:016x}", r.measurements.reported_tcb),
                "chip_id": hex(&r.measurements.chip_id),
            },
        }))
    }

    fn emit(as_json: bool, output: &Value) {
        if as_json {
            println!("{output}");
            return;
        }
        let tee = output["tee"].as_str().unwrap_or("unknown").to_uppercase();
        let status = if output["passed"] == true {
            "PASSED"
        } else {
            "FAILED"
        };
        println!("{tee} verification: {status}");
        if tee == "TDX" {
            println!("  verification_scope: {}", output["verification_scope"]);
            println!("  verification_time: {}", output["verification_time"]);
            println!("  tcb_baseline_date: {}", output["tcb_baseline_date"]);
            println!("  tcb_checked: {}", output["tcb_checked"]);
            println!("  complete_dcap_verification: false; CRL and QE identity: not checked");
            println!("  Signed Service-TD fields do not establish migration-policy approval.");
        }
        if let Some(error) = output["error"].as_str() {
            println!("  reason: {error}");
        }
        if let Some(checks) = output["checks"].as_object() {
            for (name, passed) in checks {
                println!("  {name}: {}", if passed == true { "ok" } else { "FAILED" });
            }
        }
        if let Some(tcb) = output.get("tcb") {
            println!("TCB assessment (strict: every assessed status must be UpToDate):");
            println!("{tcb:#}");
        }
        if let Some(fields) = output["measurements"].as_object() {
            println!("measurements:");
            for (name, value) in fields {
                if let Some(text) = value.as_str() {
                    println!("  {name}: {text}");
                } else {
                    println!("  {name}: {value}");
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use verify::{TcbAssessment, TcbStatus, TdxTcbResult};

        fn up_to_date() -> TdxTcbResult {
            let assessment = TcbAssessment {
                status: TcbStatus::UpToDate,
                tcb_date: Some("2023-08-09T00:00:00Z".into()),
                reason: None,
            };
            TdxTcbResult {
                current: assessment.clone(),
                launch: assessment.clone(),
                initial: Some(assessment),
                aggregate_status: TcbStatus::UpToDate,
                aggregate_date: Some("2023-08-09T00:00:00Z".into()),
            }
        }

        #[test]
        fn strict_policy_checks_every_component_and_required_initial() {
            let mut tcb = up_to_date();
            assert!(tcb_accepted(&tcb, true));
            tcb.initial = None;
            assert!(tcb_accepted(&tcb, false));
            assert!(!tcb_accepted(&tcb, true));
            for status in [
                TcbStatus::ConfigurationNeeded,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::Revoked,
                TcbStatus::NotEvaluated,
            ] {
                for component in 0..4 {
                    let mut tcb = up_to_date();
                    match component {
                        0 => tcb.current.status = status.clone(),
                        1 => tcb.launch.status = status.clone(),
                        2 => tcb.initial.as_mut().unwrap().status = status.clone(),
                        _ => tcb.aggregate_status = status.clone(),
                    }
                    assert!(!tcb_accepted(&tcb, true), "{component}: {status:?}");
                    assert!(!tcb_accepted(&tcb, false), "{component}: {status:?}");
                }
            }
        }

        #[test]
        fn rejected_assessment_keeps_rich_json_and_dates() {
            // Synthetic TCB results test CLI policy/output only. The real expired
            // fixture is never represented as passing collateral authentication.
            let bytes = include_bytes!("../../../crates/azure-guest-attestation-sdk/src/verify/testdata/oe_tdx_v5_servtd_quote.bin");
            let mut policy = verify::TdxVerifyPolicy::default();
            policy.verification_time = Some(1790294400);
            let quote = verify::verify_td_quote(bytes, &policy).unwrap();
            let mut tcb = up_to_date();
            assert_eq!(assessed_result(&quote, &tcb, 1790294400)["passed"], true);
            for status in [TcbStatus::OutOfDate, TcbStatus::NotEvaluated] {
                tcb.initial.as_mut().unwrap().status = status.clone();
                tcb.initial.as_mut().unwrap().reason =
                    Some("unsupported model\n\"quoted\"\\reason".into());
                tcb.aggregate_status = status;
                let output = assessed_result(&quote, &tcb, 1790294400);
                let output: Value = serde_json::from_str(&output.to_string()).unwrap();
                assert_eq!(output["passed"], false);
                assert!(output.get("error").is_none());
                assert_eq!(output["tcb"], json!(tcb));
                assert_eq!(output["verification_time"], 1790294400i64);
                assert_eq!(output["checks"]["body signature"], true);
                assert_eq!(output["measurements"]["servtd_ext"], true);
            }
        }

        #[test]
        fn errors_do_not_disclose_lower_level_contents() {
            const SECRET: &str = "CERTIFICATE_CONTENT_SENTINEL\nprivate/path\"";
            for kind in [
                std::io::ErrorKind::NotFound,
                std::io::ErrorKind::PermissionDenied,
                std::io::ErrorKind::InvalidData,
                std::io::ErrorKind::InvalidInput,
                std::io::ErrorKind::Other,
            ] {
                let error = anyhow::Error::new(std::io::Error::new(kind, SECRET))
                    .context(format!("certificate parsing failed: {SECRET}"));
                let output = error_result(error);
                assert_eq!(output["passed"], false);
                assert!(!output.to_string().contains("CERTIFICATE_CONTENT_SENTINEL"));
                assert!(!output.to_string().contains("private/path"));
                assert!(output["error_code"].is_string());
            }
            let output = error_result(anyhow::anyhow!(SECRET));
            assert!(!output.to_string().contains("CERTIFICATE_CONTENT_SENTINEL"));
        }
    }
}
