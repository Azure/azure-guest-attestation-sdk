// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Missing rustdoc on public items is allowed for the initial v0.1 release.
// Comprehensive documentation will be added in a follow-up pass.
#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{Parser, Subcommand};

#[cfg(target_os = "windows")]
use anyhow::bail;
use anyhow::Context;

// Import functions from their module paths (root no longer re-exports many helpers)
use azure_guest_attestation_sdk::tee_report::td_quote::{
    parse_td_quote_with_options, pretty_td_quote, ParsedTdQuote, TdQuoteBody, TdQuoteCertification,
    TdQuoteEcdsaNestedCertification, TdQuotePckCertChain, TdQuoteSignatureMode,
};
use azure_guest_attestation_sdk::tpm::attestation::{get_ak_cert, get_ak_pub};
use azure_guest_attestation_sdk::tpm::attestation::{
    get_ak_cert_trimmed, get_cvm_report_raw, get_tee_report_and_type, get_user_data_nv,
};
use azure_guest_attestation_sdk::tpm::commands::TpmCommandExt;
use azure_guest_attestation_sdk::tpm::device::Tpm;
use azure_guest_attestation_sdk::tpm::event_log::{self, SpecIdEvent};
use azure_guest_attestation_sdk::tpm::types::PcrAlgorithm;
use base64::Engine;

type PcrBank = (PcrAlgorithm, Vec<(u32, Vec<u8>)>);

#[derive(Parser, Debug)]
#[command(author, version, about = "Azure Guest Attestation CLI", long_about = None)]
struct Cli {
    /// Output file instead of stdout
    #[arg(global = true, short = 'o', long)]
    out: Option<PathBuf>,

    /// Enable verbose TPM debug logging (sets CVM_TPM_DEBUG=1 for this process)
    #[arg(global = true, long = "debug-tpm")]
    debug_tpm: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fetch CVM attestation report (and optional runtime claims)
    CvmReport {
        /// Optional user data (<=64 bytes). Forms:
        ///   hex:deadbeef    (explicit hex, any length up to 64 bytes)
        ///   utf8:hello      (UTF-8 string, will be truncated at 64 bytes)
        ///   deadbeef...     (auto-detect hex if only [0-9a-fA-F] and even length)
        ///   (empty)         (all zeros)
        #[arg(long = "user-data", value_name = "DATA", default_value = "")]
        user_data: String,
        /// Output raw report bytes in hex
        #[arg(long)]
        raw: bool,
        /// Only output runtime claims JSON (pretty)
        #[arg(long)]
        claims: bool,
        /// Pretty print structured header fields
        #[arg(long, default_value_t = true)]
        pretty: bool,
        /// Show raw runtime claims JSON tail (UTF-8) even if parse failed / empty
        #[arg(long)]
        show_json: bool,
    },
    /// Fetch Attestation Key certificate (if provisioned in NV index)
    AkCert {
        /// Output in PEM form (assumes certificate DER in NV index)
        #[arg(long)]
        pem: bool,
        /// Attempt to parse and summarize X509 fields (requires --features with-x509)
        #[arg(long)]
        summary: bool,
        /// Output base64 instead of binary
        #[arg(long)]
        base64: bool,
        /// Force raw binary to stdout even if console (may error on Windows)
        #[arg(long)]
        binary: bool,
        /// Do not trim DER to parsed ASN.1 length (keep NV size)
        #[arg(long)]
        no_trim: bool,
    },
    /// Fetch Attestation Key public area
    AkPub {
        /// Output raw public area in hex
        #[arg(long)]
        hex: bool,
    },
    /// Diagnose TPM availability and environment
    Diagnose {
        /// Emit JSON instead of human text
        #[arg(long)]
        json: bool,
    },
    /// Fetch and display only the raw TEE report (or parsed form)
    TeeReport {
        /// Provide optional user data (same format as cvm-report) to influence report_data field
        #[arg(long = "user-data", value_name = "DATA", default_value = "")]
        user_data: String,
        /// Output only raw TEE report bytes (hex) without parsing
        #[arg(long)]
        raw: bool,
        /// Pretty print parsed structure (default true unless --raw)
        #[arg(long, default_value_t = true)]
        pretty: bool,
    },
    /// Parse a TD quote from disk or fetch it from the platform
    TdQuote {
        /// Path to the TD quote blob file (omit to fetch from IMDS)
        #[arg(value_name = "PATH")]
        quote: Option<PathBuf>,
        /// Output the raw quote bytes (binary) instead of parsing
        #[arg(long)]
        raw: bool,
        /// Output the quote bytes as a hex string instead of parsing
        #[arg(long)]
        hex: bool,
        /// Pretty print parsed structure (default true unless --raw or --hex)
        #[arg(long, default_value_t = true)]
        pretty: bool,
        /// Ignore missing or truncated signature data when parsing
        #[arg(long = "ignore-signature")]
        ignore_signature: bool,
        /// Save the extracted PCK certificate chain (PEM) to a file
        #[arg(long = "save-pck-pem", value_name = "PATH")]
        save_pck_pem: Option<PathBuf>,
    },
    /// Fetch isolation evidence only (SNP VCEK chain or TDX quote) and display in hex/base64
    IsolationEvidence {
        /// Output in base64 instead of hex
        #[arg(long)]
        base64: bool,
    },
    /// Decode the TPM event log and replay PCR values
    TpmEventLog {
        /// Optional path to the binary event log (defaults to common platform locations)
        #[arg(long = "event-log", value_name = "PATH")]
        event_log: Option<PathBuf>,
        /// Directory containing Windows Measured Boot logs (overrides defaults)
        #[cfg(target_os = "windows")]
        #[arg(long = "windows-dir", value_name = "DIR")]
        windows_dir: Option<PathBuf>,
        /// Filter output to the provided PCR indices (comma-separated or repeated)
        #[arg(long = "pcr-index", value_name = "INDEX", value_delimiter = ',')]
        pcr_index: Vec<u32>,
        /// Hash algorithm to use when replaying PCR values
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Compare replayed PCR values against live TPM readings
        #[arg(long)]
        verify: bool,
    },
    /// Read PCR values from the TPM
    ReadPcrs {
        /// Filter output to the provided PCR indices (comma-separated or repeated)
        #[arg(long = "pcr-index", value_name = "INDEX", value_delimiter = ',')]
        pcr_index: Vec<u32>,
    },
    /// Perform guest attestation against provider (loopback or MAA)
    GuestAttest {
        /// Provider: loopback | maa
        #[arg(long, default_value = "loopback")]
        provider: String,
        /// MAA endpoint (used when --provider=maa)
        #[arg(
            long,
            default_value = "https://sharedweu.weu.attest.azure.net/attest/AzureGuest?api-version=2020-10-01"
        )]
        endpoint: String,
        /// Optional JSON object of key-value pairs to embed (values base64 encoded) in ClientPayload
        #[arg(long, value_name = "JSON", default_value = "{}")]
        client_payload: String,
        /// Decode returned JWT (if it looks like one) and pretty print header/payload JSON
        #[arg(long)]
        decode: bool,
        /// Include original request JSON
        #[arg(long)]
        show_request: bool,
    },
    /// Perform TEE-only attestation (no TPM/PCR evidence) against MAA platform endpoint
    TeeAttest {
        /// MAA platform endpoint (e.g. `https://<region>.attest.azure.net/attest/TdxVm?api-version=2023-04-01-preview` or SevSnpVm)
        #[arg(
            long,
            default_value = "https://sharedweu.weu.attest.azure.net/attest/TdxVm?api-version=2023-04-01-preview"
        )]
        endpoint: String,
        /// Decode JWT (header & payload JSON pretty) if token-like
        #[arg(long)]
        decode: bool,
        /// Force treat evidence as SNP even if report type TDX (testing override)
        #[arg(long)]
        force_snp: bool,
        /// Force treat evidence as TDX even if report type SNP (testing override)
        #[arg(long)]
        force_tdx: bool,
        /// Show raw JSON request payload sent to MAA
        #[arg(long)]
        show_request: bool,
    },
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing early so all subsequent operations (including TPM access)
    // emit logs according to AZURE_GUEST_ATTESTATION_LOG / RUST_LOG environment filters.
    azure_guest_attestation_sdk::init_tracing();
    let cli = Cli::parse();
    if cli.debug_tpm {
        // Set env var early so lower layers can read it. Ignore failure if already set.
        std::env::set_var("CVM_TPM_DEBUG", "1");
    }
    let mut writer: Box<dyn Write> = match &cli.out {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stdout()),
    };

    match cli.command {
        Commands::CvmReport {
            user_data,
            raw,
            claims,
            pretty,
            show_json,
        } => {
            let ud_vec = parse_user_data_variable(&user_data)?; // Vec<u8> (<=64)
            let tpm = match Tpm::open() {
                Ok(t) => t,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    writeln!(writer, "TPM access via TBS failed (reported not found). If PowerShell 'get-tpm' shows TpmPresent=True this indicates a TBS accessibility or policy issue. Suggestions:\n  * Run: get-service tbs (should be Running)\n  * Restart service: Stop-Service tbs; Start-Service tbs\n  * Run: tpmtool getdeviceinformation\n  * Check: tpm.msc status\n  * If VM: ensure vTPM attached (Gen2, security settings)\n  * Set CVM_TPM_VERBOSE=1 and rerun for rc details")?;
                    return Ok(());
                }
                Err(e) => return Err(anyhow::anyhow!("Failed to open TPM: {e}")),
            };
            if raw {
                let bytes = get_cvm_report_raw(&tpm, Some(&ud_vec))?;
                writeln!(writer, "{}", hex::encode(bytes))?;
                return Ok(());
            }
            let (rep, rc) =
                azure_guest_attestation_sdk::tpm::attestation::get_cvm_report(&tpm, Some(&ud_vec))?;
            if claims {
                if let Some(c) = rc {
                    writeln!(writer, "{}", serde_json::to_string_pretty(&c)?)?;
                }
                return Ok(());
            }
            if pretty {
                writeln!(writer, "CVM Attestation Report:")?;
                // Full report_header dump
                let rh = &rep.report_header;
                writeln!(writer, "  ReportHeader.signature: 0x{:08x}", rh.signature)?;
                writeln!(writer, "  ReportHeader.version: {}", rh.version)?;
                writeln!(writer, "  ReportHeader.report_size: {}", rh.report_size)?;
                writeln!(writer, "  ReportHeader.request_type: {:?}", rh.request_type)?;
                writeln!(writer, "  ReportHeader.status: 0x{:08x}", rh.status)?;
                writeln!(
                    writer,
                    "  ReportHeader.reserved[0]: 0x{:08x}",
                    rh.reserved[0]
                )?;
                writeln!(
                    writer,
                    "  ReportHeader.reserved[1]: 0x{:08x}",
                    rh.reserved[1]
                )?;
                writeln!(
                    writer,
                    "  ReportHeader.reserved[2]: 0x{:08x}",
                    rh.reserved[2]
                )?;
                // Full runtime_claims_header dump
                let rch = &rep.runtime_claims_header;
                writeln!(writer, "  RuntimeClaimsHeader.data_size: {}", rch.data_size)?;
                writeln!(writer, "  RuntimeClaimsHeader.version: {}", rch.version)?;
                writeln!(
                    writer,
                    "  RuntimeClaimsHeader.report_type: {:?}",
                    rch.report_type
                )?;
                writeln!(
                    writer,
                    "  RuntimeClaimsHeader.report_data_hash_type: {:?}",
                    rch.report_data_hash_type
                )?;
                writeln!(
                    writer,
                    "  RuntimeClaimsHeader.variable_data_size: {}",
                    rch.variable_data_size
                )?;
                // Decode and pretty print full TEE report structure
                use azure_guest_attestation_sdk::report::{
                    CvmReportType, SNP_VM_REPORT_SIZE, TDX_VM_REPORT_SIZE, VBS_VM_REPORT_SIZE,
                };
                let rtype = rep.runtime_claims_header.report_type;
                let expected = match rtype {
                    CvmReportType::SnpVmReport => SNP_VM_REPORT_SIZE,
                    CvmReportType::TdxVmReport => TDX_VM_REPORT_SIZE,
                    CvmReportType::VbsVmReport => VBS_VM_REPORT_SIZE,
                    CvmReportType::TvmReport | CvmReportType::Invalid => 0,
                };
                if expected > 0 && expected <= rep.tee_report.len() {
                    match rtype {
                        CvmReportType::SnpVmReport => {
                            #[allow(clippy::cast_ptr_alignment)]
                            let r: &azure_guest_attestation_sdk::tee_report::snp::SnpReport = unsafe { &*(rep.tee_report.as_ptr() as *const _) };
                            let pretty_full =
                                azure_guest_attestation_sdk::tee_report::pretty_snp(r);
                            writeln!(writer, "{pretty_full}")?;
                        }
                        CvmReportType::TdxVmReport => {
                            #[allow(clippy::cast_ptr_alignment)]
                            let r: &azure_guest_attestation_sdk::tee_report::tdx::TdReport = unsafe { &*(rep.tee_report.as_ptr() as *const _) };
                            let pretty_full =
                                azure_guest_attestation_sdk::tee_report::pretty_tdx(r);
                            writeln!(writer, "{pretty_full}")?;
                        }
                        CvmReportType::VbsVmReport => {
                            #[allow(clippy::cast_ptr_alignment)]
                            let r: &azure_guest_attestation_sdk::tee_report::vbs::VbsReport = unsafe { &*(rep.tee_report.as_ptr() as *const _) };
                            let pretty_full =
                                azure_guest_attestation_sdk::tee_report::pretty_vbs(r);
                            writeln!(writer, "{pretty_full}")?;
                        }
                        _ => {}
                    }
                } else {
                    writeln!(
                        writer,
                        "(No TEE report body to decode for type {:?})",
                        rtype
                    )?;
                }
            }
            if let Some(c) = rc {
                writeln!(writer, "Runtime Claims JSON:")?;
                writeln!(writer, "{}", serde_json::to_string_pretty(&c)?)?;
            } else {
                writeln!(writer, "(No runtime claims present)")?;
            }
            if show_json {
                let var = rep.runtime_claims_header.variable_data_size as usize;
                if var > 0 {
                    let raw_full = get_cvm_report_raw(&tpm, None)?;
                    let fixed_len = std::mem::size_of::<
                        azure_guest_attestation_sdk::report::CvmAttestationReport,
                    >();
                    if raw_full.len() >= fixed_len + var {
                        let tail = &raw_full[fixed_len..fixed_len + var];
                        match std::str::from_utf8(tail) {
                            Ok(s) => {
                                writeln!(writer, "Runtime Claims Tail (UTF-8):")?;
                                writeln!(writer, "{s}")?;
                            }
                            Err(_) => writeln!(
                                writer,
                                "Runtime Claims Tail present but not valid UTF-8 ({} bytes)",
                                var
                            )?,
                        }
                    } else {
                        writeln!(
                            writer,
                            "(Variable data size {} beyond buffer length {})",
                            var,
                            raw_full.len()
                        )?;
                    }
                } else {
                    writeln!(writer, "(runtime_claims_header.variable_data_size == 0)")?;
                }
            }

            // Always attempt to read and display NV user data index contents after report generation.
            match get_user_data_nv(&tpm) {
                Ok(Some(data)) => {
                    writeln!(writer, "User Data NV Index: defined")?;
                    if data.is_empty() {
                        writeln!(writer, "  (empty / all zero bytes)")?;
                    } else {
                        // Hex representation
                        writeln!(
                            writer,
                            "  Hex ({} bytes): {}",
                            data.len(),
                            hex::encode(&data)
                        )?;
                        // UTF-8 (lossy) preview
                        let utf8_preview = String::from_utf8_lossy(&data);
                        // Escape newlines for a concise single-line preview
                        let escaped = utf8_preview.replace('\n', "\\n").replace('\r', "\\r");
                        writeln!(writer, "  UTF-8 (lossy): {escaped}")?;
                    }
                }
                Ok(None) => {
                    writeln!(writer, "User Data NV Index: (not defined)")?;
                }
                Err(e) => {
                    writeln!(writer, "User Data NV Index: error reading: {e}")?;
                }
            }
        }
        Commands::AkCert {
            pem,
            summary,
            base64,
            binary,
            no_trim,
        } => {
            let tpm = match Tpm::open() {
                Ok(t) => t,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    writeln!(writer, "TPM access via TBS failed (not found). If 'get-tpm' reports present, see: azure-guest-attest diagnose, restart TBS service, check tpm.msc, and verify virtualization settings.")?;
                    return Ok(());
                }
                Err(e) => return Err(anyhow::anyhow!("Failed to open TPM: {e}")),
            };
            let cert = if no_trim {
                get_ak_cert(&tpm)?
            } else {
                get_ak_cert_trimmed(&tpm)?
            };
            if cert.is_empty() {
                writeln!(writer, "(AK cert NV index empty or not defined)")?;
                return Ok(());
            }
            let stdout_is_tty = std::io::stdout().is_terminal() && cli.out.is_none();
            // If user did not pick a textual encoding and stdout is a TTY, auto-upgrade to PEM to avoid Windows console encoding issues.
            let effective_pem = pem || (stdout_is_tty && !base64 && !binary);
            if summary {
                #[cfg(feature = "with-x509")]
                {
                    use x509_parser::prelude::*;
                    match X509Certificate::from_der(&cert) {
                        Ok((_, x509)) => {
                            writeln!(writer, "Subject: {}", x509.subject())?;
                            writeln!(writer, "Issuer: {}", x509.issuer())?;
                            writeln!(
                                writer,
                                "Not Before: {}",
                                x509.validity().not_before.to_rfc2822()
                            )?;
                            writeln!(
                                writer,
                                "Not After: {}",
                                x509.validity().not_after.to_rfc2822()
                            )?;
                        }
                        Err(e) => writeln!(writer, "Failed to parse cert: {e}")?,
                    }
                }
                #[cfg(not(feature = "with-x509"))]
                {
                    writeln!(writer, "(rebuild with --features with-x509 for summary)")?;
                }
            }
            if effective_pem {
                writeln!(writer, "{}", der_to_pem("CERTIFICATE", &cert))?;
            } else if base64 {
                let eng = base64::engine::general_purpose::STANDARD;
                writeln!(writer, "{}", eng.encode(&cert))?;
            } else {
                if stdout_is_tty {
                    writeln!(
                        io::stderr(),
                        "Warning: writing raw binary to console; consider --pem or --base64"
                    )?;
                }
                writer.write_all(&cert)?;
            }
        }
        Commands::AkPub { hex } => {
            let tpm = match Tpm::open() {
                Ok(t) => t,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    writeln!(writer, "TPM access via TBS failed (not found). Use 'azure-guest-attest diagnose' and system tools (get-tpm, tpmtool) to isolate policy/service issues.")?;
                    return Ok(());
                }
                Err(e) => return Err(anyhow::anyhow!("Failed to open TPM: {e}")),
            };
            let pub_area = get_ak_pub(&tpm)?;
            if hex {
                writeln!(writer, "{}", hex::encode(pub_area))?;
            } else {
                writer.write_all(&pub_area)?;
            }
        }
        Commands::Diagnose { json } => {
            let mut result = serde_json::json!({
                "platform": std::env::consts::OS,
                "tpm_open": null,
                "notes": [] ,
            });
            match Tpm::open() {
                Ok(_) => {
                    if json {
                        result["tpm_open"] = serde_json::json!(true);
                    } else {
                        writeln!(writer, "TPM context: OK")?;
                    }
                }
                Err(e) => {
                    if json {
                        result["tpm_open"] = serde_json::json!(false);
                    } else {
                        writeln!(writer, "TPM context open failed: {e}")?;
                    }
                }
            }
            if cfg!(target_os = "windows") && !json {
                writeln!(writer, "Windows checks:")?;
                writeln!(
                    writer,
                    "  1. Run 'tpm.msc' -> Status should report 'The TPM is ready to use'"
                )?;
                writeln!(writer, "  2. Settings > Privacy & Security > Windows Security > Device Security -> Security processor details")?;
                writeln!(
                    writer,
                    "  3. Device Manager -> Security devices -> Trusted Platform Module"
                )?;
                writeln!(writer, "  4. If using a VM: ensure vTPM is attached and generation 2 VM with security features enabled")?;
                writeln!(writer, "  5. WSL note: Access to host TPM may require /dev/tpm* passthrough (not automatic)")?;
            }
            if json {
                writeln!(writer, "{}", serde_json::to_string_pretty(&result)?)?;
            }
        }
        Commands::TeeReport {
            user_data,
            raw,
            pretty,
        } => {
            let ud_vec = parse_user_data_variable(&user_data)?; // may be empty
            let tpm = match Tpm::open() {
                Ok(t) => t,
                Err(e) => return Err(anyhow::anyhow!("Failed to open TPM: {e}")),
            };
            let (tee_bytes, rtype) = get_tee_report_and_type(&tpm, Some(&ud_vec))?;
            use azure_guest_attestation_sdk::report::CvmReportType;
            if raw {
                if tee_bytes.is_empty() {
                    writeln!(writer, "(no TEE report for type {:?})", rtype)?;
                } else {
                    writeln!(writer, "{}", hex::encode(tee_bytes))?;
                }
                return Ok(());
            }
            if tee_bytes.is_empty() {
                writeln!(writer, "TEE report type {:?} has no payload", rtype)?;
                return Ok(());
            }
            match rtype {
                CvmReportType::SnpVmReport => {
                    if pretty {
                        if tee_bytes.len()
                            >= azure_guest_attestation_sdk::report::SNP_VM_REPORT_SIZE
                        {
                            #[allow(clippy::cast_ptr_alignment)]
                            let rep: &azure_guest_attestation_sdk::tee_report::snp::SnpReport = unsafe { &*(tee_bytes.as_ptr() as *const _) };
                            let full = azure_guest_attestation_sdk::tee_report::pretty_snp(rep);
                            writeln!(writer, "{full}")?;
                        } else {
                            writeln!(writer, "(truncated SNP report: {} bytes)", tee_bytes.len())?;
                        }
                    } else {
                        writeln!(writer, "{}", hex::encode(&tee_bytes))?;
                    }
                }
                CvmReportType::TdxVmReport => {
                    if pretty {
                        if tee_bytes.len()
                            >= azure_guest_attestation_sdk::report::TDX_VM_REPORT_SIZE
                        {
                            #[allow(clippy::cast_ptr_alignment)]
                            let rep: &azure_guest_attestation_sdk::tee_report::tdx::TdReport = unsafe { &*(tee_bytes.as_ptr() as *const _) };
                            let full = azure_guest_attestation_sdk::tee_report::pretty_tdx(rep);
                            writeln!(writer, "{full}")?;
                        } else {
                            writeln!(writer, "(truncated TDX report: {} bytes)", tee_bytes.len())?;
                        }
                    } else {
                        writeln!(writer, "{}", hex::encode(&tee_bytes))?;
                    }
                }
                CvmReportType::VbsVmReport => {
                    if pretty {
                        if tee_bytes.len()
                            >= azure_guest_attestation_sdk::report::VBS_VM_REPORT_SIZE
                        {
                            #[allow(clippy::cast_ptr_alignment)]
                            let rep: &azure_guest_attestation_sdk::tee_report::vbs::VbsReport = unsafe { &*(tee_bytes.as_ptr() as *const _) };
                            let full = azure_guest_attestation_sdk::tee_report::pretty_vbs(rep);
                            writeln!(writer, "{full}")?;
                        } else {
                            writeln!(writer, "(truncated VBS report: {} bytes)", tee_bytes.len())?;
                        }
                    } else {
                        writeln!(writer, "{}", hex::encode(&tee_bytes))?;
                    }
                }
                CvmReportType::TvmReport | CvmReportType::Invalid => {
                    writeln!(writer, "No TEE report available for type {:?}", rtype)?;
                }
            }
        }
        Commands::TdQuote {
            quote,
            raw,
            hex,
            pretty,
            ignore_signature,
            save_pck_pem,
        } => {
            let quote_bytes = if let Some(path) = quote {
                std::fs::read(&path)
                    .with_context(|| format!("reading TD quote from {}", path.display()))?
            } else {
                fetch_platform_td_quote()?.ok_or_else(|| {
                    anyhow::anyhow!("TD quote not available: host does not expose TDX report")
                })?
            };
            // raw outputs binary bytes, hex outputs hex string
            if raw {
                writer.write_all(&quote_bytes)?;
                return Ok(());
            }
            let capture_chain = save_pck_pem.is_some();
            let rendered =
                render_td_quote(&quote_bytes, hex, pretty, ignore_signature, capture_chain)?;
            writeln!(writer, "{}", rendered.display)?;
            if let Some(err) = &rendered.signature_error {
                writeln!(
                    writer,
                    "Warning: signature certification block parsing failed: {err}"
                )?;
            }
            if let Some(path) = save_pck_pem {
                let chain = rendered.pck_cert_chain.as_ref().ok_or_else(|| {
                    let mut msg = String::from("PCK certificate chain not present in quote");
                    if let Some(err) = &rendered.signature_error {
                        msg.push_str(&format!(" (parse error: {err})"));
                    }
                    anyhow::anyhow!(msg)
                })?;
                std::fs::write(&path, chain)
                    .with_context(|| format!("writing PCK cert chain to {}", path.display()))?;
                writeln!(
                    writer,
                    "Saved PCK cert chain ({} bytes) to {}",
                    chain.len(),
                    path.display()
                )?;
                if let Some(identity) = rendered.qe_identity.as_ref() {
                    writeln!(
                        writer,
                        "Quote includes QE identity payload ({} bytes); inspect pretty output for details.",
                        identity.len()
                    )?;
                }
            }
        }
        Commands::IsolationEvidence { base64 } => {
            let tpm = match Tpm::open() {
                Ok(t) => t,
                Err(e) => return Err(anyhow::anyhow!("Failed to open TPM: {e}")),
            };
            // Reuse report parsing to derive evidence type.
            let raw_report = get_cvm_report_raw(&tpm, None)?;
            let (parsed, _) =
                azure_guest_attestation_sdk::report::CvmAttestationReport::parse_with_runtime_claims(
                    &raw_report,
                )?;
            use azure_guest_attestation_sdk::report::CvmReportType;
            let rtype = parsed.runtime_claims_header.report_type;
            match rtype {
                CvmReportType::SnpVmReport => {
                    // Attempt IMDS VCEK chain fetch if feature enabled; else
                    if let Ok(client) = std::panic::catch_unwind(
                        azure_guest_attestation_sdk::guest_attest::ImdsClient::new,
                    ) {
                        match client.get_vcek_chain() {
                            Ok(bytes) => {
                                if base64 {
                                    writeln!(
                                        writer,
                                        "{}",
                                        base64::engine::general_purpose::STANDARD.encode(&bytes)
                                    )?;
                                } else {
                                    writeln!(writer, "{}", hex::encode(&bytes))?;
                                }
                            }
                            Err(e) => writeln!(writer, "(failed to fetch VCEK chain: {e})")?,
                        }
                    }
                }
                CvmReportType::TdxVmReport => {
                    if let Ok(client) = std::panic::catch_unwind(
                        azure_guest_attestation_sdk::guest_attest::ImdsClient::new,
                    ) {
                        match client.get_td_quote(&parsed.tee_report) {
                            Ok(bytes) => {
                                if base64 {
                                    writeln!(
                                        writer,
                                        "{}",
                                        base64::engine::general_purpose::STANDARD.encode(&bytes)
                                    )?;
                                } else {
                                    writeln!(writer, "{}", hex::encode(&bytes))?;
                                }
                            }
                            Err(e) => writeln!(writer, "(failed to fetch TD quote: {e})")?,
                        }
                    }
                }
                _ => writeln!(
                    writer,
                    "Unsupported report type {:?} for isolation evidence",
                    rtype
                )?,
            }
        }
        Commands::TpmEventLog {
            event_log: event_log_path,
            #[cfg(target_os = "windows")]
            windows_dir,
            pcr_index,
            algorithm,
            verify,
        } => {
            let alg = parse_algorithm_flag(&algorithm)?;
            let filter = validate_pcr_filter(&pcr_index)?;
            let filter_set = if filter.is_empty() {
                None
            } else {
                Some(filter.iter().copied().collect::<BTreeSet<u32>>())
            };

            #[cfg(target_os = "windows")]
            let windows_override = windows_dir.as_deref();
            #[cfg(not(target_os = "windows"))]
            let windows_override: Option<&Path> = None;

            let (raw_logs, sources) =
                load_event_logs_with_windows(event_log_path.as_deref(), windows_override)?;
            if raw_logs.len() != sources.len() {
                return Err(anyhow::anyhow!(
                    "Internal error: event log source count mismatch"
                ));
            }
            let mut parsed_logs = Vec::new();
            let mut skipped_logs = Vec::new();
            let mut text_logs = Vec::new();
            for (raw_log, source) in raw_logs.into_iter().zip(sources.into_iter()) {
                match event_log::parse_event_log(&raw_log) {
                    Ok(parsed) => parsed_logs.push((source, parsed)),
                    Err(err) => {
                        if event_log::is_mostly_printable(&raw_log) {
                            let text = String::from_utf8_lossy(&raw_log).to_string();
                            text_logs.push((source, text));
                        } else {
                            skipped_logs.push((source, err));
                        }
                    }
                }
            }

            if parsed_logs.is_empty() {
                if text_logs.is_empty() {
                    let msg = skipped_logs
                        .iter()
                        .map(|(path, err)| format!("{}: {err}", path.display()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(anyhow::anyhow!(
                        "No event logs could be parsed ({})",
                        if msg.is_empty() {
                            "no sources available".to_string()
                        } else {
                            msg
                        }
                    ));
                } else {
                    writeln!(writer, "No binary TPM event logs were parsed.")?;
                    writeln!(writer, "Text logs detected:")?;
                    for (path, text) in text_logs {
                        let lines: Vec<&str> = text.lines().collect();
                        writeln!(writer, "  {}:", path.display())?;
                        for line in lines.iter().take(20) {
                            writeln!(writer, "    {line}")?;
                        }
                        if lines.len() > 20 {
                            writeln!(writer, "    ... (truncated)")?;
                        }
                    }
                    writeln!(
                        writer,
                        "Re-run with --event-log pointing to a binary measurement log to enable PCR replay."
                    )?;
                    return Ok(());
                }
            }

            if parsed_logs.len() == 1 {
                writeln!(writer, "Event log source: {}", parsed_logs[0].0.display())?;
            } else {
                writeln!(writer, "Event log sources:")?;
                for (path, _) in &parsed_logs {
                    writeln!(writer, "  {}", path.display())?;
                }
            }

            if !skipped_logs.is_empty() {
                writeln!(writer, "Skipped event logs:")?;
                for (path, err) in &skipped_logs {
                    writeln!(writer, "  {} ({err})", path.display())?;
                }
            }

            if !text_logs.is_empty() {
                writeln!(writer, "Text event logs (not parsed as binary):")?;
                for (path, text) in text_logs {
                    let lines: Vec<&str> = text.lines().collect();
                    writeln!(writer, "  {}:", path.display())?;
                    for line in lines.iter().take(20) {
                        writeln!(writer, "    {line}")?;
                    }
                    if lines.len() > 20 {
                        writeln!(writer, "    ... (truncated)")?;
                    }
                }
            }

            if let Some(spec) = parsed_logs.iter().find_map(|(_, log)| {
                log.events.iter().find_map(|evt| {
                    if evt.event_type == 0x0000_0003 {
                        event_log::try_parse_spec_id_event(&evt.event_data)
                    } else {
                        None
                    }
                })
            }) {
                write_spec_overview(&mut *writer, &spec)?;
            }

            let combined_events: Vec<_> = parsed_logs
                .iter()
                .flat_map(|(_, log)| log.events.iter().cloned())
                .collect();

            if combined_events.is_empty() {
                writeln!(writer, "No events in log")?;
            } else {
                writeln!(writer, "Events:")?;
                let multiple_sources = parsed_logs.len() > 1;
                let mut printed_any = false;
                for (idx, (path, log)) in parsed_logs.iter().enumerate() {
                    let mut header_printed = false;
                    for evt in &log.events {
                        if let Some(set) = filter_set.as_ref() {
                            if !set.contains(&evt.pcr_index) {
                                continue;
                            }
                        }
                        if multiple_sources && !header_printed {
                            writeln!(writer, "  Source: {}", path.display())?;
                            header_printed = true;
                        }
                        write_event_entry(&mut *writer, evt)?;
                        printed_any = true;
                    }
                    if multiple_sources && header_printed && idx + 1 < parsed_logs.len() {
                        writeln!(writer)?;
                    }
                }
                if !printed_any {
                    writeln!(writer, "(no events matched PCR filter)")?;
                }
            }

            let mut replayed = event_log::replay_pcrs(&combined_events, alg);
            if let Some(set) = filter_set.as_ref() {
                for idx in set {
                    replayed
                        .entry(*idx)
                        .or_insert_with(|| vec![0u8; alg.digest_len()]);
                }
            }
            if replayed.is_empty() {
                writeln!(
                    writer,
                    "Replayed PCRs ({}): (no digests for this algorithm)",
                    alg
                )?;
            } else {
                writeln!(writer, "Replayed PCRs ({}):", alg)?;
                for (idx, digest) in &replayed {
                    if filter_set.as_ref().map_or(true, |set| set.contains(idx)) {
                        writeln!(writer, "  PCR[{idx}]: {}", hex::encode(digest))?;
                    }
                }
            }

            if verify {
                let mut verify_indices: Vec<u32> = if let Some(set) = filter_set.as_ref() {
                    set.iter().copied().collect()
                } else {
                    replayed.keys().copied().collect()
                };
                verify_indices.sort_unstable();
                verify_indices.dedup();
                if verify_indices.is_empty() {
                    writeln!(writer, "No PCR indices available for verification")?;
                } else {
                    let tpm =
                        Tpm::open().map_err(|e| anyhow::anyhow!("Failed to open TPM: {e}"))?;
                    let live_values = match tpm.read_pcrs_for_alg(alg, &verify_indices) {
                        Ok(vals) => vals,
                        Err(err) => {
                            return Err(anyhow::anyhow!(
                                "Failed to read TPM PCRs for {}: {err}",
                                alg
                            ))
                        }
                    };
                    let live_map: BTreeMap<u32, Vec<u8>> = live_values.into_iter().collect();
                    writeln!(writer, "Verification ({}):", alg)?;
                    for idx in verify_indices {
                        let expected = replayed
                            .get(&idx)
                            .cloned()
                            .unwrap_or_else(|| vec![0u8; alg.digest_len()]);
                        match live_map.get(&idx) {
                            Some(actual) => {
                                let status = if *actual == expected {
                                    "OK"
                                } else {
                                    "MISMATCH"
                                };
                                writeln!(
                                    writer,
                                    "  PCR[{idx}] {status} expected {} actual {}",
                                    hex::encode(&expected),
                                    hex::encode(actual)
                                )?;
                            }
                            None => {
                                writeln!(
                                    writer,
                                    "  PCR[{idx}] missing in TPM response (expected {})",
                                    hex::encode(&expected)
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Commands::ReadPcrs { pcr_index } => {
            let indices = normalize_pcrs_with_default(&pcr_index)?;
            let tpm = Tpm::open().map_err(|e| anyhow::anyhow!("Failed to open TPM: {e}"))?;
            let mut banks: Vec<PcrBank> = Vec::new();
            let mut skipped: Vec<(PcrAlgorithm, String)> = Vec::new();
            for alg in [
                PcrAlgorithm::Sha1,
                PcrAlgorithm::Sha256,
                PcrAlgorithm::Sha384,
            ] {
                match tpm.read_pcrs_for_alg(alg, &indices) {
                    Ok(values) if !values.is_empty() => banks.push((alg, values)),
                    Ok(_) => {}
                    Err(err) => skipped.push((alg, err.to_string())),
                }
            }
            if banks.is_empty() {
                if skipped.is_empty() {
                    writeln!(writer, "No PCR values returned")?;
                } else {
                    let reasons = skipped
                        .iter()
                        .map(|(alg, err)| format!("{alg}: {err}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(
                        writer,
                        "PCR read failed for all algorithms. Reasons: {reasons}",
                    )?;
                }
            } else {
                writeln!(writer, "PCR values:")?;
                for (alg, values) in &banks {
                    writeln!(writer, "  {alg}:")?;
                    for (idx, digest) in values {
                        writeln!(writer, "    PCR[{idx}]: {}", hex::encode(digest))?;
                    }
                }
                if !skipped.is_empty() {
                    let notes = skipped
                        .into_iter()
                        .map(|(alg, err)| format!("{alg} unavailable ({err})"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(writer, "  Note: {notes}")?;
                }
            }
        }
        Commands::GuestAttest {
            provider,
            endpoint,
            client_payload,
            decode,
            show_request,
        } => {
            let tpm = Tpm::open().map_err(|e| anyhow::anyhow!("Failed to open TPM: {e}"))?;
            // Build provider enum
            let prov = match provider.as_str() {
                "loopback" => azure_guest_attestation_sdk::client::Provider::Loopback,
                "maa" => azure_guest_attestation_sdk::client::Provider::maa(endpoint.clone()),
                other => return Err(anyhow::anyhow!("Unknown provider: {other}")),
            };
            let client = azure_guest_attestation_sdk::client::AttestationClient::from_tpm(tpm);
            let opts = azure_guest_attestation_sdk::client::AttestOptions {
                client_payload: Some(client_payload.clone()),
                ..Default::default()
            };
            let result = client.attest_guest(prov, Some(&opts))?;
            if show_request {
                writeln!(writer, "Request JSON:\n{}", result.request_json)?;
            }
            if let Some(tok) = &result.token {
                writeln!(writer, "Token (raw/envelope b64url): {tok}")?;
                if decode {
                    // Try envelope decrypt using the ephemeral key (recreated from PCRs)
                    match client.decrypt_token(&result.pcrs, tok) {
                        Ok(Some(inner_jwt)) => {
                            writeln!(writer, "Decrypted JWT:")?;
                            decode_and_print_jwt(&inner_jwt, &mut *writer)?;
                        }
                        Ok(None) => {
                            writeln!(writer, "(Token not in encrypted envelope format; attempting direct JWT decode)")?;
                            decode_and_print_jwt(tok, &mut *writer)?;
                        }
                        Err(e) => {
                            writeln!(writer, "(Envelope parse/decrypt failed: {e}; attempting direct JWT decode)")?;
                            decode_and_print_jwt(tok, &mut *writer)?;
                        }
                    }
                }
            } else {
                writeln!(writer, "(no token returned)")?;
            }
        }
        Commands::TeeAttest {
            endpoint,
            decode,
            force_snp,
            force_tdx,
            show_request,
        } => {
            let tpm = Tpm::open().map_err(|e| anyhow::anyhow!("Failed to open TPM: {e}"))?;
            use azure_guest_attestation_sdk::report::CvmReportType;
            let override_type = if force_snp {
                Some(CvmReportType::SnpVmReport)
            } else if force_tdx {
                Some(CvmReportType::TdxVmReport)
            } else {
                None
            };
            let (token_or_body, payload) =
                azure_guest_attestation_sdk::guest_attest::tee_only_attest_platform(
                    &tpm,
                    &endpoint,
                    override_type,
                )?;
            if show_request {
                writeln!(writer, "Request JSON:\n{payload}")?;
            }
            writeln!(writer, "Token: {token_or_body}")?;
            if decode {
                decode_and_print_jwt(&token_or_body, &mut *writer)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RenderedTdQuote {
    display: String,
    pck_cert_chain: Option<Vec<u8>>,
    qe_identity: Option<Vec<u8>>,
    signature_error: Option<String>,
}

fn render_td_quote(
    bytes: &[u8],
    hex_output: bool,
    pretty: bool,
    ignore_signature: bool,
    capture_chain: bool,
) -> anyhow::Result<RenderedTdQuote> {
    if hex_output && !capture_chain {
        return Ok(RenderedTdQuote {
            display: hex::encode(bytes),
            pck_cert_chain: None,
            qe_identity: None,
            signature_error: None,
        });
    }

    let mode = if ignore_signature {
        TdQuoteSignatureMode::AllowMissing
    } else {
        TdQuoteSignatureMode::Strict
    };
    let parsed = parse_td_quote_with_options(bytes, mode)
        .map_err(|e| anyhow::anyhow!("failed to parse TD quote: {e}"))?;

    let mut pck_cert_chain = None;
    let mut qe_identity = None;
    if capture_chain {
        if let Some(chain) = extract_pck_cert_chain(&parsed) {
            pck_cert_chain = Some(chain.cert_chain.to_vec());
            if let Some(identity) = chain.qe_identity {
                qe_identity = Some(identity.to_vec());
            }
        }
    }

    let display = if hex_output {
        hex::encode(bytes)
    } else if pretty {
        pretty_td_quote(&parsed)
    } else {
        td_quote_summary(&parsed)
    };

    Ok(RenderedTdQuote {
        display,
        pck_cert_chain,
        qe_identity,
        signature_error: parsed.signature_parse_error.as_ref().map(|e| e.to_string()),
    })
}

fn extract_pck_cert_chain<'a>(
    parsed: &'a ParsedTdQuote<'a>,
) -> Option<&'a TdQuotePckCertChain<'a>> {
    let signature = parsed.signature.as_ref()?;
    let certification = signature.certification.as_ref()?;
    match certification {
        TdQuoteCertification::EcdsaSigAux(ecdsa) => match ecdsa.nested_certification.as_ref()? {
            TdQuoteEcdsaNestedCertification::PckCertChain(chain) => Some(chain),
            _ => None,
        },
        _ => None,
    }
}

fn fetch_platform_td_quote() -> anyhow::Result<Option<Vec<u8>>> {
    let tpm = match Tpm::open() {
        Ok(t) => t,
        Err(e) => return Err(anyhow::anyhow!("Failed to open TPM: {e}")),
    };

    let (report, _) = azure_guest_attestation_sdk::tpm::attestation::get_cvm_report(&tpm, None)?;
    if report.runtime_claims_header.report_type
        != azure_guest_attestation_sdk::report::CvmReportType::TdxVmReport
    {
        return Ok(None);
    }

    let client = match std::panic::catch_unwind(
        azure_guest_attestation_sdk::guest_attest::ImdsClient::new,
    ) {
        Ok(c) => c,
        Err(_) => {
            return Err(anyhow::anyhow!("IMDS client unavailable on this platform"));
        }
    };

    match client.get_td_quote(&report.tee_report) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) => Err(anyhow::anyhow!("Failed to fetch TD quote from IMDS: {e}")),
    }
}

fn td_quote_summary(parsed: &ParsedTdQuote<'_>) -> String {
    let body_label = match &parsed.body {
        TdQuoteBody::Tdx10(_) => "TDX 1.0",
        TdQuoteBody::Tdx15(_) => "TDX 1.5",
        TdQuoteBody::Unknown { .. } => "unknown",
    };
    format!(
        "TD Quote v{} tee_type=0x{:08x} body_type=0x{:04x} ({}) body_size={} signature_len={} remainder={}",
        parsed.header.version,
        parsed.header.tee_type,
        parsed.body_header.body_type,
        body_label,
        parsed.body_header.size,
        parsed.signature_data_len,
        parsed.remainder.len()
    )
}

fn parse_user_data_variable(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    let trimmed = s.trim();
    let (mode, payload) = if let Some(rest) = trimmed.strip_prefix("hex:") {
        ("hex", rest)
    } else if let Some(rest) = trimmed.strip_prefix("utf8:") {
        ("utf8", rest)
    } else {
        ("auto", trimmed)
    };
    match mode {
        "utf8" => {
            let bytes = payload.as_bytes();
            if bytes.len() > 64 {
                Ok(bytes[..64].to_vec())
            } else {
                Ok(bytes.to_vec())
            }
        }
        "hex" => hex_to_bytes(payload),
        "auto" => {
            if is_probable_hex(payload) {
                hex_to_bytes(payload)
            } else {
                // treat as utf8
                let bytes = payload.as_bytes();
                if bytes.len() > 64 {
                    Ok(bytes[..64].to_vec())
                } else {
                    Ok(bytes.to_vec())
                }
            }
        }
        _ => unreachable!(),
    }
}

fn is_probable_hex(s: &str) -> bool {
    if s.len() % 2 != 0 || s.is_empty() {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit()) && (s.len() / 2) <= 64
}

fn hex_to_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow::anyhow!("hex data must have even length"));
    }
    if (s.len() / 2) > 64 {
        return Err(anyhow::anyhow!("hex decodes to more than 64 bytes"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?);
    }
    Ok(out)
}

fn der_to_pem(label: &str, der: &[u8]) -> String {
    let eng = base64::engine::general_purpose::STANDARD;
    let b64 = eng.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {label}-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn base64_url_decode_vec(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64url decode failed: {e}"))
}

fn decode_and_print_jwt(token: &str, writer: &mut dyn Write) -> anyhow::Result<()> {
    // 1. If it looks like a dot-separated JWT, decode header + payload directly.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() >= 2 {
        let header_raw = base64_url_decode_vec(parts[0])?;
        let payload_raw = base64_url_decode_vec(parts[1])?;
        let header = String::from_utf8_lossy(&header_raw);
        let payload = String::from_utf8_lossy(&payload_raw);
        writeln!(writer, "JWT Header:")?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&header) {
            writeln!(writer, "{}", serde_json::to_string_pretty(&v)?)?;
        } else {
            writeln!(writer, "{header}")?;
        }
        writeln!(writer, "JWT Payload:")?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) {
            writeln!(writer, "{}", serde_json::to_string_pretty(&v)?)?;
        } else {
            writeln!(writer, "{payload}")?;
        }
        return Ok(());
    }

    // 2. Try base64url-decode → JSON envelope (MAA encrypted token format).
    //    The envelope has { "Jwt": "...", "EncryptedInnerKey": "...", ... }.
    if let Ok(raw) = base64_url_decode_vec(token) {
        if let Ok(text) = String::from_utf8(raw) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                // If there's a "Jwt" field, try to decode it as a JWT.
                if let Some(jwt_str) = v.get("Jwt").and_then(|j| j.as_str()) {
                    let jwt_parts: Vec<&str> = jwt_str.split('.').collect();
                    if jwt_parts.len() >= 2 {
                        writeln!(writer, "(Decoded encrypted envelope — Jwt field is a JWT)")?;
                        return decode_and_print_jwt(jwt_str, writer);
                    }
                }
                // Otherwise, print the envelope JSON structure (with long
                // values truncated for readability).
                writeln!(writer, "Encrypted envelope:")?;
                if let Some(obj) = v.as_object() {
                    for (key, val) in obj {
                        if let Some(s) = val.as_str() {
                            if s.len() > 80 {
                                writeln!(
                                    writer,
                                    "  {key}: \"{}...\" ({} bytes)",
                                    &s[..80],
                                    s.len()
                                )?;
                            } else {
                                writeln!(writer, "  {key}: \"{s}\"")?;
                            }
                        } else {
                            writeln!(writer, "  {key}: {val}")?;
                        }
                    }
                } else {
                    writeln!(writer, "{}", serde_json::to_string_pretty(&v)?)?;
                }
                return Ok(());
            }
        }
    }

    writeln!(writer, "(not a JWT structure)")?;
    Ok(())
}

fn parse_algorithm_flag(value: &str) -> anyhow::Result<PcrAlgorithm> {
    PcrAlgorithm::from_str(value).map_err(|_| {
        anyhow::anyhow!(
            "Unsupported algorithm '{}'. Expected sha1, sha256, or sha384.",
            value
        )
    })
}

fn validate_pcr_filter(pcrs: &[u32]) -> anyhow::Result<Vec<u32>> {
    let mut out = Vec::new();
    for &idx in pcrs {
        if idx > 23 {
            return Err(anyhow::anyhow!("PCR index {idx} out of range (0-23)"));
        }
        if !out.contains(&idx) {
            out.push(idx);
        }
    }
    Ok(out)
}

fn normalize_pcrs_with_default(pcrs: &[u32]) -> anyhow::Result<Vec<u32>> {
    let filtered = validate_pcr_filter(pcrs)?;
    if filtered.is_empty() {
        Ok((0u32..24).collect())
    } else {
        Ok(filtered)
    }
}

fn write_spec_overview(writer: &mut dyn Write, spec: &SpecIdEvent) -> io::Result<()> {
    writeln!(
        writer,
        "Spec ID: {} class=0x{:08x} version {}.{} errata {} uintn {}",
        spec.signature,
        spec.platform_class,
        spec.spec_version_major,
        spec.spec_version_minor,
        spec.spec_errata,
        spec.uintn_size
    )?;
    if !spec.algorithms.is_empty() {
        writeln!(writer, "  Algorithms:")?;
        for alg in &spec.algorithms {
            let name = PcrAlgorithm::from_alg_id(alg.algorithm_id)
                .map(|a| a.to_string())
                .unwrap_or_else(|| format!("0x{:04x}", alg.algorithm_id));
            writeln!(writer, "    {} (size {})", name, alg.digest_size)?;
        }
    }
    if !spec.vendor_info.is_empty() {
        let preview = hex_preview(&spec.vendor_info, 64);
        writeln!(writer, "  Vendor info: {}", preview)?;
    }
    Ok(())
}

fn write_event_entry(writer: &mut dyn Write, event: &event_log::Event) -> io::Result<()> {
    let name = event_log::event_type_description(event.event_type).unwrap_or("UNKNOWN");
    writeln!(
        writer,
        "PCR[{}] {} (0x{:08x})",
        event.pcr_index, name, event.event_type
    )?;
    if event.digests.is_empty() {
        writeln!(writer, "    (no digests)")?;
    } else {
        for digest in &event.digests {
            let digest_hex = hex::encode(&digest.digest);
            if let Some(alg) = PcrAlgorithm::from_alg_id(digest.alg_id) {
                writeln!(writer, "    {}: {}", alg, digest_hex)?;
            } else {
                writeln!(writer, "    alg 0x{:04x}: {}", digest.alg_id, digest_hex)?;
            }
        }
    }
    if !event.event_data.is_empty() {
        if event_log::is_mostly_printable(&event.event_data) {
            let printable = String::from_utf8_lossy(&event.event_data);
            let sanitized = printable
                .replace('\r', "\\r")
                .replace('\n', "\\n")
                .replace('\t', "\\t");
            if !sanitized.is_empty() {
                writeln!(writer, "    data: {}", sanitized)?;
            }
        } else {
            let preview = hex_preview(&event.event_data, 128);
            writeln!(writer, "    data (hex): {}", preview)?;
        }
    }
    Ok(())
}

fn hex_preview(bytes: &[u8], max_chars: usize) -> String {
    let hex_str = hex::encode(bytes);
    if hex_str.len() <= max_chars {
        hex_str
    } else if max_chars >= 4 {
        let capped = max_chars - (max_chars % 2);
        if capped == 0 {
            format!("{} bytes", bytes.len())
        } else {
            format!("{}... ({} bytes)", &hex_str[..capped], bytes.len())
        }
    } else {
        format!("{} bytes", bytes.len())
    }
}

fn load_event_logs_with_windows(
    explicit: Option<&Path>,
    #[cfg_attr(not(target_os = "windows"), allow(unused_variables))] windows_dir: Option<&Path>,
) -> anyhow::Result<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    if let Some(path) = explicit {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading event log from {}", path.display()))?;
        return Ok((vec![bytes], vec![path.to_path_buf()]));
    }

    #[cfg(target_os = "windows")]
    if let Some(dir) = windows_dir {
        let entries = std::fs::read_dir(dir).with_context(|| {
            format!(
                "failed reading Windows event log directory {}",
                dir.display()
            )
        })?;

        let mut raw_logs = Vec::new();
        let mut sources = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed enumerating Windows event log directory {}",
                    dir.display()
                )
            })?;
            let file_type = entry.file_type().with_context(|| {
                format!("failed querying file type for {}", entry.path().display())
            })?;
            if !file_type.is_file() {
                continue;
            }
            let path = entry.path();
            let is_bin = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("bin"))
                .unwrap_or(false);
            if !is_bin {
                continue;
            }
            match std::fs::read(&path) {
                Ok(bytes) if !bytes.is_empty() => {
                    raw_logs.push(bytes);
                    sources.push(path);
                }
                Ok(_) => {}
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "failed reading event log {}: {err}",
                        path.display()
                    ));
                }
            }
        }

        if raw_logs.is_empty() {
            bail!("No TPM event logs found in {}", dir.display());
        }

        return Ok((raw_logs, sources));
    }

    let (logs, sources) = event_log::load_event_logs(None)?;
    Ok((logs, sources))
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_guest_attestation_sdk::tee_report::td_quote::{
        parse_td_quote, TdQuoteBodyTdx10, TdQuoteBodyType, TdQuoteHeader, TD_QUOTE_BODY_V1_0_SIZE,
    };
    use core::mem::size_of;
    use std::path::PathBuf;

    #[test]
    fn td_quote_summary_reports_key_fields() {
        let quote = minimal_tdx10_quote();
        let parsed = parse_td_quote(&quote).expect("parse minimal quote");
        let summary = td_quote_summary(&parsed);
        assert!(summary.contains("TD Quote v5"));
        assert!(summary.contains("body_type=0x0002"));
        assert!(summary.contains("signature_len=0"));
    }

    #[test]
    fn render_td_quote_modes() {
        let quote = minimal_tdx10_quote();
        let hex_out = render_td_quote(&quote, true, true, false, false).expect("hex mode");
        assert_eq!(hex_out.display, hex::encode(&quote));
        assert!(hex_out.pck_cert_chain.is_none());
        assert!(hex_out.signature_error.is_none());

        let pretty = render_td_quote(&quote, false, true, false, false).expect("pretty mode");
        assert!(pretty.display.contains("TD Quote v5"));
        assert!(pretty.signature_error.is_none());

        let summary = render_td_quote(&quote, false, false, false, false).expect("summary mode");
        assert!(summary.display.contains("body_type=0x0002"));
        assert!(summary.signature_error.is_none());
    }

    #[test]
    fn clap_parses_td_quote_command() {
        let cli = Cli::try_parse_from(["tool", "td-quote", "--raw", "quote.bin"]).unwrap();
        match cli.command {
            Commands::TdQuote {
                quote,
                raw,
                hex,
                pretty,
                ignore_signature,
                save_pck_pem,
            } => {
                assert_eq!(quote, Some(PathBuf::from("quote.bin")));
                assert!(raw);
                assert!(!hex);
                assert!(pretty);
                assert!(!ignore_signature);
                assert!(save_pck_pem.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Test --hex flag
        let cli = Cli::try_parse_from(["tool", "td-quote", "--hex", "quote.bin"]).unwrap();
        match cli.command {
            Commands::TdQuote {
                quote,
                raw,
                hex,
                pretty,
                ignore_signature,
                save_pck_pem,
            } => {
                assert_eq!(quote, Some(PathBuf::from("quote.bin")));
                assert!(!raw);
                assert!(hex);
                assert!(pretty);
                assert!(!ignore_signature);
                assert!(save_pck_pem.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn td_quote_command_defaults_to_system_quote() {
        let cli = Cli::try_parse_from(["tool", "td-quote"]).unwrap();
        match cli.command {
            Commands::TdQuote {
                quote,
                raw,
                hex,
                pretty,
                ignore_signature,
                save_pck_pem,
            } => {
                assert!(quote.is_none());
                assert!(!raw);
                assert!(!hex);
                assert!(pretty);
                assert!(!ignore_signature);
                assert!(save_pck_pem.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn clap_parses_td_quote_save_flag() {
        let cli = Cli::try_parse_from(["tool", "td-quote", "--save-pck-pem", "chain.pem"]).unwrap();
        match cli.command {
            Commands::TdQuote {
                quote,
                raw,
                hex,
                pretty,
                ignore_signature,
                save_pck_pem,
            } => {
                assert!(quote.is_none());
                assert!(!raw);
                assert!(!hex);
                assert!(pretty);
                assert!(!ignore_signature);
                assert_eq!(save_pck_pem, Some(PathBuf::from("chain.pem")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn td_quote_ignore_signature_flag() {
        let mut quote = minimal_tdx10_quote();
        // Drop the signature length field to simulate a quote without trailing signature data.
        quote.truncate(quote.len() - 4);

        let err = render_td_quote(&quote, false, true, false, false).unwrap_err();
        assert!(err.to_string().contains("failed to parse TD quote"));

        let summary = render_td_quote(&quote, false, false, true, false).expect("ignore signature");
        assert!(summary.display.contains("signature_len=0"));
        assert!(summary.signature_error.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn clap_parses_tpm_event_log_windows_dir() {
        let cli =
            Cli::try_parse_from(["tool", "tpm-event-log", "--windows-dir", "C:\\Logs"]).unwrap();
        match cli.command {
            Commands::TpmEventLog {
                event_log,
                windows_dir,
                pcr_index,
                algorithm,
                verify,
            } => {
                assert!(event_log.is_none());
                assert_eq!(windows_dir, Some(PathBuf::from("C:\\Logs")));
                assert!(pcr_index.is_empty());
                assert_eq!(algorithm, "sha256");
                assert!(!verify);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    fn as_bytes<T: Copy>(value: &T) -> &[u8] {
        unsafe { core::slice::from_raw_parts((value as *const T) as *const u8, size_of::<T>()) }
    }

    fn minimal_tdx10_quote() -> Vec<u8> {
        let header = TdQuoteHeader {
            version: 5,
            attestation_key_type: 2,
            tee_type: 0x0000_0081,
            qe_svn: 0,
            pce_svn: 0,
            qe_vendor_id: [0u8; 16],
            user_data: [0u8; 20],
            body_type: TdQuoteBodyType::Tdx10 as u16,
            body_size: TD_QUOTE_BODY_V1_0_SIZE as u32,
        };
        let body = TdQuoteBodyTdx10 {
            tee_tcb_svn: [0u8; 16],
            mr_seam: [0u8; 48],
            mr_signer_seam: [0u8; 48],
            seam_attributes: [0u8; 8],
            td_attributes: [0u8; 8],
            xfam: [0u8; 8],
            mr_td: [0u8; 48],
            mr_config_id: [0u8; 48],
            mr_owner: [0u8; 48],
            mr_owner_config: [0u8; 48],
            rtmr0: [0u8; 48],
            rtmr1: [0u8; 48],
            rtmr2: [0u8; 48],
            rtmr3: [0u8; 48],
            report_data: [0u8; 64],
        };

        let mut quote = Vec::new();
        quote.extend_from_slice(&header.version.to_le_bytes());
        quote.extend_from_slice(&header.attestation_key_type.to_le_bytes());
        quote.extend_from_slice(&header.tee_type.to_le_bytes());
        quote.extend_from_slice(&header.qe_svn.to_le_bytes());
        quote.extend_from_slice(&header.pce_svn.to_le_bytes());
        quote.extend_from_slice(&header.qe_vendor_id);
        quote.extend_from_slice(&header.user_data);
        quote.extend_from_slice(&header.body_type.to_le_bytes());
        quote.extend_from_slice(&header.body_size.to_le_bytes());
        quote.extend_from_slice(as_bytes(&body));
        quote.extend_from_slice(&0u32.to_le_bytes());
        quote
    }
}
