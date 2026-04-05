// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI tool for low-level TPM 2.0 operations using the `azure-tpm` crate.
//!
//! Requires access to a platform TPM device (`/dev/tpmrm0` on Linux,
//! TBS on Windows).  Run with `--help` for usage.

use anyhow::{bail, Context, Result};
use azure_tpm::event_log;
use azure_tpm::types::{Hierarchy, NvPublic, PcrAlgorithm, TpmaNvBits};
use azure_tpm::{Tpm, TpmCommandExt};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

/// Low-level TPM 2.0 command-line tool built on azure-tpm.
#[derive(Parser)]
#[command(name = "azure-tpm-tool", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read PCR values from the TPM.
    PcrRead {
        /// PCR indices to read (e.g. 0,1,2,7).
        #[arg(short, long, value_delimiter = ',', required = true)]
        pcrs: Vec<u32>,
        /// Hash algorithm bank to read from.
        #[arg(short, long, default_value = "sha256")]
        algorithm: PcrAlg,
    },

    /// Define a new NV index.
    NvDefine {
        /// NV index handle (hex, e.g. 0x01500001).
        #[arg(long, value_parser = parse_hex_u32)]
        index: u32,
        /// Size of the NV index in bytes.
        #[arg(short, long)]
        size: u16,
        /// NV index type.
        #[arg(short = 't', long, default_value = "ordinary")]
        nv_type: NvType,
        /// Hex-encoded authorization value (empty for no auth).
        #[arg(long, default_value = "")]
        auth: String,
    },

    /// Undefine (delete) an NV index.
    NvUndefine {
        /// NV index handle (hex, e.g. 0x01500001).
        #[arg(long, value_parser = parse_hex_u32)]
        index: u32,
    },

    /// Read the public area of an NV index.
    NvReadPublic {
        /// NV index handle (hex, e.g. 0x01500001).
        #[arg(long, value_parser = parse_hex_u32)]
        index: u32,
    },

    /// Read data from an NV index.
    NvRead {
        /// NV index handle (hex, e.g. 0x01500001).
        #[arg(long, value_parser = parse_hex_u32)]
        index: u32,
        /// Output file (default: print hex to stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Write data to an NV index.
    NvWrite {
        /// NV index handle (hex, e.g. 0x01500001).
        #[arg(long, value_parser = parse_hex_u32)]
        index: u32,
        /// Hex-encoded data to write.
        #[arg(long, group = "input")]
        data: Option<String>,
        /// File containing data to write.
        #[arg(short, long, group = "input")]
        file: Option<PathBuf>,
        /// Write a UTF-8 string (will be zero-padded to the NV index size).
        #[arg(long, group = "input")]
        string: Option<String>,
    },

    /// Extend an NV index (TPM2_NT_EXTEND type).
    NvExtend {
        /// NV index handle (hex, e.g. 0x01500001).
        #[arg(long, value_parser = parse_hex_u32)]
        index: u32,
        /// Hex-encoded data to extend.
        #[arg(long)]
        data: String,
    },

    /// Read the public area of a loaded object or persistent key.
    ReadPublic {
        /// Object handle (hex, e.g. 0x81000003).
        #[arg(long, value_parser = parse_hex_u32)]
        handle: u32,
    },

    /// Flush a transient object from the TPM.
    FlushContext {
        /// Transient handle to flush (hex).
        #[arg(long, value_parser = parse_hex_u32)]
        handle: u32,
    },

    /// Create a primary key in a hierarchy.
    CreatePrimary {
        /// Hierarchy to create the key in.
        #[arg(short = 'H', long, default_value = "owner")]
        hierarchy: HierarchyArg,
    },

    /// Make a transient key persistent (or remove a persistent key).
    EvictControl {
        /// Persistent handle to assign (hex, e.g. 0x81000010).
        #[arg(long, value_parser = parse_hex_u32)]
        persistent: u32,
        /// Transient handle of the key to persist (hex).
        #[arg(long, value_parser = parse_hex_u32)]
        transient: u32,
    },

    /// Parse and display a TCG event log.
    EventLog {
        /// Path to a binary event log file. If omitted, reads the system
        /// event log (/sys/kernel/security/tpm0/binary_bios_measurements).
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Hash algorithm for PCR replay.
        #[arg(short, long, default_value = "sha256")]
        algorithm: PcrAlg,
    },

    /// Generate a PCR quote signed by a key.
    Quote {
        /// Signing key handle (hex, e.g. 0x81000003).
        #[arg(long, value_parser = parse_hex_u32)]
        key: u32,
        /// PCR indices to quote (e.g. 0,1,2,7).
        #[arg(short, long, value_delimiter = ',', required = true)]
        pcrs: Vec<u32>,
    },
}

// ---------------------------------------------------------------------------
// Value enums for clap
// ---------------------------------------------------------------------------

#[derive(Clone, ValueEnum)]
enum PcrAlg {
    Sha1,
    Sha256,
    Sha384,
}

impl From<PcrAlg> for PcrAlgorithm {
    fn from(a: PcrAlg) -> Self {
        match a {
            PcrAlg::Sha1 => PcrAlgorithm::Sha1,
            PcrAlg::Sha256 => PcrAlgorithm::Sha256,
            PcrAlg::Sha384 => PcrAlgorithm::Sha384,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum NvType {
    /// Standard read/write storage.
    Ordinary,
    /// Extend-type (hash chain, like a PCR).
    Extend,
}

#[derive(Clone, ValueEnum)]
enum HierarchyArg {
    Owner,
    Endorsement,
    Null,
}

impl From<HierarchyArg> for Hierarchy {
    fn from(h: HierarchyArg) -> Self {
        match h {
            HierarchyArg::Owner => Hierarchy::Owner,
            HierarchyArg::Endorsement => Hierarchy::Endorsement,
            HierarchyArg::Null => Hierarchy::Null,
        }
    }
}

// ---------------------------------------------------------------------------
// Hex parsing helper
// ---------------------------------------------------------------------------

fn parse_hex_u32(s: &str) -> Result<u32, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|e| format!("invalid hex handle: {e}"))
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_pcr_read(tpm: &Tpm, pcrs: &[u32], alg: PcrAlgorithm) -> Result<()> {
    let values = tpm
        .read_pcrs_for_alg(alg, pcrs)
        .context("TPM2_PCR_Read failed")?;
    for (index, digest) in &values {
        println!("PCR{index:02}: {}", hex::encode(digest));
    }
    Ok(())
}

fn cmd_nv_define(tpm: &Tpm, index: u32, size: u16, nv_type: NvType, auth_hex: &str) -> Result<()> {
    let public = match nv_type {
        NvType::Ordinary => NvPublic::new_ordinary_index(index, size),
        NvType::Extend => NvPublic::new_extend_index(index, size),
    };
    let auth = if auth_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(auth_hex).context("invalid hex auth value")?
    };
    tpm.nv_define_space(public, &auth)
        .context("TPM2_NV_DefineSpace failed")?;
    println!(
        "Defined NV index 0x{index:08x} ({size} bytes, type={nv_type})",
        nv_type = match nv_type {
            NvType::Ordinary => "ordinary",
            NvType::Extend => "extend",
        }
    );
    Ok(())
}

fn cmd_nv_undefine(tpm: &Tpm, index: u32) -> Result<()> {
    tpm.nv_undefine_space(index)
        .context("TPM2_NV_UndefineSpace failed")?;
    println!("Undefined NV index 0x{index:08x}");
    Ok(())
}

fn cmd_nv_read_public(tpm: &Tpm, index: u32) -> Result<()> {
    let pub_info = tpm
        .nv_read_public(index)
        .context("TPM2_NV_ReadPublic failed")?;
    println!("NV Index:    0x{:08x}", pub_info.nv_index);
    println!("Name Alg:    0x{:04x}", pub_info.name_alg);
    println!("Attributes:  0x{:08x}", pub_info.attributes);
    let bits = TpmaNvBits::from(pub_info.attributes);
    print!("  Flags:     ");
    let mut flags = Vec::new();
    if bits.nv_ownerwrite() {
        flags.push("OWNERWRITE");
    }
    if bits.nv_authwrite() {
        flags.push("AUTHWRITE");
    }
    if bits.nv_ownerread() {
        flags.push("OWNERREAD");
    }
    if bits.nv_authread() {
        flags.push("AUTHREAD");
    }
    if bits.nv_no_da() {
        flags.push("NO_DA");
    }
    if bits.nt_extend() {
        flags.push("NT_EXTEND");
    }
    if bits.nv_clear_stclear() {
        flags.push("CLEAR_STCLEAR");
    }
    if bits.nv_ppwrite() {
        flags.push("PPWRITE");
    }
    if bits.nv_ppread() {
        flags.push("PPREAD");
    }
    if bits.nv_written() {
        flags.push("WRITTEN");
    }
    if bits.nv_platformcreate() {
        flags.push("PLATFORMCREATE");
    }
    if bits.nv_policywrite() {
        flags.push("POLICYWRITE");
    }
    if bits.nv_policyread() {
        flags.push("POLICYREAD");
    }
    if bits.nv_writedefine() {
        flags.push("WRITEDEFINE");
    }
    if bits.nv_writelocked() {
        flags.push("WRITELOCKED");
    }
    if bits.nv_readlocked() {
        flags.push("READLOCKED");
    }
    println!("{}", flags.join(" | "));
    println!(
        "Auth Policy: {}",
        if pub_info.auth_policy.is_empty() {
            "(empty)".to_string()
        } else {
            hex::encode(&pub_info.auth_policy)
        }
    );
    println!("Data Size:   {} bytes", pub_info.data_size);
    if pub_info.is_extend_type() {
        println!("Type:        extend (hash chain)");
    } else {
        println!("Type:        ordinary");
    }
    Ok(())
}

fn cmd_nv_read(tpm: &Tpm, index: u32, output: Option<PathBuf>) -> Result<()> {
    let data = tpm.read_nv_index(index).context("TPM2_NV_Read failed")?;
    if let Some(path) = output {
        std::fs::write(&path, &data)
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!(
            "Read {} bytes from NV 0x{:08x} → {}",
            data.len(),
            index,
            path.display()
        );
    } else {
        println!("{}", hex::encode(&data));
    }
    Ok(())
}

fn cmd_nv_write(
    tpm: &Tpm,
    index: u32,
    data_hex: Option<String>,
    file: Option<PathBuf>,
    string: Option<String>,
) -> Result<()> {
    let data = if let Some(hex_str) = data_hex {
        hex::decode(&hex_str).context("invalid hex data")?
    } else if let Some(path) = file {
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?
    } else if let Some(s) = string {
        s.into_bytes()
    } else {
        bail!("one of --data, --file, or --string is required");
    };
    tpm.write_nv_index(index, &data)
        .context("TPM2_NV_Write failed")?;
    println!("Wrote {} bytes to NV index 0x{index:08x}", data.len());
    Ok(())
}

fn cmd_nv_extend(tpm: &Tpm, index: u32, data_hex: &str) -> Result<()> {
    let data = hex::decode(data_hex).context("invalid hex data")?;
    tpm.nv_extend(index, &data)
        .context("TPM2_NV_Extend failed")?;
    println!("Extended NV index 0x{index:08x} with {} bytes", data.len());
    Ok(())
}

fn cmd_read_public(tpm: &Tpm, handle: u32) -> Result<()> {
    let public_bytes = tpm.read_public(handle).context("TPM2_ReadPublic failed")?;
    println!("Handle:     0x{handle:08x}");
    println!("Public ({} bytes):", public_bytes.len());
    println!("  {}", hex::encode(&public_bytes));
    Ok(())
}

fn cmd_flush_context(tpm: &Tpm, handle: u32) -> Result<()> {
    tpm.flush_context(handle)
        .context("TPM2_FlushContext failed")?;
    println!("Flushed handle 0x{handle:08x}");
    Ok(())
}

fn cmd_create_primary(tpm: &Tpm, hierarchy: Hierarchy) -> Result<()> {
    let template = azure_tpm::types::rsa_restricted_signing_public();
    let created = tpm
        .create_primary(hierarchy, template, &[])
        .context("TPM2_CreatePrimary failed")?;
    println!("Created primary key:");
    println!("  Handle:  0x{:08x} (transient)", created.handle);
    println!("  Public:  {} bytes", created.public.len());
    println!("  Hint: use 'evict-control' to make it persistent, or 'flush-context' to remove it.");
    Ok(())
}

fn cmd_evict_control(tpm: &Tpm, persistent: u32, transient: u32) -> Result<()> {
    tpm.evict_control(persistent, transient)
        .context("TPM2_EvictControl failed")?;
    println!("Persisted transient 0x{transient:08x} → persistent 0x{persistent:08x}");
    Ok(())
}

fn cmd_event_log(file: Option<PathBuf>, alg: PcrAlgorithm) -> Result<()> {
    let (raw, source) =
        event_log::load_event_log(file.as_deref()).context("failed to load event log")?;
    println!("Event log: {} ({} bytes)", source.display(), raw.len());
    let log = event_log::parse_event_log(&raw).context("failed to parse event log")?;

    // Try to extract SpecIdEvent from the first event's data
    if let Some(first) = log.events.first() {
        if let Some(spec) = event_log::try_parse_spec_id_event(&first.event_data) {
            println!(
                "Spec ID: platform_class={}, version={}.{}, algorithms={}",
                spec.platform_class,
                spec.spec_version_major,
                spec.spec_version_minor,
                spec.algorithms.len()
            );
            for a in &spec.algorithms {
                let name = PcrAlgorithm::from_alg_id(a.algorithm_id)
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| format!("0x{:04x}", a.algorithm_id));
                println!("  Algorithm: {} (digest size: {})", name, a.digest_size);
            }
        }
    }

    println!("\nEvents ({}):", log.events.len());
    for (i, evt) in log.events.iter().enumerate() {
        let type_desc = event_log::event_type_description(evt.event_type).unwrap_or("UNKNOWN");
        print!(
            "  [{i:3}] PCR{:02} type=0x{:08x} ({})",
            evt.pcr_index, evt.event_type, type_desc
        );
        if let Some(digest) = evt.digest_for_algorithm(alg) {
            print!(" {}={}", alg, hex::encode(digest));
        }
        if !evt.event_data.is_empty() && event_log::is_mostly_printable(&evt.event_data) {
            let s = String::from_utf8_lossy(&evt.event_data);
            let trimmed = s.trim_end_matches('\0');
            if !trimmed.is_empty() {
                print!(" data=\"{}\"", trimmed);
            }
        }
        println!();
    }

    // Replay PCR values
    let replayed = event_log::replay_pcrs(&log.events, alg);
    if !replayed.is_empty() {
        println!("\nReplayed PCR values ({alg}):");
        for (pcr, digest) in &replayed {
            println!("  PCR{pcr:02}: {}", hex::encode(digest));
        }
    }
    Ok(())
}

fn cmd_quote(tpm: &Tpm, key_handle: u32, pcrs: &[u32]) -> Result<()> {
    let (attest, signature) = tpm
        .quote_with_key(key_handle, pcrs)
        .context("TPM2_Quote failed")?;
    println!("Attestation ({} bytes):", attest.len());
    println!("  {}", hex::encode(&attest));
    println!("Signature ({} bytes):", signature.len());
    println!("  {}", hex::encode(&signature));
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Event log doesn't need a TPM
    if let Command::EventLog { file, algorithm } = cli.command {
        return cmd_event_log(file, algorithm.into());
    }

    let tpm = Tpm::open().context("failed to open TPM device")?;

    match cli.command {
        Command::PcrRead { pcrs, algorithm } => cmd_pcr_read(&tpm, &pcrs, algorithm.into()),
        Command::NvDefine {
            index,
            size,
            nv_type,
            auth,
        } => cmd_nv_define(&tpm, index, size, nv_type, &auth),
        Command::NvUndefine { index } => cmd_nv_undefine(&tpm, index),
        Command::NvReadPublic { index } => cmd_nv_read_public(&tpm, index),
        Command::NvRead { index, output } => cmd_nv_read(&tpm, index, output),
        Command::NvWrite {
            index,
            data,
            file,
            string,
        } => cmd_nv_write(&tpm, index, data, file, string),
        Command::NvExtend { index, data } => cmd_nv_extend(&tpm, index, &data),
        Command::ReadPublic { handle } => cmd_read_public(&tpm, handle),
        Command::FlushContext { handle } => cmd_flush_context(&tpm, handle),
        Command::CreatePrimary { hierarchy } => cmd_create_primary(&tpm, hierarchy.into()),
        Command::EvictControl {
            persistent,
            transient,
        } => cmd_evict_control(&tpm, persistent, transient),
        Command::Quote { key, pcrs } => cmd_quote(&tpm, key, &pcrs),
        Command::EventLog { .. } => unreachable!(),
    }
}
