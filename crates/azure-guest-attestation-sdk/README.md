# Azure Guest Attestation SDK

[![Crates.io](https://img.shields.io/crates/v/azure-guest-attestation-sdk.svg)](https://crates.io/crates/azure-guest-attestation-sdk)
[![Documentation](https://docs.rs/azure-guest-attestation-sdk/badge.svg)](https://docs.rs/azure-guest-attestation-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Rust implementation of the Azure Attestation SDK for Confidential VMs (CVM) and TrustedLaunch VMs, providing TPM 2.0 operations and TEE attestation capabilities.

## Features

- **TPM 2.0 Command Support**: Full implementation of key TPM commands
  - Key management (CreatePrimary, Load, EvictControl)
  - Signing and verification (Sign, VerifySignature, Quote, Certify)
  - PCR operations (PCR_Read, PolicyPCR)
  - NV storage (NV_Read, NV_Write, NV_DefineSpace)
  - Cryptographic operations (RSA_Decrypt)
- **ECC Support**: ECDSA P-256 signing keys
- **TEE Report Parsing**: Intel TDX, AMD SEV-SNP, VBS
- **High-level `AttestationClient` API** with MAA integration
- **TDX endorsement retrieval** from Azure THIM (`endorsement` module / `ThimClient`)
- **COSE_Sign1 payload extraction** (`cose` module — RFC 9052, no external CBOR crate)
- **TrustedLaunch VM support** — auto-detected when CVM report is absent
- **Stateless `parse` module** for offline report inspection
- **Cross-Platform**: Windows and Linux support

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
azure-guest-attestation-sdk = "0.1"
```

## Quick Start

### One-shot Attestation

```rust
use azure_guest_attestation_sdk::{AttestationClient, Provider};

let client = AttestationClient::new()?;
let result = client.attest_guest(
    Provider::maa("https://sharedeus.eus.attest.azure.net"),
    None,
)?;
println!("Token: {}", result.token.unwrap_or_default());
```

### Decomposed Evidence Collection

For finer control, collect evidence and build the report in stages:

```rust
use azure_guest_attestation_sdk::{AttestationClient, Provider};

let client = AttestationClient::new()?;

// Step 1: Collect CVM (TEE) evidence
let cvm_evidence = client.get_cvm_evidence(None)?;

// Step 2: Collect device evidence (AK cert, PCR quote, ephemeral key)
use azure_guest_attestation_sdk::{DeviceType, DeviceEvidenceOptions};
let device_evidence = client.get_device_evidence(Some(&DeviceEvidenceOptions {
    device_type: DeviceType::Tpm,
    pcr_selection: Some(vec![0, 1, 2, 7]),
}))?;

// Step 3: Build the attestation report
let report = client.create_attestation_report(
    &device_evidence, Some(&cvm_evidence), None, None,
)?;

// Step 4: Submit to provider (or inspect report.json directly)
println!("Request JSON: {}", report.json);
```

### Low-level TPM Usage

```rust
use azure_guest_attestation_sdk::tpm::{Tpm, TpmCommandExt};
use azure_guest_attestation_sdk::tpm::attestation::get_cvm_report;

// Open the platform TPM
let tpm = Tpm::open()?;

// Read PCR values
let pcrs = tpm.read_pcrs_sha256(&[0, 1, 2, 7])?;
for (index, digest) in &pcrs {
    println!("PCR{}: {}", index, hex::encode(digest));
}

// Get CVM attestation report
let (report, claims) = get_cvm_report(&tpm, Some(b"user-data"))?;
```

## Testing

The SDK ships with comprehensive tests backed by the
[Microsoft TPM 2.0 Reference Implementation](https://github.com/microsoft/ms-tpm-20-ref-rs)
(`ms-tpm-20-ref`), an in-process virtual TPM that enables deterministic,
hardware-independent testing.

### Recommended: cargo-nextest (parallel)

```bash
# Install once
cargo install cargo-nextest

# Run all tests (from workspace root – uses alias defined in .cargo/config.toml)
cargo nt

# Or explicitly
cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests
```

`cargo-nextest` runs each test as a **separate process**, so each test gets its
own vTPM instance and tests execute fully in parallel.

### Fallback: cargo test

```bash
cargo test -p azure-guest-attestation-sdk --features vtpm-tests --lib
```

The reference TPM uses a process-global singleton with Mutex serialization,
so multi-threaded execution within `cargo test` is also safe.

### Unit tests only (no vTPM)

```bash
cargo test --lib
```

### Code quality

```bash
# Format check
cargo fmt --check

# Lint (includes vtpm-test targets)
cargo clippy -p azure-guest-attestation-sdk --features vtpm-tests --all-targets -- -D warnings
```

### vTPM Build Requirements

- **Perl** (for vendored OpenSSL build): [Strawberry Perl](https://strawberryperl.com/) on Windows
- On Windows with conflicting Perl installations, set:
  `$env:PERL5LIB = "C:\Strawberry\perl\lib;C:\Strawberry\perl\vendor\lib;C:\Strawberry\perl\site\lib"`

## Module Structure

| Module | Description |
|--------|-------------|
| `client` | `AttestationClient` — high-level API, `DeviceEvidence`, `CvmEvidence`, `Provider` |
| `cose` | Minimal COSE_Sign1 parser (RFC 9052) — extracts payload from CBOR-encoded envelopes |
| `endorsement` | `ThimClient` for TDX endorsement retrieval from Azure THIM, `EndorsementResponse` |
| `parse` | Stateless parsing (reports, quotes, JWT tokens) |
| `tpm` | Re-exports from `azure-tpm` (device, commands, types, helpers, event_log) |
| `tpm::attestation` | Azure-specific: AK management, CVM reports, PCR quotes, ephemeral keys, ECC signing |
| `tee_report` | TEE-specific report parsing (TDX, SNP, VBS) |
| `guest_attest` | Provider abstractions, submission helpers (`submit_to_provider`, `submit_tee_only`), attestation types |

## Developer Setup

```powershell
# Windows
.\scripts\setup.ps1

# Linux/macOS
./scripts/setup.sh
```

## License

MIT License - see [LICENSE](../../LICENSE)

