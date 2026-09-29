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

## Local TDX migration-field and TCB verification

With the `verify` feature, `verify::verify_td_quote()` verifies quote signatures
and the PCK chain, and returns all signed type-4 migration fields in
`TdxVerifyResult::service_td`. `TdQuoteBodyTdx15Ex::servtd_ext()` checks bit 17 of
TD attributes; this is distinct from the migratable bit. `init_tee_fmspc` is a
12-byte model encoding, **not a six-byte FMSPC**.

For authenticated TCB Info assessment use
`verify::verify_td_quote_with_collateral(&quote, &collateral, &policy)`:

- `TdxCollateral` accepts signed Intel TDX TCB Info JSON plus its PEM issuer
  chain. `from_flattened_endorsements()` safely extracts these from a flattened x64
  v4 bundle; serialized pointer slots are never used.
- TCB Info signatures and both certificate chains are checked against the pinned
  Intel root. Collateral FMSPC/PCE ID must match the authenticated PCK.
- SVN comparisons are componentwise, with separate module identity/ISVSVN checks
  for later modules. Current, launch and required initial assessments retain their
  own status/date/reason. Initial PCESVN and initial module signer/attributes are
  absent from the extension and cannot be verified.
- Initial-model matching uses a narrowly defined Emerald Rapids allowlist. Unknown models
  or missing required module identities yield `NotEvaluated` rather than reusing
  current-platform status. No generic CPUID-to-FMSPC equivalence is assumed.
- Certificate and TCB Info validity use one time, current by default. Historical
  `TdxTcbPolicy::verification_time` is explicit and does not prove current freshness.
  `baseline_date` is an opt-in certification-date policy relaxation, never an expiry or
  signature bypass. Inspect all statuses, not only the aggregate (which is not a
  total severity ordering).

**This does not implement full Intel DCAP/QVL:** CRLs, QE identity collateral,
migration continuity, and allowed Service-TD hashes are not evaluated. A returned
result means cryptographic inputs authenticated; callers must evaluate statuses
and their own policy. The companion CLI enforces every assessed component UpToDate
and prints scope/unchecked-check indicators; see its
[documentation](../../tools/azure-guest-local-verify/README.md).

The public Service-TD fixture has no common certificate/TCB Info validity window. Its
signatures and TCB matching are tested separately; production correctly rejects
the stale bundle. Positive end-to-end tests use synthetic signed collateral with
test-only roots, which the public Intel-pinned API rejects.

## Testing

The SDK ships with comprehensive tests backed by the
[Microsoft TPM 2.0 Reference Implementation](https://github.com/microsoft/ms-tpm-20-ref-rs)
(`ms-tpm-20-ref`), an in-process virtual TPM that enables deterministic,
hardware-independent testing. It is activated with the custom `--cfg vtpm_tests`
flag (set via `RUSTFLAGS`); the published crate never depends on it.

### Recommended: cargo-nextest (parallel)

```bash
# Install once
cargo install cargo-nextest

# Run all tests (from workspace root – uses alias defined in .cargo/config.toml)
RUSTFLAGS="--cfg vtpm_tests" cargo nt

# Or explicitly
RUSTFLAGS="--cfg vtpm_tests" cargo nextest run -p azure-guest-attestation-sdk
```

`cargo-nextest` runs each test as a **separate process**, so each test gets its
own vTPM instance and tests execute fully in parallel.

### Fallback: cargo test

```bash
RUSTFLAGS="--cfg vtpm_tests" cargo test -p azure-guest-attestation-sdk --lib
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
RUSTFLAGS="--cfg vtpm_tests" cargo clippy -p azure-guest-attestation-sdk --all-targets -- -D warnings
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

