# Azure Guest Attestation SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Azure Attestation SDK for Confidential VMs (Intel TDX, AMD SEV-SNP) and TrustedLaunch VMs on Azure, providing TPM 2.0 operations and TEE attestation capabilities.

## Repository Structure

```
├── Cargo.toml                      # Workspace root
├── .cargo/config.toml              # Cargo aliases (cargo nt, cargo vt)
├── .config/nextest.toml            # cargo-nextest configuration
├── crates/
│   └── azure-guest-attestation-sdk/       # Core library (publishable to crates.io)
└── tools/
    └── azure-guest-attest/                 # CLI tool
```

## Quick Start

### Prerequisites

- Rust toolchain (install via [rustup](https://www.rust-lang.org/tools/install))
- On Windows: Visual Studio Build Tools (MSVC) with "Desktop development with C++" workload
- On Linux: `build-essential` (or equivalent: `gcc`, `make`, `perl`)
- [cargo-nextest](https://nexte.st/) (recommended test runner): `cargo install cargo-nextest`

### Setup

```powershell
# Windows
.\scripts\setup.ps1

# Linux/macOS
./scripts/setup.sh
```

### Build All

```bash
# From repository root
cargo build --release
```

### Build Individual Crates

```bash
# Library only
cargo build -p azure-guest-attestation-sdk --release

# CLI tool only
cargo build -p azure-guest-attest --release
```

## Testing

The SDK uses the [Microsoft TPM 2.0 Reference Implementation](https://github.com/microsoft/ms-tpm-20-ref-rs)
as an in-process virtual TPM for deterministic, hardware-independent testing.
This is enabled by the `vtpm-tests` feature flag.

### Recommended: cargo-nextest (parallel, process-per-test)

[cargo-nextest](https://nexte.st/) runs each test as a **separate process**, giving
each test its own vTPM instance. Tests run fully in parallel with no thread-safety
concerns.

```bash
# Install once
cargo install cargo-nextest

# Run all SDK tests (uses workspace alias)
cargo nt

# Or explicitly
cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests
```

### Fallback: cargo test

The built-in `cargo test` harness runs all tests in a single process.
The reference TPM uses a process-global singleton with Mutex serialization.
Multi-step TPM operations that span multiple commands may encounter transient
state conflicts under multi-threaded execution; affected tests skip gracefully.

> **Note**: `cargo nextest` is the recommended runner for full, reliable coverage.

```bash
# Using workspace alias
cargo vt

# Or explicitly
cargo test -p azure-guest-attestation-sdk --features vtpm-tests --lib
```

### Other Test Commands

```bash
# Check formatting
cargo fmt --check

# Run clippy lints (all targets including tests)
cargo clippy -p azure-guest-attestation-sdk --features vtpm-tests --all-targets -- -D warnings

# Unit tests only (no vTPM, no hardware TPM needed)
cargo test -p azure-guest-attestation-sdk --lib
```

### vTPM Test Requirements

Tests gated behind `vtpm-tests` use the in-process reference TPM (`ms-tpm-20-ref`).
Build requirements:

- **Perl** (for vendored OpenSSL build) – [Strawberry Perl](https://strawberryperl.com/) on Windows
- On Windows with conflicting Perl installations (e.g. OS build tools), set:
  ```powershell
  $env:PERL5LIB = "C:\Strawberry\perl\lib;C:\Strawberry\perl\vendor\lib;C:\Strawberry\perl\site\lib"
  ```

## Crates

### [azure-guest-attestation-sdk](crates/azure-guest-attestation-sdk/)

Core attestation library - publishable to [crates.io](https://crates.io/crates/azure-guest-attestation-sdk).

```toml
[dependencies]
azure-guest-attestation-sdk = "0.1"
```

Features:
- TPM 2.0 command support (CreatePrimary, Sign, Quote, PCR operations, NV storage)
- TEE report parsing (Intel TDX, AMD SEV-SNP, VBS)
- High-level `AttestationClient` API with decomposed evidence collection and MAA integration
- `DeviceEvidence` / `CvmEvidence` types for step-by-step attestation workflows
- Stateless `parse` module for offline report / token inspection
- ECC P-256 signing keys

### [azure-guest-attest](tools/azure-guest-attest/)

Command-line tool for guest attestation operations.

```bash
azure-guest-attest --help
```

## CLI Usage (`azure-guest-attest`)

The `tools/azure-guest-attest/` directory contains a cross-platform command line utility for fetching CVM/vTPM attestation artifacts.

### Build

```powershell
cargo build -p azure-guest-attest --release
```

#### Static Build on Windows

For creating a fully static binary on Windows (with statically linked CRT), use the `static` feature:

**MSVC toolchain:**
```powershell
$env:RUSTFLAGS="-Ctarget-feature=+crt-static"
cargo build -p azure-guest-attest --features static --release
```

**GNU toolchain (MinGW):**
```powershell
cargo build -p azure-guest-attest --features static --release
```

### Help

```powershell
target/debug/azure-guest-attest --help
```

### Commands

* `azure-guest-attest cvm-report [--user-data <128 hex chars>] [--raw] [--claims] [--pretty]`
   * Fetch the CVM attestation report and optional runtime claims.
   * `--user-data` 64-byte (128 hex chars) value to stage before retrieving the report.
   * `--raw` Emit full NV report bytes as hex only.
   * `--claims` Emit only runtime claims JSON (pretty) if present.
   * `--pretty` (default) Print formatted header and claims. (Use `--no-pretty` to disable.)

* `azure-guest-attest ak-cert [--pem] [--base64] [--summary]`
   * Fetch Attestation Key certificate (if defined in NV index). Prints notice if missing.
   * `--pem` Output PEM instead of raw DER.
   * `--base64` Output base64 DER (no headers).
   * `--summary` Parse basic X.509 metadata (requires build with `--features with-x509`).

* `azure-guest-attest ak-pub [--hex]`
   * Fetch Attestation Key public area; `--hex` for hex encoding, otherwise raw bytes.

* `azure-guest-attest tee-report [--user-data <DATA>] [--raw] [--no-pretty]`
   * Fetch only the TEE attestation report body (without runtime claims parsing).
   * `--raw` outputs the report bytes (hex) trimmed to its known size for the report type.
   * Without `--raw`, a minimal parsed summary is printed depending on report type (SNP/TDX/VBS).
   * Report type is inferred from the embedded runtime claims header field.

Global option: `-o/--out <FILE>` to write output to a file instead of stdout.

### Examples

```powershell
# Pretty report + claims
azure-guest-attest cvm-report

# Raw report hex
azure-guest-attest cvm-report --raw

# Only claims after staging user data
azure-guest-attest cvm-report --user-data 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f --claims

# AK certificate in PEM
azure-guest-attest ak-cert --pem

# With summary (enable feature)
cargo run -p azure-guest-attest --features with-x509 -- ak-cert --summary --pem

# Raw TEE report only (hex)
azure-guest-attest tee-report --raw

# Parsed SNP report (with custom user data staged first)
azure-guest-attest tee-report --user-data utf8:hello
```

If an NV index is absent the tool prints a message and exits zero, allowing scripts to branch without treating it as an error.

### Guest Attestation

Additional commands for isolation evidence retrieval and Microsoft Azure Attestation (MAA) requests.
These require network access (IMDS for evidence, MAA endpoint for attestation).

Commands:

* `azure-guest-attest isolation-evidence [--base64]`
   * For SNP: fetches the VCEK certificate chain via IMDS (concatenated VCEK + chain PEM/DER text as returned).
   * For TDX: fetches a TD quote via IMDS.
   * Output defaults to hex; `--base64` switches to standard base64.

* `azure-guest-attest guest-attest [--provider loopback|maa] [--endpoint <MAA_URL>] [--decode] [--show-request]`
   * Collects TPM + TEE evidence, builds a GuestAttestationParameters JSON payload, base64url encodes it and submits to the selected provider.
   * Providers:
      * `loopback` (default): Returns an echo token embedding the request (testing only).
      * `maa`: Calls Microsoft Azure Attestation endpoint (default endpoint currently set to shared WEU sample: `https://sharedweu.weu.attest.azure.net/attest/AzureGuest?api-version=2020-10-01`).
   * `--decode` attempts to parse the returned token as JWT and pretty-print header & payload JSON.
   * `--show-request` prints the original JSON prior to encoding.

Examples:

```powershell
# Isolation evidence (hex)
azure-guest-attest isolation-evidence

# Isolation evidence base64
azure-guest-attest isolation-evidence --base64

# Guest attestation loopback with decoded echo token
azure-guest-attest guest-attest --provider loopback --show-request --decode

# Guest attestation against MAA shared WEU endpoint
azure-guest-attest guest-attest --provider maa --decode

# Custom MAA endpoint
azure-guest-attest guest-attest --provider maa --endpoint "https://<your-instance>.attest.azure.net/attest/AzureGuest?api-version=2020-10-01" --decode
```

Returned token structure: For MAA this is typically a JWT; for loopback it is a base64url encoded JSON object with fields `{ "loopback": true, "request": <b64url> }`.

### TEE-only Platform Attestation

The `tee-attest` subcommand performs platform isolation attestation directly against the Microsoft Azure Attestation (MAA) platform endpoints using only the underlying TEE evidence (SNP report + VCEK chain, or TDX quote). It omits all TPM / PCR / guest evidence.

Command:

* `azure-guest-attest tee-attest [--endpoint <MAA_PLATFORM_URL>] [--decode] [--show-request] [--force-snp] [--force-tdx]`
   * `--endpoint` MAA platform endpoint. Use the TDX or SNP path depending on the detected or desired report type:
      * TDX: `https://<region>.attest.azure.net/attest/TdxVm?api-version=2023-04-01-preview`
      * SNP: `https://<region>.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01`
      (A default TDX shared WEU endpoint is provided if omitted.)
   * The tool auto-detects report type from the CVM report. It warns if the endpoint and detected type mismatch.
   * `--decode` Pretty-print JWT header & payload (no signature verification) if the response looks like a JWT.
   * `--show-request` Prints the JSON payload sent to MAA (after IMDS quote / VCEK fetch where applicable).
   * `--force-snp` / `--force-tdx` Override the detected type for testing (does not transform evidence; only affects warnings).

Payload Shape (sent to MAA):

```jsonc
// TDX example
{
   "quote": "<base64 TD quote>",
   "runtimeData": { "data": "", "dataType": "JSON" }
}

// SNP example (SnpReport + VCEK chain wrapped then base64 encoded)
{
   "report": "<base64 JSON bytes of { SnpReport: b64(report), VcekCertChain: b64(chain) }>",
   "runtimeData": { "data": "", "dataType": "JSON" }
}
```

Examples:

```powershell
# TDX TEE-only attestation (shared WEU sample endpoint) with JWT decode
azure-guest-attest tee-attest --decode

# Explicit SNP platform endpoint
azure-guest-attest tee-attest --endpoint "https://sharedweu.weu.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01" --decode

# Show raw request JSON for inspection
azure-guest-attest tee-attest --show-request

# Force treat evidence as SNP (testing mismatch warning behavior)
azure-guest-attest tee-attest --force-snp
```

Notes:
* IMDS is contacted to fetch the TD quote (TDX) or VCEK chain (SNP); ensure the tool runs inside the confidential VM environment with IMDS accessible.
* Runtime data is currently empty; future versions may surface selected runtime claims.
* Use `azure-guest-attest guest-attest` if you need TPM / PCR evidence combined with TEE evidence.

## Logging & Diagnostics

The Rust core uses the `tracing` ecosystem for structured logging.

Environment variables:

* `AZURE_GUEST_ATTESTATION_LOG` – Override default (INFO) filter (`e.g. guest_attest=debug`)
* `RUST_LOG` – Fallback if the above unset
* `CVM_TPM_DEBUG`, `CVM_TPM_VERBOSE`, `CVM_TPM_DEBUG_NV` – Legacy fine-grained gates enabling additional debug-level output

All module logs share target `guest_attest`.

Example:

```bash
# Linux/macOS
AZURE_GUEST_ATTESTATION_LOG="guest_attest=debug" cargo run -p azure-guest-attest -- cvm-report
```

```powershell
# Windows (PowerShell)
$env:AZURE_GUEST_ATTESTATION_LOG = "guest_attest=debug"; cargo run -p azure-guest-attest -- cvm-report
```

To reset the variable:

```bash
# Linux/macOS
unset AZURE_GUEST_ATTESTATION_LOG
```

```powershell
# Windows (PowerShell)
Remove-Item Env:AZURE_GUEST_ATTESTATION_LOG
```

## Development Notes

* `AttestationClient::attest_guest()` internally decomposes into `get_cvm_evidence()` → `get_device_evidence()` → `create_attestation_report()` → `submit_to_provider()`, each callable independently.
* Attestation provider abstraction supports loopback & MAA; future providers can implement the `AttestationProvider` trait.
* Submission helpers (`submit_to_provider`, `submit_tee_only`) include retry logic with exponential backoff.
* Tool (`azure-guest-attest`) serves as a reference usage + regression harness.

## Contributing

This project welcomes contributions and suggestions. Most contributions require
you to agree to a Contributor License Agreement (CLA) declaring that you have the
right to, and actually do, grant us the rights to use your contribution. For
details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether
you need to provide a CLA and decorate the PR appropriately. Simply follow the
instructions provided by the bot.

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any
additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must
not cause confusion or imply Microsoft sponsorship. Any use of third-party
trademarks or logos are subject to those third-party's policies.