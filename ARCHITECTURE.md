# Azure Guest Attestation SDK – Architecture

## Overview

The Azure Guest Attestation SDK is a Rust library for guest attestation on Azure. It supports **Confidential VMs** (Intel TDX, AMD SEV-SNP, VBS) and **TrustedLaunch** VMs.

The SDK is organized as a Cargo workspace with two members:

| Crate | Purpose |
|-------|---------|
| `azure-guest-attestation-sdk` | Core library — TPM commands, TEE report parsing, attestation workflows |
| `azure-guest-attest` | CLI tool — exercises the SDK for testing and diagnostics |

## Layered API

```
┌─────────────────────────────────────────────────────────┐
│  Application / CLI                                      │
├─────────────────────────────────────────────────────────┤
│  AttestationClient                                      │
│    .attest_guest()  .attest_platform()  .decrypt_token() │
│    .get_cvm_evidence()  .get_device_evidence()          │
│    .get_endorsement()   .create_attestation_report()    │
├─────────────────────────────────────────────────────────┤
│  parse module (stateless)                               │
│    snp_report  tdx_report  td_quote  attestation_token  │
├─────────────────────────────────────────────────────────┤
│  guest_attest  ·  report  ·  tee_report  ·  tpm         │
│  (provider abstractions, submission helpers, types)     │
├─────────────────────────────────────────────────────────┤
│  TPM 2.0 device (vTPM / hardware TPM)                   │
└─────────────────────────────────────────────────────────┘
```

| Level | Entry point | Description |
|-------|------------|-------------|
| **High** | `AttestationClient::attest_guest` | One-shot: collect evidence → build report → submit → token |
| **Mid** | `get_cvm_evidence`, `get_device_evidence`, `create_attestation_report` | Collect and assemble artifacts separately |
| **Low** | `tpm`, `tee_report`, `report` | Direct TPM commands, TEE report parsing |
| **Parse** | `parse` module | Stateless parsing of reports, quotes, and tokens |

### Attestation Flow (decomposed)

`AttestationClient::attest_guest()` is the highest-level API. Internally it follows
these steps, each of which can also be called independently:

```
1. Resolve PCR selection    → explicit (AttestOptions::pcr_selection) or OS default
2. get_cvm_evidence()          → CvmEvidence (TEE report, runtime claims)
                                  Falls back to TrustedLaunch when CVM
                                  report NV index is absent.
3. get_device_evidence(opts)   → DeviceEvidence (TpmInfo + ephemeral key handle)
                                  DeviceEvidenceOptions selects device type + PCRs
4. create_attestation_report() → AttestationReport (JSON request body)
5. submit_to_provider()        → token (with retry + backoff)
```

`attest_platform()` (TEE-only, no TPM evidence) follows a similar pattern:

```
1. get_cvm_evidence()                      → CvmEvidence
2. build_tee_only_payload_from_evidence()  → JSON payload
3. submit_tee_only()                       → token
```

## Module Map

```
crates/azure-guest-attestation-sdk/src/
├── lib.rs            # Crate root — module declarations, re-exports, tracing init
├── client.rs         # AttestationClient, Provider, options & result types
├── parse.rs          # Stateless parsing functions (no TPM / network)
├── guest_attest/
│   ├── mod.rs        # Attestation types, payload builders, TCG log collection
│   ├── provider.rs   # AttestationProvider trait, MaaProvider, LoopbackProvider
│   └── imds.rs       # ImdsClient for platform endorsements (VCEK chain, TD Quote)
├── report.rs         # CvmAttestationReport, CvmReportType, RuntimeClaims
├── tee_report/
│   ├── mod.rs        # Pretty-print dispatchers
│   ├── snp.rs        # AMD SEV-SNP report structures
│   ├── tdx.rs        # Intel TDX report structures (TDREPORT_STRUCT)
│   ├── td_quote.rs   # TDX quote v4/v5 parser
│   └── vbs.rs        # VBS report structures
└── tpm/
    ├── mod.rs         # Re-exports
    ├── device.rs      # Platform TPM access (Linux /dev/tpmrm0, Windows TBS)
    ├── commands.rs    # TpmCommandExt trait — high-level TPM operations
    ├── attestation.rs # CVM report retrieval, AK management, PCR quotes, ephemeral keys
    ├── types.rs       # TPM 2.0 structures and marshaling
    ├── helpers.rs     # Command buffer building utilities
    └── event_log.rs   # TCG event log parsing
```

## Key Design Decisions

### AttestationClient owns the TPM

`AttestationClient` holds an open `Tpm` handle internally. Callers never need to manage TPM lifecycle or pass device handles around. This keeps the public API simple:

```rust
let client = AttestationClient::new()?;
let result = client.attest_guest(Provider::maa("https://..."), None)?;
```

For more control, each step can be called independently:

```rust
let client = AttestationClient::new()?;
let cvm_evidence = client.get_cvm_evidence(None)?;
let device_evidence = client.get_device_evidence(Some(&DeviceEvidenceOptions {
    device_type: DeviceType::Tpm,
    pcr_selection: Some(vec![0, 1, 2, 7]),
}))?;
let report = client.create_attestation_report(&device_evidence, Some(&cvm_evidence), None, None)?;
// submit report.json to your own provider, or use submit_to_provider()
```

### DeviceEvidence bundles TPM artifacts

`DeviceEvidence` wraps the serializable `TpmInfo` (AK cert, PCR quote, ephemeral key, etc.) together with the ephemeral key handle and PCR indices. This ensures the handle — needed later for `decrypt_token()` — is never lost when collecting evidence separately from attestation.

### Provider is an enum, not a trait

`Provider` is an exhaustive enum (`Maa` / `Loopback`) rather than a `dyn` trait object. This avoids the complexity of trait objects in the public API and makes the provider set explicit.

### Stateless parse module

The `parse` module contains pure functions that operate on byte slices — no TPM, no network. This makes it easy to inspect attestation artifacts offline or in tests.

### vTPM singleton for tests

Tests that use the in-process reference TPM (`vtpm-tests` feature) share a single `OnceLock<Mutex<...>>` singleton. This allows full parallelism under `cargo nextest` (process-per-test) while remaining safe under `cargo test` (shared process with mutex serialization).

## TPM Access

| Platform | Device | Notes |
|----------|--------|-------|
| Linux | `/dev/tpmrm0` → `/dev/tpm0` | Kernel resource manager preferred |
| Windows | TBS (TPM Base Services) | Via `windows-sys` crate |
| Tests | `ms-tpm-20-ref` (in-process) | Feature-gated behind `vtpm-tests` |

## Future Work

- **C FFI layer** — A `cdylib` crate with `#[no_mangle]` functions wrapping `AttestationClient` can be added later to support language bindings (Python, C#, Go, etc.) via FFI.
- **Additional providers** — The `Provider` enum can be extended with new variants as needed.
- **Async support** — The current API is synchronous (blocking HTTP via `reqwest::blocking`). An async variant could be added behind a feature flag.