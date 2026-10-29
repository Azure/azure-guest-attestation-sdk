# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-29

Maintenance release of `azure-tpm` and `azure-guest-attestation-sdk`.
CLI/tool versions are unchanged; no CLI binaries are published with this release.

### Added

- Add compatible `attest_guest_with_user_data` and
  `attest_platform_with_user_data` SDK methods and `--user-data` for
  `guest-attest` and `tee-attest`, preserving existing API signatures and
  `AttestOptions` fields.

### Fixed

- Update locked `tokio` to 1.53.3 to resolve the
  RUSTSEC-2026-0386 I/O-safety advisory without suppressing the advisory policy.
- Parse quote PCR digests as a single TPM2B_DIGEST, preserving the 0.1.x
  `ParsedQuoteAttest::pcr_digests` field as a zero-or-one-entry list.
- Include exact report runtime claims in TEE-only attestation requests.
- Fail attestation when requested user data cannot be staged or CVM evidence
  cannot be collected, rather than silently continuing without its binding.
- Update vulnerable HTTP/2, QUIC, TLS, certificate-validation, and trust-root
  dependencies to patched versions.

## [0.1.0] - 2026-03-18

Initial release. `azure-tpm` and `azure-guest-attestation-sdk` are publishable
to crates.io; the reference-TPM test harness (`ms-tpm-20-ref`) is pulled only
for tests via cfg-gated dev-dependencies and the non-published
`azure-tpm-testkit` crate, activated with `--cfg vtpm_tests`.

Minimum Supported Rust Version (MSRV): **1.90**.

### Added

- **High-level `AttestationClient` API** — one-shot `attest()` and decomposed
  `get_cvm_evidence()` → `get_device_evidence()` → `create_attestation_report()`
  → `submit_to_provider()` workflow.
- **`Tpm::from_raw_reference` / `Tpm::is_reference`** on `azure-tpm`, enabling
  non-hardware (reference/simulator) transports.
- **TEE-only attestation** via `attest_platform()` / `submit_tee_only()`.
- **TrustedLaunch VM support** — auto-detected when CVM report NV index is
  absent. `IsolationInfo` carries `vm_type: TrustedLaunch` with no TEE evidence.
- **TPM 2.0 command layer** — `CreatePrimary`, `Load`, `EvictControl`, `Sign`,
  `VerifySignature`, `Quote`, `Certify`, `PCR_Read`, `PolicyPCR`, `NV_Read`,
  `NV_Write`, `NV_DefineSpace`, `RSA_Decrypt`, and ECDSA P-256 signing.
- **TEE report parsers** — Intel TDX (TDREPORT + TD Quote v4/v5), AMD SEV-SNP,
  VBS report structures.
- **Stateless `parse` module** — offline inspection of SNP reports, TDX reports,
  TD Quotes, and JWT attestation tokens.
- **MAA provider** — Microsoft Azure Attestation integration with retry +
  exponential backoff.
- **TCG event log** collection (Linux `binary_bios_measurements`, Windows WBCL).
- **Token decryption** — AES-256-GCM envelope decryption using ephemeral TPM key.
- **Cross-platform** — Linux (`/dev/tpmrm0`) and Windows (TBS) TPM access.
- **CLI tool** (`azure-guest-attest`) for diagnostics, testing, and reference usage.

[Unreleased]: https://github.com/Azure/azure-guest-attestation-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Azure/azure-guest-attestation-sdk/releases/tag/v0.1.0
