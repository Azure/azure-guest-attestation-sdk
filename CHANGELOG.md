# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **TDX Service-TD / live-migration TCB Info assessment.**
  `verify_td_quote_with_collateral()` authenticates signed Intel TCB Info to the
  pinned Intel root, checks certificate/collateral freshness and PCK FMSPC/PCE-ID
  binding, and reports current, launch, and initial-platform/module TCB states.
  `SERVTD_EXT` gates initial evaluation; its 12-byte model encoding uses the
  conservative Emerald Rapids allowlist rather than raw FMSPC equality.
  Unsupported initial models produce `NotEvaluated`, never an implicit pass.
  The existing signature-only API now returns the signed Service-TD fields.
  - Local CLI accepts flattened x64 `--endorsements`, or `--tcb-info` plus
    `--tcb-issuer-chain`, explicit `--verification-time`, and opt-in
    `--tcb-baseline-date`. It requires every evaluated TCB component UpToDate.
  - This is **not full DCAP/QVL verification**: CRLs, QE identity, Service-TD
    hash allowlists and migration continuity policies are not evaluated.
  - Public Service-TD fixtures, wire-offset/signature-tampering tests and synthetic
    signed-collateral tests cover the implementation. The sample bundle's dates are
    inconsistent; full validation intentionally rejects it as stale.

- **Local (offline) attestation verification** behind a new `verify` feature
  (requires the `native` backend: OpenSSL on Linux, CNG + crypt32 on Windows).
  - `verify::verify_snp_report()` validates an AMD SEV-SNP report's VCEK chain
    to a **pinned AMD ARK root** (Milan, Genoa) and verifies the report
    signature (ECDSA P-384 / SHA-384).
  - `verify::verify_td_quote()` validates an Intel TDX ECDSA quote end to end:
    the body signature (ECDSA P-256), the attestation-key binding to the QE
    report (`report_data`), the QE report signature (PCK), and the PCK
    certificate chain to a **pinned Intel SGX Root CA**. QGS `GET_QUOTE_RESP`
    envelopes (TDX QGS / MigTD) are unwrapped transparently.
- **`azure-guest-local-verify` CLI** — a new tool that verifies attestation
  evidence offline: `tdx <quote>` and `snp <report> --vcek <chain.pem>`, with
  text or `--json` output and exit code 2 on failure. Linux and Windows.
- **Runtime claims track the current OpenHCL `AttestationVmConfig` contract.**
  `report::AttestationVmConfig` gained the fields emitted by current hosts but
  previously dropped on the floor by this SDK:
  - `interactive_console_enabled` (`interactive-console-enabled`)
  - `vmgs_provisioner` (`vmgs-provisioner`) — new `report::VmgsProvisioner`
    carrying the VMGS `id` and `signer`
  - `hardware_sealing_policy` (`hardware-sealing-policy`) — new
    `report::HardwareSealingPolicy` (`none` / `hash` / `signer`)

  All three are `Option`, so absence (an older host that predates the field) is
  distinguishable from an explicitly reported value, matching how
  `tpm_persisted` and `filtered_vpci_devices_allowed` already behave.

  `HardwareSealingPolicy` carries an `Unknown(String)` catch-all so a policy
  value introduced by a future platform is preserved verbatim instead of
  failing to deserialize. That matters because
  `CvmAttestationReport::parse_with_runtime_claims()` maps a claims
  deserialization failure to `None`, so a strict enum would have silently
  discarded the *entire* claims blob over one unrecognized string.

  Field names, shapes, and the `tpm_persisted` legacy-naming caveat follow
  `AttestationVmConfig` in openvmm's `openhcl_attestation_protocol`
  (`openhcl/openhcl_attestation_protocol/src/igvm_attest/get.rs`).

- **`--user-data` on `guest-attest` and `tee-attest`.** Both subcommands now
  accept the same `hex:` / `utf8:` / auto-detect format as `cvm-report` and
  `tee-report` (≤64 bytes). The value is staged into the user-data NV index,
  so the platform includes it as `user-data` in the runtime claims — and
  because `report_data` is a hash over those claims, it is covered by the
  hardware signature.
  - Note this is **not** the same as `guest-attest --client-payload`, which is
    transport-level metadata in the request JSON and is not bound to the report.
  - New `AttestOptions::user_data` and `PlatformAttestOptions::user_data`.

### Fixed

- Update the locked `rustls` dependency to 0.23.45 for RUSTSEC-2026-0285.

- **`verify::verify_td_quote()` rejected TDX 1.5 Service-TD extended quotes.**
  The parser understands `body_type` 4 (`TdQuoteBody::Tdx15Ex`), but the
  verifier's measurement extraction only matched `Tdx10`/`Tdx15` and fell
  through to `unsupported TD quote body type`, so real TDX **v5** quotes failed
  verification after passing every cryptographic check. The remaining catch-all
  is now an explicit `Unknown` arm, so a future known body type is a compile
  error here rather than a runtime rejection.

- **TEE-only attestation sent an empty `runtimeData`.** Both
  `build_tee_only_payload()` and `build_tee_only_payload_from_evidence()`
  hardcoded `runtime_data = Vec::new()`, so the `runtimeData.data` field in the
  MAA platform request was always empty even though the runtime claims were
  available (`CvmEvidence::runtime_data`). MAA re-hashes this blob and compares
  it against the TEE report's `report_data`, so the binding could not be
  checked, and anything carried in the claims — including user data — never
  reached the relying party. The raw claim bytes are now forwarded verbatim
  (never re-serialized, since the hash covers the exact bytes).

- **User-data staging failures were silently ignored.** `get_cvm_report_raw()`
  logged a warning and continued when `ensure_user_data_index_and_write()`
  failed, then read the report anyway. Callers received a valid, hardware-signed
  report whose runtime claims carried stale or absent user data, with no
  indication their value had not been bound — a worse outcome than an error,
  since a relying party would accept the token. Staging failures are now
  returned as errors. This affects every `user_data` caller, including
  `cvm-report --user-data` and `tee-report --user-data`.

### Changed

- **`AttestationClient::attest_platform()` takes an options argument**
  (`Option<&PlatformAttestOptions>`). Pass `None` for the previous behavior.
- **`guest_attest::tee_only_attest_platform()` and `build_tee_only_payload()`
  take a `user_data: Option<&[u8]>` argument.** Pass `None` for the previous
  behavior.
- `attest_guest()` now returns an error when `user_data` is requested on a VM
  with no CVM evidence, instead of silently dropping it.
- **CLI `--json` `tcb` is derived from the MAA claims for SEV-SNP.** MAA reports
  only the granular SNP SVNs, so the CLI now renders the 8-byte AMD `TCB_VERSION`
  as big-endian hex (e.g. `DB18000000000004`) composed from
  `x-ms-sevsnpvm-{bootloader,tee,snpfw,microcode}-svn` instead of leaving `tcb`
  `null`. This matches the TCB string historically emitted by cvm-attestation-tools
  and used by ACC-VM-Tests as a grouping key. TDX continues to use
  `tdx_tee_tcb_svn`. Works at the top level and nested under `x-ms-isolation-tee`.

- **`azure-guest-attest` CLI 0.2.0 — pluggable crypto backend.** The CLI can now
  be built against platform crypto instead of the pure-Rust `ring`/`aes`/`sha1`
  crates (a compliance requirement). A new `native` feature routes TLS through
  `native-tls` (OpenSSL on Linux, SChannel on Windows) and AES-GCM / SHA-1
  through OpenSSL (Linux) / CNG-BCrypt (Windows). The shipped release binary is
  built with `--no-default-features --features native` and contains none of
  `ring`, `aes`, or `sha1`.
  - **Breaking (packaging):** the `native` Linux binary is **dynamically linked**
    against the system OpenSSL — the fully-static musl artifact is no longer
    produced. The Linux release asset moves from `x86_64-unknown-linux-musl` to
    `x86_64-unknown-linux-gnu` and requires `libssl`/`libcrypto` on the host.
    Windows uses the OS-provided SChannel/CNG (no extra runtime dependency).

### Added

- **Feature-gated crypto backends** in `azure-tpm` and
  `azure-guest-attestation-sdk`: `rustcrypto` (default, portable, pure-Rust,
  published to crates.io) and `native` (platform crypto). The published crates
  keep the pure-Rust default so downstream consumers are unaffected.
- **QGS `GET_QUOTE_RESP` unwrapping** in the TD quote parser. `parse_td_quote`
  now transparently detects and unwraps the Intel QGS response envelope
  (`qgs_msg_get_quote_resp_t`) that the TDX Quote Generation Service and
  MigTD / Service-TD "inbox" tooling emit, then parses the inner quote. A
  malformed or inconsistent envelope is rejected instead of silently
  mis-parsed. Exposed publicly as `unwrap_qgs_get_quote_response`.
- **TDX 1.5 extended Service-TD quote body** (`TdQuoteBodyTdx15Ex`, TD Quote
  Body type 4 / `sgx_report2_body_v1_5_ex_t`) carrying the migration-history
  fields (`td_id`, `vmid`, `devinfo`, init/current SERVTD hash & attributes).
- **Extended TDINFO** on the report side (`TdInfoExtensionV15Ex` /
  `tee_info_v1_5_ex_t`), surfaced via `TdReport::td_info_extension_v15_ex()`
  when the report type version is 3.

### Removed

- Unused `sha1` and `digest` dependencies from `azure-guest-attestation-sdk`,
  and the unused `reqwest` dependency and static-CRT `build.rs` from the CLI.

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
