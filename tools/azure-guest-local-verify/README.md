# Azure Guest Local Verify

Offline verification of Intel TDX quotes and AMD SEV-SNP reports against
pinned hardware roots. Supported on Linux (OpenSSL) and Windows (CNG/crypt32).

## TDX

`azure-guest-local-verify tdx QUOTE` retains upstream's signature and PCK-chain
verification for bare and QGS-wrapped quotes. It does not appraise Intel TCB
Info, QE identity, revocation, or migration policy.

## SNP

`azure-guest-local-verify snp REPORT --vcek CHAIN` now requires supported SNP
report structure, chain/signature validity, and VCEK role/product/TCB/HWID
bindings. JSON adds `checks["VCEK report binding"]` and
`verification_scope: "structure_signature_chain_and_vcek_binding"`.

`passed: true` does **not** mean acceptance policy or revocation passed:
`policy_checked`, `crl_checked`, and `cpuid_stepping_checked` are false.
Acceptance policy remains the caller's responsibility. See the
[SNP verification design](../../doc/snp-verification.md) for binding rules,
compatibility, and unchecked policy details.

Add `--json` for machine-readable output. SNP verification returns exit 0 on
success and 2 on invalid evidence, mismatched collateral, or input-read failure.
SNP failures use fixed `error` messages and `error_code` categories; raw
certificate/parser error contents and paths are not printed.

## Validation

Run `cargo fmt -p azure-guest-local-verify -- --check`,
`cargo test -p azure-guest-local-verify`, and
`cargo clippy -p azure-guest-local-verify --all-targets -- -D warnings`.