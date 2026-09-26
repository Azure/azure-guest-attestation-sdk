# Azure Guest Local Verify

Offline verification of Intel TDX quotes and AMD SEV-SNP reports against
pinned hardware roots. Supported on Linux (OpenSSL) and Windows (CNG/crypt32).

## TDX modes

- **Signature-only (default):** `azure-guest-local-verify tdx QUOTE` checks the
  quote signature, attestation-key binding, QE report signature, and PCK chain
  to the pinned Intel SGX Root CA. JSON explicitly reports
  `verification_scope: "signature_and_chain"`, `tcb_checked: false`, and no
  `tcb` object. `passed` means these signature/chain checks succeeded, **not**
  that TCB status, revocation, or migration policy was approved.
- **Authenticated TCB Info:** add `--endorsements PATH` for an OE flattened
  **x64** v4 TDX collateral bundle, or provide both `--tcb-info PATH` and
  `--tcb-issuer-chain PATH` (signed Intel TDX TCB Info JSON and PEM signing
  certificate chain). These input forms are mutually exclusive.
  JSON reports `verification_scope: "signature_and_chain_and_tcb_info"`.
  Only TCB Info and its issuer chain are consumed from the OE bundle.

Both bare and QGS-wrapped quotes are supported. Add `--json` before or after
the subcommand for machine-readable output.

### Time and baseline policy

`--verification-time SECONDS` selects a nonnegative Unix timestamp for
certificate validation and, when supplied, collateral freshness. It also
works in signature-only mode. The default is the current time, resolved once
and reported as `verification_time`. Historical validation is not evidence
of present freshness.

`--tcb-baseline-date SECONDS` requires collateral. This explicitly opts into
the SDK's certification-date relaxation: a matched TCB date at/after the
baseline can relax `OutOfDate` to `UpToDate`, or
`OutOfDateConfigurationNeeded` to `ConfigurationNeeded`. The latter still
fails the CLI's strict policy. A baseline never bypasses signatures,
certificate validity, or collateral expiration. The selected baseline is
reported as `tcb_baseline_date` (null by default).

### Acceptance and output

With authenticated collateral, `passed` is true **only** when the signature
checks succeed and **every** assessed status is `UpToDate`: `current`,
`launch`, `initial` (if present), and `aggregate_status`. A missing initial
assessment is allowed only when the signed `SERVTD_EXT` attribute does not
require it. Any degraded status or `NotEvaluated` fails, even if an aggregate
status alone appears acceptable.

- Exit **0**: accepted within the stated verification scope.
- Exit **2**: verification/policy rejection, input-read failure, or invalid CLI
  arguments. Argument errors are ordinary Clap diagnostics on stderr.
- A policy rejection retains the complete `tcb` object in JSON, including
  component `status`, `tcb_date`, and `reason`, plus `aggregate_status` and
  `aggregate_date`. Verified measurements and signature checks are retained.
  It is not reduced to an error string.
- Authentication, parsing, or freshness failures report `passed: false` and
  a fixed `error` message and `error_code`, without inventing an authenticated
  TCB assessment. Raw certificate/parser error chains and input paths are not
  printed. Codes are `input_not_found`, `permission_denied`, `invalid_input`,
  `invalid_evidence`, and `verification_failed`. Detailed programmatic errors
  remain available from the SDK; the CLI intentionally limits diagnostics.
- `tcb_checked` indicates that the authenticated assessment returned, **not**
  that all statuses passed. `verification_scope` names the requested checks,
  including on failure.

**Neither mode is complete Intel DCAP/QVL verification.** All TDX JSON
results explicitly report `complete_dcap_verification: false`,
`crl_checked: false`, and `qe_identity_checked: false`. Verifying the QE
report's signature is not evaluation of QE identity collateral. No CRL
revocation, QE identity, Service-TD hash allowlist, or migration-continuity
policy is evaluated. Applications must supply their own appropriate policy.

### Signed migration fields

For a Service-TD type-4 quote, both human and JSON `measurements` output add:

`tee_tcb_svn_2`, `mr_service_td`, `vmid`, `td_id`, `devinfo`,
`init_server_td_hash`, `init_server_td_attr`, `init_cpu_svn`,
`init_tee_tcb_svn`, `init_tee_fmspc`, `curr_server_td_hash`,
`curr_server_td_attr`, and `servtd_ext`.

Byte arrays use lowercase hex; `vmid` is a number and `servtd_ext` is a
boolean. `init_tee_fmspc` is a **12-byte initial-platform model encoding**,
not a raw six-byte Intel FMSPC. `init_tee_fmspc_model` additionally exposes
its three little-endian u32 `words` and word 1 as `cpuid_leaf1_eax`.
`servtd_ext` is derived from TD attributes bit 17 and determines whether
initial-platform fields apply. Merely displaying signed fields is not
migration-policy approval.

## Public fixture caveat

The SDK's read-only Open Enclave Service-TD quote and endorsements samples
have **no common valid verification time**: TCB Info is valid from
2024-07-15 until 2024-08-14, the TCB signing certificate starts in 2025, and
the quote's PCK certificate starts in 2026. Default collateral verification
therefore rejects the stale bundle. Selecting July 2024 cannot produce a
valid result because the certificates were not yet valid then.

Tests use Unix time `1790294400` to exercise valid quote signatures and
explicit expired-collateral rejection. Synthetic assessments test strict
status acceptance and rich JSON independently; they do not claim the stale
bundle passes authentication. Fresh, matching, signed collateral is needed
for a successful authenticated TCB assessment.

## SNP

`azure-guest-local-verify snp REPORT --vcek CHAIN` retains the existing SNP
verification flow and JSON measurements/checks. TDX-specific options do not
apply to SNP.

## Validation

Run `cargo fmt -p azure-guest-local-verify -- --check`,
`cargo test -p azure-guest-local-verify`, and
`cargo clippy -p azure-guest-local-verify --all-targets -- -D warnings`.