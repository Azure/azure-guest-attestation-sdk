# SNP Verification

[Design index](README.md) | [Architecture overview](../ARCHITECTURE.md) |
[SDK usage](../crates/azure-guest-attestation-sdk/README.md) |
[Local verifier CLI](../tools/azure-guest-local-verify/README.md)

## Scope and Contract

With the `verify` feature, `verify::verify_snp_report()` checks a raw AMD
SEV-SNP report and a caller-supplied PEM certificate chain. Verification uses
OpenSSL on Linux and CNG/Crypt32 on Windows. The production trust anchors are
the SDK's pinned AMD ARK certificates, not roots supplied with the evidence.

A successful result establishes supported report structure, report signature,
certificate-chain validity, and VCEK bindings to the authenticated report.
`SnpVerifyResult::vcek_binding_valid` reports that binding success. It does not
mean that a relying party should accept the workload or its security posture.

## Verification Flow

1. Require the exact report size and validate supported wire-format invariants.
2. Parse the supplied VCEK leaf and issuer certificates. Validate the leaf's
   chain against pinned AMD roots; supplied self-signed certificates do not
   become trust anchors.
3. Verify the report signature with that leaf: ECDSA P-384/SHA-384 over the
   first `0x2a0` bytes. Signature components are little-endian on the wire.
4. Inspect the DER of the same authenticated leaf for its VCEK role, named
   P-384 key, product generation, reported TCB components, and hardware ID.
5. Return the authenticated measurements and completed-check flags.

The binding validator is private and assumes that chain and report signature
verification have already succeeded. It never establishes trust from issuer
names or unsigned extension data alone.

## Report Structure

The verifier accepts exactly 1,184 bytes and report versions 2 through 5. It
requires the VCEK signer, an unmasked nonzero chip ID, VMPL 0 through 3, and
signature algorithm 1. Reserved signer/policy bits, version-specific reserved
regions, and ECDSA component padding are validated.

These are format checks, not guest-policy approval. In particular, the
verifier does not require a particular DEBUG, SMT, migration, or mitigation
configuration. `platform_info` remains opaque and authenticated: applying a
reserved-bit mask from an older ABI would reject supported newer evidence.

`SnpReport` preserves its existing wire layout and reserved fields for source
compatibility. `cpuid()` exposes family/model/stepping in versions 3 through 5;
version 2 has no CPUID claim. `mitigation_vectors()` exposes launch/current
vectors only in version 5 without imposing required bits.

`parse::snp_report()` remains a permissive inspection API. Parsing alone is
not verification and must not be used as evidence acceptance.

## VCEK Binding

The leaf must have the VCEK subject role, the expected generation-specific
issuer name, and an EC public key using named curve `secp384r1`. Malformed or
duplicate extensions, missing required AMD extensions, and unsupported AMD
extensions are rejected. Present standard extensions must not designate the
leaf as a CA or permit certificate signing instead of document signing.

The supported generation mappings are intentionally explicit:

| Generation | CPUID family/model (hex) | Accepted ProductName | structVersion | HWID binding |
|---|---|---|---|---|
| Milan | `19/01` | `Milan-B0`, `Milan-B1` | 0 | All 64 chip-ID bytes |
| Genoa | `19/11` | `Genoa`, `Genoa-B0`, `Genoa-B1`, `Genoa-B2` | 0 | All 64 chip-ID bytes |
| Turin | `1a/02` | `Turin`, `Turin-B0`, `Turin-B1` | 1 | First 8 chip-ID bytes; remaining 56 must be zero |

For version 2, generation comes from the authenticated certificate because
the report has no CPUID fields. For later versions, the report's family/model
must match the certificate generation. Product suffixes are not equated with
CPUID stepping; stepping is only range-checked.

`reported_tcb` must match the VCEK's component extensions exactly:

| Layout | Byte mapping in little-endian `reported_tcb` |
|---|---|
| Milan/Genoa | Bootloader 0, TEE 1, SNP 6, microcode 7; bytes 2 through 5 reserved |
| Turin | FMC 0, bootloader 1, TEE 2, SNP 3, microcode 7; bytes 4 through 6 reserved |

TCB extension integers must use canonical DER encodings in `0..=255`.
`current_tcb`, `committed_tcb`, and `launch_tcb` are not substituted for
`reported_tcb` when binding the signing key. VLEK and masked chip IDs are not
supported by this verifier.

## Relying-Party Responsibilities

The verifier does not evaluate:

- Certificate revocation or minimum acceptable TCB levels.
- Expected nonce/REPORTDATA, workload measurements, or trusted ID/author keys.
- Required guest policy, platform configuration, or mitigation bits.
- Migration authorization or continuity.
- Certificate-backed CPUID stepping equivalence.

The CLI makes this boundary explicit with
`verification_scope: "structure_signature_chain_and_vcek_binding"` and false
`policy_checked`, `crl_checked`, and `cpuid_stepping_checked` flags. SNP failures
use fixed diagnostic categories instead of printing raw certificate/parser
errors or input paths.

## Compatibility

These mandatory structural and binding checks tighten the existing verifier:
evidence that previously passed signature-only verification may now fail.
The change does not add direct `/dev/sev-guest` collection, a runtime
certificate-fetching path, or a relying-party policy engine.

## Test Strategy

One shared real-evidence table covers Milan v3, Genoa v3, and Turin v5. Each
platform runs the same signature/chain/binding success checks and golden
measurement assertions, signed-field tampering, size/padding rejection,
untrusted-root rejection, and cross-platform chain-mismatch tests.

The same table drives VCEK binding cases for reported TCB, HWID, CPUID,
structVersion, required extensions, and duplicates. Generation differences
are explicit fixture metadata rather than assumptions about fixture order.
CLI tests exercise all three platforms and every mismatched platform pair.

Synthetic signed reports and certificates test authenticated negative paths
with test-only roots on Linux. Those roots are not accepted by the production
API. Native Windows tests use real evidence and shared binding tests to cover
the CNG/Crypt32 path.

## Implementation Map

- [Report format and verifier](../crates/azure-guest-attestation-sdk/src/verify/snp.rs)
- [Private VCEK binding checks](../crates/azure-guest-attestation-sdk/src/verify/snp/vcek.rs)
- [Versioned report accessors](../crates/azure-guest-attestation-sdk/src/tee_report/snp.rs)
- [CLI regression tests](../tools/azure-guest-local-verify/tests/snp_cli.rs)