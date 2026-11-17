# SNP Verification

[Design index](README.md) | [Architecture overview](../ARCHITECTURE.md) |
[SDK usage](../crates/azure-guest-attestation-sdk/README.md) |
[Local verifier CLI](../tools/azure-guest-local-verify/README.md)

## Scope and Contract

With the `verify` feature, `verify::verify_snp_report()` checks a raw AMD
SEV-SNP report and a caller-supplied PEM certificate chain. Verification uses
OpenSSL on Linux and CNG/Crypt32 on Windows with `native`, or SymCrypt with
`symcrypt` (see [backend selection](symcrypt.md)). The production trust anchors are
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

The verifier accepts exactly 1,184 bytes and report versions 2 through 6. It
requires the legacy VCEK signer (selector 0), an unmasked nonzero chip ID, VMPL 0 through 3, and
signature algorithm 1. Reserved signer/policy bits, version-specific reserved
regions, and ECDSA component padding are validated.

These are format checks, not guest-policy approval. In particular, the
verifier does not require a particular DEBUG, SMT, migration, or mitigation
configuration. `platform_info` remains opaque and authenticated: applying a
reserved-bit mask from an older ABI would reject supported newer evidence.

`SnpReport` preserves its existing wire layout and reserved fields for source
compatibility. `cpuid()` exposes family/model/stepping in versions 3 through 6;
version 2 has no CPUID claim. `mitigation_vectors()` exposes launch/current
vectors in versions 5 and 6 without imposing required bits.

### Version 6

The layout follows [AMD 56860 revision 1.59, Table 27](https://docs.amd.com/v/u/en-US/56860_PUB_SEV_SNP)
(August 2026). Report size, signature algorithm, signature offset and signed
length are unchanged. `extended_tcb()` returns `Some(SnpExtendedTcb)` only for
v6, containing the raw 32-byte `current`, `launch` and `committed` ETCB claims
in wire order. Other versions return `None`; an absent field is not a zero claim.
The pretty-printer used by `tee-report` also displays CPUID, mitigation vectors
and ETCB when their report version defines them.

| Byte range | v6 meaning |
|---|---|
| `0x1f8..0x208` | Launch/current mitigation vectors, as in v5 |
| `0x208..0x220` | Reserved, required zero |
| `0x220..0x240` | CURRENT_ETCB |
| `0x240..0x260` | LAUNCH_ETCB |
| `0x260..0x280` | COMMITTED_ETCB |
| `0x280..0x2a0` | Reserved, required zero |

These are half-open byte ranges, based on the ABI's explicit offsets. The
Table 27 row at `0x208` labels bits `192:0`; the next field starts at `0x220`,
so the reserved byte span is 24 bytes, not 25.

ETCB is authenticated by the report signature, but remains opaque: this change
does not interpret processor-specific components, compare ETCB with certificate
extensions, enforce minimums or compare current/launch/committed values.
Legacy VCEK binding continues to use `reported_tcb`, never ETCB.

This is v6 support **within the existing guest/legacy-VCEK trust model**, not
support for every v6 signer or processor. Host-requested reports (VMPL
`0xffffffff`), chip-secret VCEK (selector 2), VLEK, and Venice/product mappings
outside the table below remain rejected. No AMD roots or trust policies are
added. Unknown report versions (including v7) remain rejected by verification.
Earlier versions retain their reserved-byte rules; v6 ETCB bytes cannot be
smuggled into a v2-v5 report.

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

The `snp_report_v6_synthetic.bin`, `snp_v6_synthetic_chain.pem` and
`snp_v6_synthetic_root.pem` fixtures are **synthetic**, not captured AMD evidence.
They were generated using fresh P-384 keys and SHA-384 ECDSA signatures, with
a test ARK -> `SEV-Milan` ASK -> `SEV-VCEK` chain (valid 2020 through 2049).
The leaf uses legacy Milan extension encodings, a synthetic chip ID `01..40`,
and `reported_tcb = 0xdb18000000000004`. The report has version 6, VMPL 0,
policy bit 17, patterned REPORTDATA/measurement, mitigation vectors
`0x1234`/`0x5678`, and three distinct nonzero ETCB byte patterns.
Private keys were not saved or committed. These deliberately exercise opaque
ETCB handling; they do not establish which ETCB values real Milan firmware emits.

All verification backends run the same synthetic-v6 signature/chain/binding
success test using a test-only explicit root. Every ETCB/vector byte is tampered
individually to prove signature coverage; every v6 reserved-gap byte is checked.
Freshly re-signed negative cases additionally exercise structural and binding
rejections on Linux/native. The production API and CLI reject the synthetic
chain, even if its root is supplied as collateral. No real v6 report/AMD chain
was supplied, so hardware interoperability remains unverified.

## Implementation Map

- [Report format and verifier](../crates/azure-guest-attestation-sdk/src/verify/snp.rs)
- [Private VCEK binding checks](../crates/azure-guest-attestation-sdk/src/verify/snp/vcek.rs)
- [Versioned report accessors](../crates/azure-guest-attestation-sdk/src/tee_report/snp.rs)
- [CLI regression tests](../tools/azure-guest-local-verify/tests/snp_cli.rs)