# Public verification fixtures

The following files are copied from Open Enclave SDK at commit
`fe278675e6c28e25231eaf3742e63fd51512650b` (PR #5108), under the MIT license
in [OPENENCLAVE-LICENSE.txt](OPENENCLAVE-LICENSE.txt):

| Local file | Source under https://github.com/openenclave/openenclave | SHA-256 |
|---|---|---|
| oe_tdx_v5_servtd_quote.bin | tests/host_verify/data/tdx_quote_v5_servtd.bin | ac7f48ff048a46a15ed34405c3fc03f33cb49894b5d59821c81fa8f4c4c4d694 |
| oe_tdx_v5_servtd_endorsements.bin | tests/secure_verify/data/tdx_quote_v5_servtd_endorsement.bin | d29ca62616ea06005466ba600292d8e6f2cb29257ae2797469bda699015fe4e9 |

The quote is raw TDX v5, type 4 (885-byte Service-TD extension body).
The endorsement file is OE's flattened x64 collateral structure, not a quote
or TDREPORT. Its stored pointer values are ignored; sections are sliced with
checked lengths. This encoding is accepted only as the documented x64 format.

The TCB Info is valid 2024-07-15 through 2024-08-14, and **is expired today**.
Its accompanying TCB signing certificate starts 2025-05-06 and its quote's PCK
certificate starts 2026-07-10. **No common verification time makes this bundle
valid.** Tests authenticate signatures at a September 2026 certificate-valid
time, test TCB matching separately, and require the full API to reject stale
collateral. A separate synthetic signed document tests the successful full path
with test-only trust roots. Production always uses the pinned Intel root.

This is not a full Intel QVL result: CRLs and QE identity are not evaluated by
this SDK's TCB Info assessment. The bundle's QE identity has a different validity
window again (September–October 2024).

References: https://github.com/openenclave/openenclave/pull/5094 and
https://github.com/openenclave/openenclave/pull/5108.