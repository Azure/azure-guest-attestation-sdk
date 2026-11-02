# SymCrypt backend

The SDK and TPM crate offer three explicit crypto backends:

| Feature | Primitives | SDK HTTP TLS | Offline `verify` |
|---|---|---|---|
| `rustcrypto` (default) | RustCrypto | rustls / ring | Not supported |
| `native` | Existing OpenSSL / Windows CNG implementation | native-tls | OpenSSL / Windows crypt32 + CNG |
| `symcrypt` | SymCrypt | rustls / rustls-symcrypt | WebPKI path building with SymCrypt signatures |

The implementation and regression tests live in the
[SDK crypto module](../crates/azure-guest-attestation-sdk/src/crypto.rs),
[TPM crypto module](../crates/azure-tpm/src/crypto.rs),
[offline backend](../crates/azure-guest-attestation-sdk/src/verify/crypto/symcrypt.rs),
and [web TLS module](../tools/azure-guest-attest-web/src/tls_crypto.rs).

`native` retains precedence when combined with `rustcrypto`. **SymCrypt cannot
be combined with either backend.** Cargo features are additive: disable default
features on every SDK/TPM dependency and forward the same backend throughout the
application. The workspace tools all expose `symcrypt`.
The existing `native` option retains its RustCrypto SHA-2 and OS session-entropy
implementation in the TPM crate; it is not given SymCrypt's strict package
isolation contract by this change.

## Selecting an offline verification backend

SDK 0.2 introduces backend-neutral `verify`. Select either supported backend:

```sh
cargo test -p azure-guest-attestation-sdk --no-default-features --features native,verify
cargo test -p azure-guest-attestation-sdk --no-default-features --features symcrypt,verify
```

In a dependency declaration, set `default-features = false` and select
`features = ["native", "verify"]` or `["symcrypt", "verify"]`. Enabling `verify`
with only `rustcrypto` is a compile error, not an implicit switch to native.
The local-verification tool still defaults to `native`.

## Native prerequisite

SymCrypt is dynamically linked, **not bundled by the Rust crates**. The tested
native distribution is SymCrypt **103.13.0**, on Linux x64 and Windows x64, with
Rust 1.90 as the minimum supported compiler. The wrapper crates are
`symcrypt` 0.5.1 and `rustls-symcrypt` 0.2.3. See the
[official release](https://github.com/microsoft/SymCrypt/releases/tag/v103.13.0)
for native distributions and their license notices.

Verify the archive before extraction:

| Distribution | SHA-256 |
|---|---|
| `symcrypt-linux-generic-amd64-release-103.13.0-286762b.tar.gz` | `c3aa92e01a3c15e33b54ca3d5e49b62076a72d4e84b3b80e2f8f4d6877427269` |
| `symcrypt-windows-amd64-release-103.13.0-286762b7.zip` | `90ea7631331d23a43e0abc7f7af89b44bda67cfa183a70a8b76d988d9d3036b8` |

### Linux

After extracting the Linux archive into a trusted directory, configure both
the linker (including rustdoc's linker) and runtime loader:

```sh
export SYMCRYPT_DIR=/absolute/path/to/extracted/symcrypt
export LIBRARY_PATH="$SYMCRYPT_DIR/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$SYMCRYPT_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cargo build --workspace --no-default-features --features symcrypt
cargo test --workspace --no-default-features --features symcrypt
```

Preserve the versioned shared-library files/symlinks and license notices when
deploying. Alternatively, use the platform's trusted library installation and
loader configuration. `RUSTFLAGS="-L native=..."` alone does not configure
rustdoc's linker or the runtime loader.

### Windows

Use the directory containing **both** `symcrypt.lib` and `symcrypt.dll`:

```powershell
$env:SYMCRYPT_LIB_PATH = 'C:\trusted\symcrypt\dll'
$env:PATH = "$env:SYMCRYPT_LIB_PATH;$env:PATH"
foreach ($directory in @('target/debug', 'target/debug/deps')) {
    New-Item -ItemType Directory -Force $directory | Out-Null
    Copy-Item "$env:SYMCRYPT_LIB_PATH/symcrypt.dll" "$directory/symcrypt.dll" -Force
}
cargo build --workspace --no-default-features --features symcrypt
cargo test --workspace --no-default-features --features symcrypt
```

The example uses the default debug output directories. For release or custom
target directories, copy the DLL to the corresponding executable/test
directories. Deploy the verified `symcrypt.dll` next to each executable,
together with the distribution's license notices and required runtime
components. Recent Windows versions also provide a System32 SymCrypt DLL:
putting the downloaded DLL on PATH alone does not pin the runtime version,
because the system directory is searched before PATH. `SYMCRYPT_LIB_PATH`
configures linking, not runtime selection.

CI covers Windows-latest and Windows 2022 with app-local DLLs. Both reject an
invalid app-local DLL rather than falling through to a system copy. Both hosted
images provide a System32 DLL, so genuine absence is validated separately on a
Windows host without that OS runtime: the same SDK executable fails with
`STATUS_DLL_NOT_FOUND`. Static CRT flags for the Rust executable do **not** make
the SymCrypt DLL static or remove its own runtime dependencies.

Missing or incompatible native libraries cause link/load failure; there is no
automatic cryptographic fallback.

## Coverage and trust boundaries

- SymCrypt supplies AES-128/256-GCM, SHA-1 (legacy PCR replay), SHA-256,
  SHA-384, session entropy, ECDSA/RSA certificate signatures, and TLS crypto.
  TPM-resident operations still execute in the TPM.
- SDK HTTP clients configure their TLS provider explicitly, without installing
  a process-global provider. HTTPS trusts Mozilla WebPKI roots, while offline
  attestation verification trusts only the pinned AMD/Intel roots. These trust
  sets are separate.
- The web tool uses SymCrypt for TLS and self-signed certificate/key generation;
  saved PEM keys can be reloaded. Its existing non-SymCrypt HTTPS mode continues
  to use ring, including when its SDK calls select `native`.
- WebPKI validates certificate paths, signatures, validity, and name
  constraints. The attestation adapter additionally enforces issuer
  `keyCertSign` when KeyUsage is present, and the selected root's validity,
  CA status and path-length constraints. Unsupported critical root extensions
  are rejected. WebPKI's bounded path building and supported algorithms apply;
  this is not a general replacement for every OpenSSL certificate profile.
- AMD's explicit default PSS `trailerField=1` encoding is allowlisted only for
  SHA-384 / MGF1-SHA384 / 48-byte salt. Signed certificate bytes are not
  normalized or rewritten.
- Existing unchecked policies remain unchecked: no new revocation, minimum
  TCB, measurement authorization, freshness, or workload identity guarantees.
- Windows OS entropy (`BCryptGenRandom` / `ProcessPrng`) is permitted. CNG
  signature, certificate validation, and TLS fallback are not.
- Selecting SymCrypt does **not** assert FIPS certification or an approved
  deployment configuration.

SDK constructors that return `Self` panic if their HTTP client cannot be
initialized, like reqwest's infallible constructor. IMDS/MAA no longer retry
initialization with an untimed default client. Fallible operations propagate
initialization/request errors rather than selecting another backend.

CI checks the default backend separately, and runs SymCrypt workspace Clippy,
tests, production dependency/import audits, rejected-feature combinations, and
the Linux MSRV check. Test-only fixture generators may use other dependencies
in non-SymCrypt builds; the SymCrypt production dependency graph must not
contain OpenSSL, native-tls, ring, aws-lc, or RustCrypto hash/AES implementations.
