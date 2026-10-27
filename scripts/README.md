# Build and Utility Scripts

This directory contains utility scripts for the Azure Guest Attestation SDK.

## Scripts

### `setup.ps1` / `setup.sh`

Initial setup scripts for the development environment. Installs the Rust toolchain
and recommended tools (e.g. `cargo-nextest`).

**Windows:**

```powershell
.\scripts\setup.ps1
```

**Linux/macOS:**

```bash
./scripts/setup.sh
```

### `clean.ps1` / `clean.sh`

Removes build artifacts and verifies `.gitignore` configuration.

**Windows:**

```powershell
.\scripts\clean.ps1 [-DryRun] [-Verbose]
```

**Linux/macOS:**

```bash
./scripts/clean.sh [--dry-run] [--verbose]
```

**Options:**

- `-DryRun` / `--dry-run`: Show what would be cleaned without deleting
- `-Verbose` / `--verbose`: Show detailed output

### `build-all.ps1`

Windows-only unified build script that compiles all workspace crates.

```powershell
.\scripts\build-all.ps1 [-Clean] [-Release]
```

**Options:**

- `-Clean`: Clean all build artifacts before building
- `-Release`: Build in release mode (optimized)

On Linux/macOS, use `cargo build` directly (see root README).

## SDK and TPM Releases

The [SDK release workflow](../.github/workflows/release-sdk.yml) publishes
`azure-tpm` followed by `azure-guest-attestation-sdk`. It is separate from the
CLI release workflows and does not change or publish CLI versions.

One-time setup:

1. Create a GitHub environment named `crates-io`, require release approval,
   and restrict deployments to tags matching `azure-guest-attestation-sdk-v*`.
2. In the crates.io settings for **each** library crate, add a Trusted Publisher:
   owner `Azure`, repository `azure-guest-attestation-sdk`, workflow filename
   `release-sdk.yml`, environment `crates-io`.

To release:

1. Prepare matching SDK/TPM versions and the SDK's `azure-tpm` dependency on
   `release/<MAJOR>.<MINOR>.x`. Commit the manifests, lockfile, and changelog.
2. Tag that reviewed commit as `azure-guest-attestation-sdk-v<VERSION>` and
   push the branch and tag to the Azure upstream repository.
3. Wait for Linux/Windows validation and the MSRV, documentation, coverage,
   and dependency checks, then approve the `crates-io` deployment.
4. After publication succeeds, create the GitHub release for the SDK tag.
   A companion `azure-tpm-v<VERSION>` source tag may point to the same commit.

The workflow uses public Cargo 1.99.0 to package both libraries together
before either version is published; this does not change the Rust 1.90 MSRV.
Verified archives and checksums are retained as Actions artifacts **before**
requesting a short-lived crates.io token through GitHub OIDC. No long-lived
Cargo token or `CARGO_REGISTRY_TOKEN` repository secret is required.

[`publish-crate.sh`](./publish-crate.sh) verifies each registry checksum
after publication. A rerun accepts an already-published version only if its
archive checksum matches; network, authentication, malformed-index, yanked,
or mismatched-archive errors fail explicitly.

Test the helper without network access or registry credentials:

```bash
bash scripts/test-publish-crate.sh
```

## Build Artifacts

Build artifacts are placed in `target/` directories by Cargo:

- `target/debug/` — debug builds
- `target/release/` — release builds (`cargo build --release`)

## Git Ignore

All build artifacts are ignored by `.gitignore`:

- Rust `target/` directories
- Compiled binaries (`.dll`, `.so`, `.dylib`, `.pdb`)

Use the clean scripts to verify your `.gitignore` is working correctly.

## Development Workflow

1. **Initial setup**: Run `setup.ps1` or `setup.sh`
2. **Build**: `cargo build` (or `cargo build --release`)
3. **Test**: `RUSTFLAGS="--cfg vtpm_tests" cargo nt` (nextest with vTPM) or `cargo vt` (built-in runner)
4. **Lint**: `cargo clippy -p azure-guest-attestation-sdk --all-targets -- -D warnings`
5. **Cleanup**: Run `clean.ps1` or `clean.sh` to remove artifacts

## Requirements

### Windows

- PowerShell 5.1 or later
- Rust/Cargo (via [rustup](https://rustup.rs/))
- Visual Studio Build Tools with C++ workload
- Perl ([Strawberry Perl](https://strawberryperl.com/)) for vTPM tests

### Linux/macOS

- Bash
- Rust/Cargo (via [rustup](https://rustup.rs/))
- Build essentials (`build-essential` / `gcc`, `make`, `perl`)
