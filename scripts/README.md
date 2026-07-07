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
