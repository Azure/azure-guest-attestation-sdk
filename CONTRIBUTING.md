# Contributing to Azure Guest Attestation SDK

Thank you for your interest in contributing to the Azure Guest Attestation SDK!

## Getting Started

### Prerequisites

- **Rust**: Install via [rustup](https://rustup.rs/) (stable toolchain, MSRV 1.94)
- **cargo-nextest** (recommended): `cargo install cargo-nextest`
- **Perl**: Required for vTPM tests (vendored OpenSSL build) –
  [Strawberry Perl](https://strawberryperl.com/) on Windows
- **Platform Tools**:
  - Windows: Visual Studio Build Tools with C++ workload
  - Linux: `build-essential` (or equivalent: `gcc`, `make`, `perl`)

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Azure/azure-guest-attestation-sdk.git
   cd azure-guest-attestation-sdk
   ```

2. Run the setup script:
   ```powershell
   # Windows
   .\scripts\setup.ps1

   # Linux/macOS
   ./scripts/setup.sh
   ```

3. Build and test:
   ```bash
   cargo build
   cargo nt          # runs nextest with vTPM (see below)
   ```

### Running Tests

The project uses the **Microsoft TPM 2.0 Reference Implementation** (`ms-tpm-20-ref`)
as an in-process virtual TPM. This is enabled by the `vtpm-tests` Cargo feature.

#### Recommended: cargo-nextest

[cargo-nextest](https://nexte.st/) runs each test as a **separate process**, so
each test gets its own reference TPM instance and all tests execute fully in parallel.

```bash
# Quick alias (defined in .cargo/config.toml)
cargo nt

# Explicit form
cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests

# CI profile (with retries)
cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests --profile ci
```

#### Fallback: cargo test

The built-in `cargo test` runner shares a single process for all tests.
The reference TPM uses a process-global singleton serialized via Mutex,
so multi-threaded execution is safe (no `--test-threads=1` required).

```bash
# Quick alias
cargo vt

# Explicit form
cargo test -p azure-guest-attestation-sdk --features vtpm-tests --lib
```

#### Unit tests only (no vTPM)

```bash
cargo test -p azure-guest-attestation-sdk --lib
```

#### Lints & formatting

```bash
cargo clippy -p azure-guest-attestation-sdk -- -D warnings
cargo fmt -- --check
```

#### vTPM Threading Model

The reference TPM (`ms-tpm-20-ref`) wraps global C state that can only be
initialized once per process. The SDK handles this transparently:

| Runner | Isolation | Parallelism |
|--------|-----------|-------------|
| `cargo nextest` | process-per-test | fully parallel |
| `cargo test` | shared singleton + Mutex | safe, serialized |

Tests use **distinct NV index ranges** to avoid state conflicts when sharing
a single TPM instance within `cargo test`.

## Code Guidelines

### Style

- Follow standard Rust formatting (`cargo fmt`)
- Use `cargo clippy` and address all warnings
- Add rustdoc comments for all public items
- Include license headers in all source files:
  ```rust
  // Copyright (c) Microsoft Corporation.
  // Licensed under the MIT License.
  ```

### Testing

- Add tests for new functionality
- Use descriptive test names with appropriate prefixes:
  - `vtpm_*` for vTPM integration tests (require `vtpm-tests` feature)
  - Descriptive names for pure unit tests
- Gate vTPM tests with `#[cfg(all(test, feature = "vtpm-tests"))]`
- Use **unique NV index values** (e.g. `0x0150_XXXX`) to avoid collisions
  with other tests sharing the same TPM instance

### Commit Messages

- Use clear, descriptive commit messages
- Reference issues when applicable: `Fixes #123`

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with appropriate tests
4. Ensure all tests pass: `cargo nt`
5. Run lints: `cargo clippy -p azure-guest-attestation-sdk -- -D warnings`
6. Submit a pull request with a clear description

## Security

Please report security vulnerabilities according to our [Security Policy](SECURITY.md).

## Code of Conduct

This project follows the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
