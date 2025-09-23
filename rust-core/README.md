# Rust core skeleton for Azure CVM Attestation SDK

## Build (Linux / Windows):

- Install Rust toolchain (stable) and `cargo`.
- Build the cdylib artifact:

  cargo build --release

- Release artifacts are under `target/<target-triple>/release/`:
  - Linux: `libazure_cvm_tpm_sdk.so`
  - Windows: `azure_cvm_tpm_sdk.dll`

## Generating header with cbindgen (optional):

- Install `cbindgen` and run from `rust-core`:

``` Shell
cbindgen --config cbindgen.toml --crate azure_cvm_tpm_sdk --output include/azure_cvm_attestation.h
```

## Notes

- The crate exposes a thin C-compatible ABI that callers can link against. The SDK allocates returned buffers using `libc::malloc` and provides `azure_cvm_attestation_free_buffer` to free them.
- For Windows consumers, prefer using the SDK-provided deallocator to avoid CRT mismatches.

## Developer setup

- On Windows (PowerShell): run `scripts\setup.ps1` from a PowerShell prompt.
- On Linux/macOS (bash): run `scripts/setup.sh`.

These scripts will install `rustup` (if missing), ensure the stable toolchain, and install `cbindgen` used to generate the C header.
