# Azure CVM Attestation SDK

## Building the Rust core

This repository contains a Rust core library under `rust-core/`. The following steps explain how to prepare your environment and build the Rust portion of the project.

### Prerequisites

- Rust toolchain (install via [rustup](https://www.rust-lang.org/tools/install))
- On Windows: Visual Studio Build Tools (MSVC) if you plan to build the MSVC target. Install the "Desktop development with C++" workload. Alternatively you can use the GNU toolchain (MinGW) if preferred.
- `cbindgen` (optional) if you want to regenerate the C header: `cargo install cbindgen`

### Quick start (recommended)

1. Run the provided setup script to install `rustup` and `cbindgen` (Windows PowerShell):

   ```powershell
   .\scripts\setup.ps1
   ```

   After the script finishes you may need to close and re-open your shell so the Cargo bin (`%USERPROFILE%\.cargo\bin`) is added to your PATH.

2. Build the Rust core in release mode:

   ```powershell
   cd rust-core
   cargo build --release
   ```

   Build artifacts are written to `rust-core/target/release/`. The produced native library will be named according to the platform (for example: `libazure_cvm_attestation.so`, `libazure_cvm_attestation.dylib`, or `azure_cvm_attestation.dll`).

### Regenerate the C header with cbindgen (optional)

From the repository root or from the `rust-core` directory, run:

```bash
# from rust-core/
cd rust-core
cbindgen --config cbindgen.toml -l C -o include/azure_cvm_attestation.h
```

This will update `rust-core/include/azure_cvm_attestation.h` based on the public Rust API and the provided `cbindgen.toml` configuration.

### Cross-compilation and targets

- To build for a different target, install the target with rustup and pass `--target` to cargo. Example (Windows MSVC x64):

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

### Troubleshooting

- If `rustup` or `cargo` are not found after running the setup script, close and re-open your terminal or add `%USERPROFILE%\.cargo\bin` to your PATH in the current session:

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
```

- On Windows, if linking fails or you see MSVC-related errors, ensure the Visual Studio Build Tools are installed with the C++ workload and that you have opened a developer command prompt or a shell with MSVC environment variables available.


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
