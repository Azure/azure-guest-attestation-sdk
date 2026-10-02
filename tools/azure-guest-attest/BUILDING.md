# Building azure-guest-attest

Run the following commands from the repository root.

## Standard Build

```powershell
cargo build --locked --release -p azure-guest-attest
```

## Static CRT Build (Windows MSVC)

### Prerequisites

- Rust 1.90 or newer with the `x86_64-pc-windows-msvc` target installed.
- Visual Studio or Visual Studio Build Tools with the C++ build tools and
  Windows SDK installed.

The workspace already enables static CRT linking for Windows MSVC targets in
[`.cargo/config.toml`](../../.cargo/config.toml):

```toml
[target.'cfg(all(target_os = "windows", target_env = "msvc"))']
rustflags = ["-Ctarget-feature=+crt-static"]
```

This applies to all MSVC builds in this workspace, including the standard build
above. No `static` Cargo feature or build-script flags are needed; the CLI has
neither a `static` feature nor a build script.

Build the Windows x64 release binary explicitly:

```powershell
cargo build --locked --release -p azure-guest-attest --target x86_64-pc-windows-msvc
```

The default crypto/TLS backend is `rustcrypto` with rustls. Static CRT linking
is independent of that feature selection.

**Environment overrides:** `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`, if set,
take precedence over the workspace rustflags. Unset them to use the workspace
configuration, or include `-Ctarget-feature=+crt-static` alongside any other
flags you need.

The workspace's static CRT configuration only applies to MSVC targets, not
GNU/MinGW. There is no build script that automatically adds `-static` or
`-static-libgcc` for GNU/MinGW.

### Verification

Test the binary produced by the explicit-target command:

```powershell
.\target\x86_64-pc-windows-msvc\release\azure-guest-attest.exe --version
```

From a Visual Studio Developer PowerShell with `dumpbin` on `PATH`, inspect
its DLL dependencies:

```powershell
dumpbin /DEPENDENTS .\target\x86_64-pc-windows-msvc\release\azure-guest-attest.exe
```

The dependency list should not contain dynamic CRT DLLs such as
`VCRUNTIME140.dll`, `MSVCP140.dll`, `ucrtbase.dll`, or `api-ms-win-crt-*.dll`.
Windows system DLLs such as `kernel32.dll`, `bcrypt.dll`, and `tbs.dll` are
still expected: static CRT linking does not produce a binary with no DLL
dependencies.

When building with the standard command on a Windows MSVC host without
`--target` or a configured default target, the binary is instead at
`target\release\azure-guest-attest.exe`. These paths assume the default Cargo
target directory (no `CARGO_TARGET_DIR` or `build.target-dir` override).

### Benefits and Trade-offs

- No Visual C++ Redistributable installation is required.
- Slightly larger binary size
- Each binary includes its own copy of the CRT and must be rebuilt to pick up
  CRT updates rather than benefiting from shared runtime updates.
