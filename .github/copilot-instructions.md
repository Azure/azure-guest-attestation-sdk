# Copilot Agent Instructions — Azure Guest Attestation SDK

These instructions apply to **every AI agent session** working on this
repository, regardless of platform (Linux, Windows, macOS) or context window
state.  Read this file in its entirety before making any changes.

---

## 1. Repository Overview

| Item | Value |
|------|-------|
| Language | Rust (edition 2021) |
| MSRV | **1.94** — every change must compile on Rust 1.94 |
| Workspace members | `crates/azure-tpm` (TPM crate), `crates/azure-guest-attestation-sdk` (SDK), `tools/azure-guest-attest` (CLI), `tools/azure-guest-attest-web` (Web tool) |
| CI | `.github/workflows/ci.yml` — runs on **both** `ubuntu-latest` and `windows-latest` |
| Pre-commit hook | `.githooks/pre-commit` — must mirror CI flags exactly |

## 2. CI Checks — The Single Source of Truth

Every commit **must** pass all of the following before push.  These are the
**exact** commands CI runs.  Do not invent variations.

> **Path filtering**: CI uses `dorny/paths-filter` to skip expensive jobs
> (clippy, test, vtpm-tests, msrv, docs, coverage) on PRs that only touch
> non-code files (markdown, scripts, etc.).  Push to `main` always runs
> everything.  The `fmt` job always runs.  Code paths that trigger the full
> suite: `crates/**`, `tools/**`, `Cargo.toml`, `Cargo.lock`,
> `rust-toolchain.toml`, `.github/workflows/ci.yml`.

### 2.1 Format

```bash
cargo fmt --all -- --check
```

### 2.2 Clippy (runs on Linux AND Windows)

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

> **Critical**: Do NOT use `--all-features`.  CI does not pass
> `--all-features` to clippy.  The `vtpm-tests` feature pulls
> `ms-tpm-20-ref` (vendored OpenSSL) which requires Perl and a C toolchain;
> adding `--all-features` will fail on runners that lack those.

### 2.3 Unit tests — no vTPM (runs on Linux AND Windows)

```bash
cargo test --workspace
```

> **No** `--features`, **no** `--test-threads=1`.  Tests must be
> safe to run in parallel across threads.

### 2.4 vTPM integration tests (runs on Linux AND Windows)

```bash
cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests
```

### 2.5 MSRV check (Linux only)

```bash
cargo +1.94 check --workspace
```

> Dev-dependencies are excluded from `cargo check`, so newer crates like
> `injectorpp` are fine as long as the main code compiles on 1.94.

### 2.6 Docs

```bash
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps
```

### 2.7 Coverage (Linux only)

```bash
cargo llvm-cov --workspace --features vtpm-tests \
  --ignore-filename-regex '(src/lib\.rs|azure-guest-attest/src/main\.rs)$' \
  --fail-under-lines 60
```

## 3. Pre-Commit Hook

The hook at `.githooks/pre-commit` **must** mirror the CI clippy flags:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

If you edit the hook, keep it in sync with §2.2 above.  Never add
`--all-features` to the hook.

## 4. Cross-Platform Rules

CI tests on **both Linux and Windows**.  Every change must work on both.

| Rule | Details |
|------|---------|
| No Unix-only paths | Use `std::path` / `std::env::consts::OS` — never hardcode `/dev/...` outside `#[cfg(unix)]` |
| No Unix-only APIs | `io::Error::other()` requires Rust ≥ 1.74 — OK for MSRV 1.94 |
| Windows `#[cfg]` | Windows-specific code must be gated with `#[cfg(target_os = "windows")]` |
| Line endings | The repo uses LF (`.gitattributes`). Don't introduce CRLF. |
| Dev-dependencies | Must compile on **all** CI platforms (Linux + Windows). If a dev-dep is platform-specific, gate its usage with `#[cfg(...)]` |

## 5. Feature Flags

| Feature | Purpose | When to gate |
|---------|---------|--------------|
| `vtpm-tests` | Pulls `ms-tpm-20-ref` + `getrandom` for in-process reference TPM | Gate test code that calls `Tpm::open_reference_for_tests()` with `#[cfg(feature = "vtpm-tests")]` |
| (none / default) | Normal SDK functionality | CI clippy + unit tests run without any features |

> **Key invariant**: `cargo clippy --workspace --all-targets` and
> `cargo test --workspace` (without `--features`) must succeed.  All test
> code that requires `vtpm-tests` must be gated.

## 6. Testing Conventions

### 6.1 Test naming

- Pure unit tests: descriptive name (`parse_version_pair_major_minor`)
- vTPM integration tests: prefix `vtpm_` and gate with `#[cfg(feature = "vtpm-tests")]`
- Injectorpp (mocked) tests: no special prefix; use `unsafe { ... }` blocks for `_unchecked` API

### 6.2 Injectorpp (runtime mocking)

The SDK uses `injectorpp` (dev-dependency) for runtime function mocking.

**Required workspace settings** (already in root `Cargo.toml`):
```toml
[profile.test]
opt-level = 0
debug = true
lto = false
codegen-units = 1
incremental = false
```

**API pattern** (use the unchecked API for methods with complex signatures):
```rust
fn fake_some_method(_self: &SomeStruct, _arg: &str) -> io::Result<Vec<u8>> {
    Ok(b"mocked".to_vec())
}

#[test]
fn test_with_mock() {
    use injectorpp::interface::injector::*;
    let mut injector = InjectorPP::new();
    unsafe {
        injector
            .when_called_unchecked(injectorpp::func_unchecked!(SomeStruct::method))
            .will_execute_raw_unchecked(injectorpp::func_unchecked!(fake_some_method));
    }
    // ... test code that exercises the mocked path ...
}
```

**Rules**:
- Fake functions must be declared as **standalone `fn` items** (not closures)
  with the exact same signature as the target method (including `&self` as
  first param).
- The injector variable must stay alive (not dropped) for the duration of
  the test — dropping it restores the original function.
- injectorpp patches process-global memory, so tests that mock the **same
  function** must not run in parallel.  `cargo test` may interleave them;
  `cargo nextest` gives each test its own process.
- injectorpp supports Linux, macOS, and Windows.

### 6.3 Thread safety

CI runs `cargo test --workspace` without `--test-threads=1`.  Tests must be
safe to run in parallel **unless** they use injectorpp to mock the same
function, in which case the mocking scope should be as narrow as possible.

### 6.4 NV index ranges

vTPM tests that write NV indices must use **distinct index values** to avoid
collisions when sharing a reference TPM instance (e.g. `0x0150_XXXX`).

## 7. Code Style

- Run `cargo fmt` before committing.
- License header on every `.rs` file:
  ```rust
  // Copyright (c) Microsoft Corporation.
  // Licensed under the MIT License.
  ```
- Rustdoc comments on all public items.
- Use `tracing::info!` / `tracing::debug!` (not `println!`) for diagnostics.

## 8. Git Workflow

- Each task gets its own branch (e.g. `snp_fix`, `injector`, `test_coverage`).
- Commit messages: concise summary line, blank line, bullet-point body.
- The pre-commit hook runs fmt + clippy automatically.  If the hook fails,
  fix the issues before committing — do not bypass it.
- Only stage files relevant to the current change.  Do not stage unrelated
  files, coverage artifacts, embedded git repos, etc.

## 9. Verifying Before Push — Checklist

Run these in order.  All must pass:

```bash
# 1. Format
cargo fmt --all -- --check

# 2. Clippy (matches CI exactly)
cargo clippy --workspace --all-targets -- -D warnings

# 3. Unit tests (no features, parallel)
cargo test --workspace

# 4. MSRV (if Rust 1.94 toolchain is installed)
cargo +1.94 check --workspace
```

If you have `vtpm-tests` prerequisites (Perl, C toolchain):
```bash
# 5. vTPM tests
cargo nextest run -p azure-guest-attestation-sdk --features vtpm-tests
```

## 10. What Cannot Be Unit-Tested

Some code paths require real hardware or network and cannot be covered by
unit tests or injectorpp mocking:

| Category | Reason |
|----------|--------|
| `Tpm::open()` | Needs `/dev/tpmrm0` or Windows TBS |
| `AttestationClient::attest_guest()` / `attest_platform()` | Needs `Tpm` instance (private inner) |
| `ImdsClient` HTTP body parsing | `reqwest::Response` has no public constructor |
| `MaaProvider::attest_guest()` / `submit_tee_only()` | Creates `reqwest::Client` internally |
| Windows `#[cfg]` blocks on Linux CI | Structurally unreachable |

These are covered by:
- `vtpm-tests` feature (reference TPM)
- Manual testing on real CVM hardware
- Integration test environments

## 11. Resuming After Context Compaction

If your context window was compacted and you lost history:

1. **Read this file first** — it contains all the rules.
2. **Read `.github/workflows/ci.yml`** — it is the ground truth for CI.
3. **Read `.githooks/pre-commit`** — must match CI clippy flags.
4. **Check `git log --oneline -20`** — understand recent changes.
5. **Check `git branch`** — know which branch you're on.
6. **Never guess CI flags** — look them up from ci.yml every time.
