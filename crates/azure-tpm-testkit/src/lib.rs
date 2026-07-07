// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! In-process reference TPM test harness for [`azure_tpm`].
//!
//! This crate is **not published**. It exists solely to back unit and
//! integration tests with the Microsoft TPM 2.0 Reference Implementation
//! ([`ms_tpm_20_ref`]), which is pulled from git and builds a vendored
//! OpenSSL. Keeping it out of the `azure-tpm` and
//! `azure-guest-attestation-sdk` dependency graphs is what allows those
//! crates to be published to crates.io.
//!
//! Tests activate this harness with the custom `--cfg vtpm_tests` flag:
//!
//! ```bash
//! RUSTFLAGS="--cfg vtpm_tests" \
//!   cargo nextest run -p azure-guest-attestation-sdk
//! ```
//!
//! # Threading model
//!
//! The reference implementation uses global C state internally, so only
//! **one** instance may exist per process. We therefore keep a
//! process-global singleton behind [`OnceLock`] and serialize all command
//! execution through a [`Mutex`].
//!
//! | Runner | Isolation | Parallelism |
//! |--------|-----------|-------------|
//! | `cargo nextest` (recommended) | process-per-test | fully parallel – each process gets its own singleton |
//! | `cargo test -- --test-threads=1` | single process, sequential | safe – one test at a time |
//! | `cargo test` (multi-threaded) | single process, shared singleton | safe – Mutex serializes access |

use azure_tpm::{RawTpm, Tpm};
use std::io;
use std::sync::{Mutex, OnceLock};

/// Lightweight handle to the shared in-process reference TPM.
///
/// The actual TPM state lives in a process-global `OnceLock<Mutex<…>>`;
/// multiple handles can coexist and all transmit calls are serialized by
/// the inner mutex.
struct RefTpm;

/// Process-global shared TPM state, initialized exactly once.
static SHARED_STATE: OnceLock<Mutex<ms_tpm_20_ref::MsTpm20RefPlatform>> = OnceLock::new();

/// Initialize the singleton reference TPM (cold-init + `TPM2_Startup(Clear)`).
///
/// Panics on failure — acceptable because this is only used from tests.
fn init_shared_state() -> Mutex<ms_tpm_20_ref::MsTpm20RefPlatform> {
    use ms_tpm_20_ref::{DynResult, InitKind, MsTpm20RefPlatform, PlatformCallbacks};
    use std::time::Instant;

    struct TestPlatform {
        nv: Vec<u8>,
        start: Instant,
    }
    impl PlatformCallbacks for TestPlatform {
        fn commit_nv_state(&mut self, state: &[u8]) -> DynResult<()> {
            self.nv = state.to_vec();
            Ok(())
        }
        fn get_crypt_random(&mut self, buf: &mut [u8]) -> DynResult<usize> {
            getrandom::getrandom(buf).unwrap();
            Ok(buf.len())
        }
        fn monotonic_timer(&mut self) -> std::time::Duration {
            self.start.elapsed()
        }
        fn get_unique_value(&self) -> &'static [u8] {
            b"cvm-ref-tpm"
        }
    }

    let platform = Box::new(TestPlatform {
        nv: vec![],
        start: Instant::now(),
    });
    let mut inner = MsTpm20RefPlatform::initialize(platform, InitKind::ColdInit)
        .expect("reference TPM initialization failed");

    // Issue TPM2_Startup(Clear)
    let startup = [0x80u8, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 0];
    let mut req = startup.to_vec();
    let mut buf = [0u8; 8192];
    let _ = inner
        .execute_command(&mut req, &mut buf)
        .expect("reference TPM startup failed");

    Mutex::new(inner)
}

impl RawTpm for RefTpm {
    fn transmit_raw(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        let state = SHARED_STATE.get_or_init(init_shared_state);
        let mut guard = state
            .lock()
            .map_err(|_| io::Error::other("TPM mutex poisoned"))?;
        let mut buf = [0u8; 8192];
        let mut req = command.to_vec();
        let sz = guard
            .execute_command(&mut req, &mut buf)
            .map_err(|e| io::Error::other(format!("ref tpm exec failed: {e}")))?;
        Ok(buf[..sz].to_vec())
    }
}

/// Open an in-process reference TPM for testing.
///
/// The returned [`Tpm`] is backed by the singleton [`ms_tpm_20_ref`]
/// implementation and reports `true` from [`Tpm::is_reference`].
pub fn reference_tpm() -> io::Result<Tpm> {
    // Ensure the singleton is initialized (panics on failure).
    let _ = SHARED_STATE.get_or_init(init_shared_state);
    Ok(Tpm::from_raw_reference(Box::new(RefTpm)))
}
