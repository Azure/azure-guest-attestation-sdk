# azure-tpm

Platform-agnostic TPM 2.0 command interface for Azure guest virtual machines.

This crate provides a platform-agnostic TPM 2.0 interface including:

- **Device access** (`device`): Platform-agnostic TPM device communication (Linux `/dev/tpmrm0`, Windows TBS, in-process reference TPM)
- **Commands** (`commands`): High-level TPM command implementations via `TpmCommandExt`
- **Types** (`types`): TPM 2.0 data structures and marshaling/unmarshaling
- **Helpers** (`helpers`): Internal utilities for command building
- **Event log** (`event_log`): TCG event log parsing

## Crypto backend

`rustcrypto` is the default. `native` retains the existing platform backend;
`symcrypt` selects SymCrypt for event-log hashes, PCR-policy hashing, and
session entropy. Select SymCrypt with `--no-default-features --features symcrypt`;
combining it with another backend is a compile error.
See [native library setup and deployment](../../doc/symcrypt.md).

## Architecture

```text
┌─────────────────────────────────────────┐
│         TpmCommandExt Trait             │
│  (create_primary, sign, quote, etc.)    │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│           RawTpm Trait                  │
│        (transmit_raw bytes)             │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│    Platform TPM Driver / vTPM / Ref     │
└─────────────────────────────────────────┘
```

## Usage

```rust,no_run
use azure_tpm::{Tpm, TpmCommandExt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tpm = Tpm::open()?;
    let pcrs = tpm.read_pcrs_sha256(&[0, 1, 2, 7])?;
    for (index, digest) in &pcrs {
        println!("PCR{index}: {}", hex::encode(digest));
    }
    Ok(())
}
```

## License

MIT
