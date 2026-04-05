# azure-tpm-tool

Command-line tool for low-level TPM 2.0 operations on Azure VMs, built on the
[`azure-tpm`](../../crates/azure-tpm) crate.

## Building

```bash
cargo build -p azure-tpm-tool
```

The binary is placed in `target/debug/azure-tpm-tool` (or `target/release/`
with `--release`).

## Requirements

- **Linux**: read/write access to `/dev/tpmrm0` (or `/dev/tpm0`).
  Typically this means running as root or being in the `tss` group.
- **Windows**: TPM Base Services (TBS) must be available.

## Commands

| Command          | Description                                                |
|------------------|------------------------------------------------------------|
| `pcr-read`       | Read PCR values (SHA-1, SHA-256, or SHA-384 bank)          |
| `nv-define`      | Define a new NV index (ordinary or extend type)            |
| `nv-undefine`    | Delete an NV index                                         |
| `nv-read-public` | Show public metadata of an NV index                        |
| `nv-read`        | Read data from an NV index                                 |
| `nv-write`       | Write data to an NV index                                  |
| `nv-extend`      | Extend an NV index (hash-chain, for `NT_EXTEND` indices)   |
| `read-public`    | Read the public area of a loaded/persistent object         |
| `create-primary` | Create a primary RSA signing key in a hierarchy            |
| `flush-context`  | Flush a transient object handle                            |
| `evict-control`  | Persist a transient key at a persistent handle             |
| `quote`          | Generate a PCR quote signed by a key                       |
| `event-log`      | Parse and display a TCG event log with PCR replay          |

Run `azure-tpm-tool <command> --help` for full option details.

## Examples

### Read PCR values

```bash
# Read PCR 0, 1, 7 from the SHA-256 bank
sudo azure-tpm-tool pcr-read --pcrs 0,1,7

# Read from the SHA-1 bank
sudo azure-tpm-tool pcr-read --pcrs 0,1 --algorithm sha1
```

### NV Index: Define, Write, Read

This is a complete walkthrough of creating an NV index, writing data to it,
reading the data back, and then cleaning up.

```bash
# 1. Define an ordinary (read/write) NV index at handle 0x01500001, 64 bytes
sudo azure-tpm-tool nv-define --index 0x01500001 --size 64

# 2. Inspect the NV index public metadata
sudo azure-tpm-tool nv-read-public --index 0x01500001

# 3. Write hex-encoded data to the NV index
sudo azure-tpm-tool nv-write --index 0x01500001 --data 48656c6c6f20545049

# 4. Or write a UTF-8 string directly
sudo azure-tpm-tool nv-write --index 0x01500001 --string "Hello TPM"

# 5. Or write from a file
sudo azure-tpm-tool nv-write --index 0x01500001 --file /path/to/data.bin

# 6. Read the data back (prints hex to stdout)
sudo azure-tpm-tool nv-read --index 0x01500001

# 7. Read the data to a file
sudo azure-tpm-tool nv-read --index 0x01500001 --output /tmp/nv_data.bin

# 8. Clean up: undefine the NV index
sudo azure-tpm-tool nv-undefine --index 0x01500001
```

### NV Extend Index

Extend-type NV indices work like PCRs — values are hash-chained, not
overwritten:

```bash
# Define an extend-type NV index (32 bytes = SHA-256 digest size)
sudo azure-tpm-tool nv-define --index 0x01500002 --size 32 --nv-type extend

# Extend with some data
sudo azure-tpm-tool nv-extend --index 0x01500002 --data 0102030405

# Read the current hash value
sudo azure-tpm-tool nv-read --index 0x01500002

# Clean up
sudo azure-tpm-tool nv-undefine --index 0x01500002
```

### Key Management

```bash
# Create a primary RSA signing key in the Owner hierarchy
sudo azure-tpm-tool create-primary --hierarchy owner

# Read the public area of a persistent key
sudo azure-tpm-tool read-public --handle 0x81000003

# Persist a transient key
sudo azure-tpm-tool evict-control --persistent 0x81000010 --transient 0x80000001

# Flush a transient handle
sudo azure-tpm-tool flush-context --handle 0x80000001
```

### PCR Quote

```bash
# Quote PCRs 0,1,7 using a persistent signing key
sudo azure-tpm-tool quote --key 0x81000003 --pcrs 0,1,7
```

### Event Log

```bash
# Parse the system event log with PCR replay
sudo azure-tpm-tool event-log

# Parse a saved event log file
azure-tpm-tool event-log --file /path/to/binary_bios_measurements

# Use SHA-1 for PCR replay
azure-tpm-tool event-log --file measurements.bin --algorithm sha1
```
