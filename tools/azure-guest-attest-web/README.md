# azure-guest-attest-web

Web-based interactive tool for Azure Guest Attestation.  Runs a local
HTTP(S) server that exposes every SDK feature through a **REST API** and
serves a **browser-based UI** for interactive exploration — no CLI required.

Works on **Linux** and **Windows** Azure Confidential VMs (SNP, TDX, VBS).

## Quick Start

```bash
# Build
cargo build -p azure-guest-attest-web --release

# Run (HTTP, localhost only)
./target/release/azure-guest-attest-web
# → http://127.0.0.1:8080
```

Then open `http://127.0.0.1:8080` in a browser, or start using the REST API
directly with `curl` / `Invoke-RestMethod`.

## HTTPS / TLS

Three TLS modes are available — no external tools like `openssl` are needed:

### Self-signed (ephemeral)

Generates a new certificate on every start.  Good for quick testing.

```bash
azure-guest-attest-web --tls-self-signed
# → https://127.0.0.1:8080
```

### Self-signed (persistent)

Generates a certificate once and saves it to disk.  On subsequent runs the
saved certificate is reloaded, so the fingerprint stays stable — you can add
it to your trust store once.

```bash
azure-guest-attest-web --tls-self-signed-dir ./certs
# First run:  "Generated and saved self-signed certificate to ./certs"
# Next runs:  "Loaded self-signed certificate from ./certs"
```

### Bring your own certificate

```bash
azure-guest-attest-web --tls-cert cert.pem --tls-key key.pem
```

### Subject Alternative Names

By default the self-signed certificate covers `localhost`, `127.0.0.1`, and
`::1`.  When clients connect via another IP or hostname, add extra SANs:

```bash
azure-guest-attest-web --tls-self-signed-dir ./certs \
    --tls-san 10.0.0.5 \
    --tls-san myvm.eastus.cloudapp.azure.com
```

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <ADDR:PORT>` | `127.0.0.1:8080` | Address and port to listen on |
| `--tls-cert <PATH>` | — | PEM certificate file |
| `--tls-key <PATH>` | — | PEM private key file |
| `--tls-self-signed` | — | Generate an ephemeral self-signed cert |
| `--tls-self-signed-dir <DIR>` | — | Persist self-signed cert in `<DIR>/cert.pem` + `<DIR>/key.pem` |
| `--tls-san <NAME>` | — | Extra SAN (IP or DNS). Repeatable |

## REST API

All endpoints are under `/api/*` and return a JSON envelope:

```json
{
  "success": true,
  "data": { "..." },
  "error": null
}
```

Interactive API documentation is available at `/api/docs` when the server is
running.  A machine-readable JSON index is at `/api`.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/diagnose` | OS info, TPM availability, CVM type |
| `GET` | `/api/cvm-report[?user_data=...]` | Full CVM attestation report |
| `GET` | `/api/tee-report[?user_data=...]` | Raw TEE report (SNP / TDX / VBS) |
| `GET` | `/api/ak-cert` | Attestation Key certificate (PEM) |
| `GET` | `/api/ak-pub` | Attestation Key public area (hex) |
| `GET` | `/api/pcrs[?indices=0,1,7]` | PCR values (SHA-1 / SHA-256 / SHA-384) |
| `GET` | `/api/event-log` | TPM event log + PCR replay |
| `GET` | `/api/td-quote` | Intel TDX quote (TDX only) |
| `GET` | `/api/isolation-evidence` | VCEK chain (SNP) or TD quote (TDX) |
| `POST` | `/api/guest-attest` | Full guest attestation → JWT token |
| `POST` | `/api/tee-attest` | TEE-only attestation → JWT token |
| `POST` | `/api/parse-token` | Decode a JWT attestation token |

### Examples

```bash
# System diagnostics
curl -s http://localhost:8080/api/diagnose | jq .

# SNP / TDX report (parsed)
curl -s http://localhost:8080/api/tee-report | jq .data.pretty

# PCRs 0 and 7 only
curl -s "http://localhost:8080/api/pcrs?indices=0,7" | jq .

# Guest attestation with MAA
curl -s -X POST http://localhost:8080/api/guest-attest \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "maa",
    "endpoint": "https://sharedweu.weu.attest.azure.net",
    "decode_token": true
  }' | jq .

# TEE-only attestation
curl -s -X POST http://localhost:8080/api/tee-attest \
  -H "Content-Type: application/json" \
  -d '{"endpoint":"https://sharedweu.weu.attest.azure.net","decode_token":true}' | jq .

# Decode a JWT token
curl -s -X POST http://localhost:8080/api/parse-token \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOi..."}' | jq .
```

#### PowerShell

```powershell
# Diagnostics
Invoke-RestMethod http://localhost:8080/api/diagnose | ConvertTo-Json

# Guest attestation
$body = @{
    provider     = "maa"
    endpoint     = "https://sharedweu.weu.attest.azure.net"
    decode_token = $true
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/guest-attest `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
```

> **Tip:** For HTTPS with a self-signed cert, add `-k` to `curl` or
> `-SkipCertificateCheck` to `Invoke-RestMethod`.

## Static Build (Windows)

Produce a self-contained binary with no MSVC runtime dependencies:

### MSVC toolchain

```powershell
$env:RUSTFLAGS = "-Ctarget-feature=+crt-static"
cargo build -p azure-guest-attest-web --features static --release
Remove-Item Env:RUSTFLAGS
```

### GNU / MinGW toolchain

```powershell
cargo build -p azure-guest-attest-web --features static --release
```

The `build.rs` script automatically adds `-static` and `-static-libgcc`.

## Architecture

```
azure-guest-attest-web
├── src/main.rs          # Axum server, REST handlers, TLS helpers, CLI
├── static/
│   ├── index.html       # Single-page app (dark theme)
│   ├── style.css        # Styles
│   ├── app.js           # Frontend logic
│   └── api-docs.html    # Interactive REST API reference
└── build.rs             # Static CRT linking (Windows)
```

All static assets are embedded via `include_str!` — the binary is entirely
self-contained with no runtime file dependencies.
