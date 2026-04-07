#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Azure VM Extension install script (Linux)
#
# This script is invoked by the Azure VM Extension at VM
# provisioning time.  It:
#   1. Installs Rust + build prerequisites (if missing)
#   2. Clones the repo at the configured commit / branch
#   3. Builds azure-guest-attest-web in release mode
#   4. Installs a systemd service that starts the web server on every boot
#      with persistent self-signed TLS certificates
#
# Configuration is read from a JSON file passed as the first argument
# (written by the Azure VM Extension from --settings).  Recognised keys:
#
#   commit     – git ref to checkout (default: "main")
#   domain     – extra SAN for the self-signed cert (e.g. "myvm.eastus.cloudapp.azure.com")
#   port       – HTTPS listen port (default: 443)
#   bind       – bind address (default: "0.0.0.0")
#   repoUrl    – git clone URL (default: this repo's GitHub URL)
#
# Usage:
#   sudo bash install.sh                          # all defaults
#   sudo bash install.sh /var/lib/waagent/...json # with extension settings

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/azure-guest-attest-web"
CERT_DIR="/opt/azure-guest-attest-web/certs"
REPO_DIR="/opt/azure-guest-attest-web/repo"
BIN_PATH="/usr/local/bin/azure-guest-attest-web"
SERVICE_NAME="azure-guest-attest-web"
LOG_FILE="/var/log/azure-guest-attest-web-install.log"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
COMMIT="main"
DOMAIN=""
PORT="443"
BIND="0.0.0.0"
REPO_URL="https://github.com/Azure/azure-guest-attestation-sdk.git"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }

die() { log "FATAL: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Parse settings JSON (first argument, optional)
# ---------------------------------------------------------------------------
if [[ $# -ge 1 && -f "$1" ]]; then
    SETTINGS_FILE="$1"
    log "Reading settings from $SETTINGS_FILE"
    # jq may not be installed yet; try python3 as fallback
    if command -v jq &>/dev/null; then
        COMMIT=$(jq  -r '.commit  // "main"'       "$SETTINGS_FILE")
        DOMAIN=$(jq  -r '.domain  // ""'            "$SETTINGS_FILE")
        PORT=$(jq    -r '.port    // "443"'         "$SETTINGS_FILE")
        BIND=$(jq    -r '.bind    // "0.0.0.0"'     "$SETTINGS_FILE")
        REPO_URL=$(jq -r '.repoUrl // "'"$REPO_URL"'"' "$SETTINGS_FILE")
    elif command -v python3 &>/dev/null; then
        read_json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('$1','$2'))" "$SETTINGS_FILE"; }
        COMMIT=$(read_json commit   "main")
        DOMAIN=$(read_json domain   "")
        PORT=$(read_json   port     "443")
        BIND=$(read_json   bind     "0.0.0.0")
        REPO_URL=$(read_json repoUrl "$REPO_URL")
    else
        log "WARNING: neither jq nor python3 found; using defaults"
    fi
fi

log "Configuration:"
log "  commit   = $COMMIT"
log "  domain   = ${DOMAIN:-(none)}"
log "  port     = $PORT"
log "  bind     = $BIND"
log "  repoUrl  = $REPO_URL"

# ---------------------------------------------------------------------------
# 1. Install system prerequisites
# ---------------------------------------------------------------------------
log "Installing build prerequisites …"

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq build-essential pkg-config libssl-dev git curl perl >/dev/null
elif command -v dnf &>/dev/null; then
    dnf install -y gcc make openssl-devel git curl perl >/dev/null
elif command -v yum &>/dev/null; then
    yum install -y gcc make openssl-devel git curl perl >/dev/null
elif command -v zypper &>/dev/null; then
    zypper install -y gcc make libopenssl-devel git curl perl >/dev/null
else
    log "WARNING: unknown package manager; assuming prerequisites are present"
fi

# ---------------------------------------------------------------------------
# 2. Install Rust (if missing)
# ---------------------------------------------------------------------------
export RUSTUP_HOME="/opt/rustup"
export CARGO_HOME="/opt/cargo"
export PATH="$CARGO_HOME/bin:$PATH"

if ! command -v rustc &>/dev/null; then
    log "Installing Rust toolchain …"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --no-modify-path 2>&1 | tail -3
    log "Rust installed: $(rustc --version)"
else
    log "Rust already present: $(rustc --version)"
fi

# ---------------------------------------------------------------------------
# 3. Clone / update the repository
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"

if [[ -d "$REPO_DIR/.git" ]]; then
    log "Repository already cloned, fetching …"
    git -C "$REPO_DIR" fetch --all --quiet
else
    log "Cloning repository …"
    git clone --quiet "$REPO_URL" "$REPO_DIR"
fi

log "Checking out $COMMIT …"
git -C "$REPO_DIR" checkout "$COMMIT" --quiet
# If it's a branch, pull latest
if git -C "$REPO_DIR" symbolic-ref HEAD &>/dev/null; then
    git -C "$REPO_DIR" pull --quiet || true
fi

# ---------------------------------------------------------------------------
# 4. Build in release mode
# ---------------------------------------------------------------------------
log "Building azure-guest-attest-web (release) … this may take a few minutes"
(cd "$REPO_DIR" && cargo build -p azure-guest-attest-web --release 2>&1 | tail -5)

# Stop the service before copying — the running binary cannot be overwritten
# ("Text file busy").  The service will be (re)started in step 6.
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    log "Stopping running service before updating binary …"
    systemctl stop "$SERVICE_NAME"
fi

cp "$REPO_DIR/target/release/azure-guest-attest-web" "$BIN_PATH"
chmod +x "$BIN_PATH"
log "Binary installed to $BIN_PATH"

# ---------------------------------------------------------------------------
# 5. Prepare cert directory
# ---------------------------------------------------------------------------
mkdir -p "$CERT_DIR"

# ---------------------------------------------------------------------------
# 6. Install systemd service
# ---------------------------------------------------------------------------
log "Installing systemd service …"

TLS_SAN_FLAG=""
if [[ -n "$DOMAIN" ]]; then
    TLS_SAN_FLAG="--tls-san $DOMAIN"
fi

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Azure Guest Attestation Web UI (HTTPS)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH --bind ${BIND}:${PORT} --tls-self-signed-dir $CERT_DIR $TLS_SAN_FLAG
Restart=on-failure
RestartSec=5
# Run as root for TPM access (/dev/tpmrm0)
User=root
Environment=RUST_LOG=info

# Hardening
ProtectSystem=strict
ReadWritePaths=$CERT_DIR /var/log
ProtectHome=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start  "$SERVICE_NAME"

log "Service $SERVICE_NAME started on ${BIND}:${PORT}"

# ---------------------------------------------------------------------------
# 7. Verify
# ---------------------------------------------------------------------------
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "✓ Service is running"
else
    log "✗ Service failed to start — check: journalctl -u $SERVICE_NAME"
    systemctl status "$SERVICE_NAME" --no-pager || true
    exit 1
fi

log "Installation complete."
log "  Web UI:  https://${DOMAIN:-<vm-ip>}:${PORT}"
log "  Certs:   $CERT_DIR"
log "  Logs:    journalctl -u $SERVICE_NAME"
