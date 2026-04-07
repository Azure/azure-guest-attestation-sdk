#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Diagnose the Azure Guest Attestation Web UI extension on a Linux VM
# remotely using `az vm run-command invoke`.
#
# Prerequisites:
#   - Azure CLI (az) logged in
#   - The target VM must be running
#
# Usage:
#   ./diagnose.sh --resource-group myRG --vm-name myVM
#   ./diagnose.sh -g myRG -n myVM
#   ./diagnose.sh -g myRG -n myVM --save diag-output.txt

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RESOURCE_GROUP=""
VM_NAME=""
SAVE_FILE=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --resource-group|-g)  RESOURCE_GROUP="$2"; shift 2 ;;
        --vm-name|-n)         VM_NAME="$2";        shift 2 ;;
        --save|-s)            SAVE_FILE="$2";      shift 2 ;;
        --help|-h)
            echo "Usage: $0 --resource-group RG --vm-name VM [options]"
            echo ""
            echo "Options:"
            echo "  --resource-group, -g   Azure resource group (required)"
            echo "  --vm-name, -n          VM name (required)"
            echo "  --save, -s             Save output to a local file"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$VM_NAME" ]]; then
    echo "Error: --resource-group and --vm-name are required"
    echo "Run with --help for usage"
    exit 1
fi

echo "Running diagnostics on $VM_NAME ($RESOURCE_GROUP) …"
echo ""

# ---------------------------------------------------------------------------
# The diagnosis script that runs on the VM
# ---------------------------------------------------------------------------
read -r -d '' DIAG_SCRIPT << 'DIAGEOF' || true
#!/usr/bin/env bash
set -uo pipefail

INSTALL_DIR="/opt/azure-guest-attest-web"
CERT_DIR="$INSTALL_DIR/certs"
REPO_DIR="$INSTALL_DIR/repo"
BIN_PATH="/usr/local/bin/azure-guest-attest-web"
SERVICE_NAME="azure-guest-attest-web"
INSTALL_LOG="/var/log/azure-guest-attest-web-install.log"
CSE_STDOUT="/var/lib/waagent/custom-script/download/0/stdout"
CSE_STDERR="/var/lib/waagent/custom-script/download/0/stderr"

section() { echo ""; echo "=================================================================="; echo "  $1"; echo "=================================================================="; }
ok()   { echo "  ✓ $*"; }
warn() { echo "  ⚠ $*"; }
fail() { echo "  ✗ $*"; }
info() { echo "  $*"; }

echo "Azure Guest Attestation Web UI — Diagnosis Report"
echo "Generated: $(date -Iseconds)"
echo "Hostname:  $(hostname)"
echo "OS:        $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "Kernel:    $(uname -r)"

# 1. Service status
section "Service Status"
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    ok "Service is enabled (starts on boot)"
else
    fail "Service is NOT enabled"
fi
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    ok "Service is running"
    info "$(systemctl show $SERVICE_NAME --property=MainPID --property=ActiveEnterTimestamp 2>/dev/null | tr '\n' ' ')"
else
    fail "Service is NOT running"
    systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || true
fi
if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
    info "ExecStart:"
    grep -E "^ExecStart" "/etc/systemd/system/${SERVICE_NAME}.service" | sed 's/^/    /'
else
    warn "Service file not found"
fi

# 2. Binary
section "Binary"
if [[ -x "$BIN_PATH" ]]; then
    ok "Binary exists at $BIN_PATH"
    info "Size: $(du -h "$BIN_PATH" | cut -f1)  Modified: $(stat -c '%y' "$BIN_PATH" 2>/dev/null | cut -d. -f1)"
else
    fail "Binary not found at $BIN_PATH"
fi

# 3. Network
section "Network"
PORT=$(grep -oP -- '--bind\s+\S+:(\d+)' "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null | grep -oP '\d+$' || echo "443")
if ss -tlnp 2>/dev/null | grep -q ":${PORT}\b"; then
    ok "Port $PORT is listening"
    ss -tlnp 2>/dev/null | grep ":${PORT}\b" | sed 's/^/    /'
else
    fail "Port $PORT is NOT listening"
fi
if command -v curl &>/dev/null; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:${PORT}/" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        ok "HTTPS responds 200 OK on localhost:$PORT"
    elif [[ "$HTTP_CODE" == "000" ]]; then
        fail "HTTPS connection failed on localhost:$PORT"
    else
        warn "HTTPS responds $HTTP_CODE on localhost:$PORT"
    fi
fi

# 4. TLS certificates
section "TLS Certificates"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
if [[ -f "$CERT_FILE" ]]; then
    ok "cert.pem exists ($CERT_DIR)"
    if command -v openssl &>/dev/null; then
        SUBJECT=$(openssl x509 -subject -noout -in "$CERT_FILE" 2>/dev/null)
        SANS=$(openssl x509 -noout -ext subjectAltName -in "$CERT_FILE" 2>/dev/null | tail -1 | sed 's/^ *//')
        EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
        info "Subject: $SUBJECT"
        info "SANs:    $SANS"
        info "Expires: $EXPIRY"
        if openssl x509 -checkend 0 -noout -in "$CERT_FILE" 2>/dev/null; then
            ok "Certificate is NOT expired"
        else
            fail "Certificate is EXPIRED"
        fi
        if ! openssl x509 -checkend 2592000 -noout -in "$CERT_FILE" 2>/dev/null; then
            warn "Certificate expires within 30 days"
        fi
    fi
else
    fail "cert.pem not found in $CERT_DIR"
fi
[[ -f "$KEY_FILE" ]] && ok "key.pem exists" || fail "key.pem not found"

# 5. Repository
section "Repository"
if [[ -d "$REPO_DIR/.git" ]]; then
    ok "Repo exists at $REPO_DIR"
    info "Commit:  $(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null)"
    info "Branch:  $(git -C "$REPO_DIR" symbolic-ref --short HEAD 2>/dev/null || echo '(detached)')"
    info "Remote:  $(git -C "$REPO_DIR" remote get-url origin 2>/dev/null)"
    info "Last:    $(git -C "$REPO_DIR" log -1 --format='%h %s (%cr)' 2>/dev/null)"
else
    fail "Repo not found at $REPO_DIR"
fi

# 6. Rust toolchain
section "Rust Toolchain"
export CARGO_HOME="/opt/cargo" RUSTUP_HOME="/opt/rustup" PATH="/opt/cargo/bin:$PATH"
if command -v rustc &>/dev/null; then
    ok "rustc: $(rustc --version 2>/dev/null)"
    ok "cargo: $(cargo --version 2>/dev/null)"
else
    fail "Rust toolchain not found"
fi

# 7. TPM access
section "TPM Access"
if [[ -c /dev/tpmrm0 ]]; then
    ok "/dev/tpmrm0 exists"
    info "Permissions: $(ls -la /dev/tpmrm0 2>/dev/null | awk '{print $1, $3, $4}')"
elif [[ -c /dev/tpm0 ]]; then
    warn "/dev/tpm0 exists but /dev/tpmrm0 not found"
else
    fail "No TPM device found"
fi

# 8. Disk space
section "Disk Space"
du -sh "$INSTALL_DIR" 2>/dev/null | sed 's/^/  Install dir: /' || info "  (not found)"
df -h / | tail -1 | awk '{printf "  Root fs: %s used of %s (%s free)\n", $3, $2, $4}'

# 9. Recent service logs
section "Recent Service Logs (last 20 lines)"
journalctl -u "$SERVICE_NAME" --no-pager -n 20 2>/dev/null | sed 's/^/    /' || warn "No journal entries"

# 10. Install log (last 20 lines)
section "Install Log (last 20 lines)"
if [[ -f "$INSTALL_LOG" ]]; then
    tail -20 "$INSTALL_LOG" | sed 's/^/    /'
else
    warn "Install log not found"
fi

# 11. CSE output
section "Azure VM Extension Output"
if [[ -f "$CSE_STDERR" ]]; then
    STDERR_LINES=$(wc -l < "$CSE_STDERR")
    if [[ "$STDERR_LINES" -gt 0 ]]; then
        warn "stderr ($STDERR_LINES lines, last 10):"
        tail -10 "$CSE_STDERR" | sed 's/^/    /'
    else
        ok "stderr is empty"
    fi
fi

# Summary
section "Summary"
ISSUES=0
systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null && ok "Service running" || { fail "Service NOT running"; ((ISSUES++)) || true; }
[[ -x "$BIN_PATH" ]]     && ok "Binary present"  || { fail "Binary missing";  ((ISSUES++)) || true; }
[[ -f "$CERT_DIR/cert.pem" ]] && ok "Cert present" || { fail "Cert missing";  ((ISSUES++)) || true; }
ss -tlnp 2>/dev/null | grep -q ":${PORT}\b" && ok "Port $PORT open" || { fail "Port $PORT closed"; ((ISSUES++)) || true; }
[[ -d "$REPO_DIR/.git" ]] && ok "Repo present"    || { fail "Repo missing";   ((ISSUES++)) || true; }
echo ""
if [[ "$ISSUES" -eq 0 ]]; then
    echo "  All checks passed. The extension appears healthy."
else
    echo "  $ISSUES issue(s) detected. See details above."
fi
DIAGEOF

# ---------------------------------------------------------------------------
# Run the diagnosis script on the VM
# ---------------------------------------------------------------------------
OUTPUT=$(az vm run-command invoke \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --command-id RunShellScript \
    --scripts "$DIAG_SCRIPT" \
    --query "value[0].message" -o tsv 2>&1)

echo "$OUTPUT"

# ---------------------------------------------------------------------------
# Save output if requested
# ---------------------------------------------------------------------------
if [[ -n "$SAVE_FILE" ]]; then
    echo "$OUTPUT" > "$SAVE_FILE"
    echo ""
    echo "Output saved to: $SAVE_FILE"
fi
