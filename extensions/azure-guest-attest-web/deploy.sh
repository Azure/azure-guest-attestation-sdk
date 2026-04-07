#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Deploy the Azure Guest Attestation Web UI extension to a Linux VM
# using an Azure VM Extension.
#
# Prerequisites:
#   - Azure CLI (az) logged in
#   - The target VM must be running
#
# Usage:
#   ./deploy.sh --resource-group myRG --vm-name myVM
#   ./deploy.sh --resource-group myRG --vm-name myVM \
#       --domain myvm.eastus.cloudapp.azure.com \
#       --commit v1.0 --port 8443
#
# Update (re-deploys the extension with the new commit):
#   ./deploy.sh --resource-group myRG --vm-name myVM --commit v2.0

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RESOURCE_GROUP=""
VM_NAME=""
COMMIT="main"
DOMAIN=""
PORT="443"
BIND="0.0.0.0"
REPO_URL="https://github.com/Azure/azure-guest-attestation-sdk.git"

# The install script location — uploaded to a publicly accessible URL or
# stored in a storage account.  For simplicity, we use the raw GitHub URL.
# Replace with your fork / branch as needed.
SCRIPT_URL="https://raw.githubusercontent.com/Azure/azure-guest-attestation-sdk/main/extensions/azure-guest-attest-web/linux/install.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --resource-group|-g)  RESOURCE_GROUP="$2"; shift 2 ;;
        --vm-name|-n)         VM_NAME="$2";        shift 2 ;;
        --commit|-c)          COMMIT="$2";         shift 2 ;;
        --domain|-d)          DOMAIN="$2";         shift 2 ;;
        --port|-p)            PORT="$2";           shift 2 ;;
        --bind|-b)            BIND="$2";           shift 2 ;;
        --repo-url)           REPO_URL="$2";       shift 2 ;;
        --script-url)         SCRIPT_URL="$2";     shift 2 ;;
        --help|-h)
            echo "Usage: $0 --resource-group RG --vm-name VM [options]"
            echo ""
            echo "Options:"
            echo "  --resource-group, -g   Azure resource group (required)"
            echo "  --vm-name, -n          VM name (required)"
            echo "  --commit, -c           Git ref to checkout (default: main)"
            echo "  --domain, -d           Domain name for TLS SAN"
            echo "  --port, -p             HTTPS port (default: 443)"
            echo "  --bind, -b             Bind address (default: 0.0.0.0)"
            echo "  --repo-url             Repository URL to clone"
            echo "  --script-url           URL of install.sh (for custom hosting)"
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

# ---------------------------------------------------------------------------
# Build settings as a compact single-line JSON (no newlines / no nesting issues)
# ---------------------------------------------------------------------------
SETTINGS_ONELINE="{\"commit\":\"$COMMIT\",\"domain\":\"$DOMAIN\",\"port\":\"$PORT\",\"bind\":\"$BIND\",\"repoUrl\":\"$REPO_URL\"}"

echo "Deploying Azure Guest Attestation Web UI extension …"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  VM Name:        $VM_NAME"
echo "  commit:         $COMMIT"
echo "  domain:         ${DOMAIN:-(none)}"
echo "  port:           $PORT"
echo "  bind:           $BIND"
echo "  repoUrl:        $REPO_URL"
echo ""

# ---------------------------------------------------------------------------
# Deploy via Azure VM Extension
# ---------------------------------------------------------------------------
# Remove existing extension if present (only one instance allowed per VM).
# Must wait for deletion to complete before setting the new extension.
az vm extension delete \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name customScript \
    2>/dev/null || true

# Base64-encode the settings JSON so it can be safely embedded in the
# commandToExecute without any quoting issues (no braces, no quotes).
SETTINGS_B64=$(echo -n "$SETTINGS_ONELINE" | base64 -w0)

# Write both JSON files for az CLI's @file syntax.
SETTINGS_TMP=$(mktemp /tmp/attest-web-settings.XXXXXX.json)
PROTECTED_TMP=$(mktemp /tmp/attest-web-protected.XXXXXX.json)
trap 'rm -f "$SETTINGS_TMP" "$PROTECTED_TMP"' EXIT

cat > "$SETTINGS_TMP" <<SJSON
{"fileUris": ["$SCRIPT_URL"]}
SJSON

# On the VM: decode base64 → write JSON file → run install script
cat > "$PROTECTED_TMP" <<PJSON
{"commandToExecute": "echo $SETTINGS_B64 | base64 -d > /tmp/attest-web-settings.json && bash install.sh /tmp/attest-web-settings.json"}
PJSON

echo "Applying Azure VM Extension …"
az vm extension set \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name customScript \
    --publisher Microsoft.Azure.Extensions \
    --version 2.1 \
    --force-update \
    --settings @"$SETTINGS_TMP" \
    --protected-settings @"$PROTECTED_TMP"

echo ""
echo "Extension deployed. The VM is now building and starting the web server."
echo "This may take 5–10 minutes for the initial build."
echo ""
echo "Check status:"
echo "  az vm extension show -g $RESOURCE_GROUP --vm-name $VM_NAME --name customScript"
echo ""
if [[ -n "$DOMAIN" ]]; then
    echo "Once ready:  https://$DOMAIN:$PORT"
else
    echo "Once ready:  https://<vm-public-ip>:$PORT"
fi
