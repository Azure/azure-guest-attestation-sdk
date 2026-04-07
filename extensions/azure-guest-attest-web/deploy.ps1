# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Deploy the Azure Guest Attestation Web UI extension to a Windows VM
# using an Azure VM Extension.
#
# Prerequisites:
#   - Azure CLI (az) logged in
#   - The target VM must be running
#
# Usage:
#   .\deploy.ps1 -ResourceGroup myRG -VMName myVM
#   .\deploy.ps1 -ResourceGroup myRG -VMName myVM `
#       -Domain "myvm.eastus.cloudapp.azure.com" `
#       -Commit "v1.0" -Port 8443
#
# Update (re-deploys the extension with the new commit):
#   .\deploy.ps1 -ResourceGroup myRG -VMName myVM -Commit "v2.0"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string]$VMName,

    [string]$Commit   = "main",
    [string]$Domain   = "",
    [int]   $Port     = 443,
    [string]$Bind     = "0.0.0.0",
    [string]$RepoUrl  = "https://github.com/Azure/azure-guest-attestation-sdk.git",

    # URL of the install.ps1 script — override for custom hosting
    [string]$ScriptUrl = "https://raw.githubusercontent.com/Azure/azure-guest-attestation-sdk/main/extensions/azure-guest-attest-web/windows/install.ps1"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Deploy mode
# ---------------------------------------------------------------------------
Write-Host "Deploying Azure Guest Attestation Web UI extension …"
Write-Host "  Resource Group: $ResourceGroup"
Write-Host "  VM Name:        $VMName"
Write-Host "  Commit:         $Commit"
Write-Host "  Domain:         $(if ($Domain) { $Domain } else { '(none)' })"
Write-Host "  Port:           $Port"
Write-Host ""

# ---------------------------------------------------------------------------
# Build the commandToExecute using -File (not -Command) to avoid cmd.exe
# parsing interference.  With -File, PowerShell parses install.ps1 as a
# standalone script and passes parameters directly — no quoting issues
# because none of the values contain spaces or special characters.
# ---------------------------------------------------------------------------
$cmdParts = @(
    "powershell -ExecutionPolicy Bypass -File install.ps1"
    "-Commit $Commit"
    "-Port $Port"
    "-Bind $Bind"
    "-RepoUrl $RepoUrl"
)
if ($Domain) {
    $cmdParts += "-Domain $Domain"
}
$innerCmd = $cmdParts -join ' '

# ---------------------------------------------------------------------------
# Remove existing extension (only one allowed per VM)
# ---------------------------------------------------------------------------
Write-Host "Removing existing Azure VM Extension (if any) …"
az vm extension delete `
    --resource-group $ResourceGroup `
    --vm-name $VMName `
    --name CustomScriptExtension 2>$null

# ---------------------------------------------------------------------------
# Deploy Azure VM Extension
# ---------------------------------------------------------------------------
Write-Host "Applying Azure VM Extension …"

# Write JSON to temp files and use az CLI's @file syntax to avoid
# PowerShell quoting issues with inline JSON.
$settingsTmp = [System.IO.Path]::GetTempFileName()
$protectedTmp = [System.IO.Path]::GetTempFileName()

# settings — only fileUris (public)
@{ fileUris = @($ScriptUrl) } | ConvertTo-Json -Compress |
    Set-Content -Path $settingsTmp -Encoding UTF8

# protectedSettings — commandToExecute (not logged by the extension)
@{ commandToExecute = $innerCmd } | ConvertTo-Json -Compress |
    Set-Content -Path $protectedTmp -Encoding UTF8

try {
    az vm extension set `
        --resource-group $ResourceGroup `
        --vm-name $VMName `
        --name CustomScriptExtension `
        --publisher Microsoft.Compute `
        --version 1.10 `
        --force-update `
        --settings "@$settingsTmp" `
        --protected-settings "@$protectedTmp"
} finally {
    Remove-Item -Path $settingsTmp, $protectedTmp -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Extension deployed. The VM is now building and starting the web server."
Write-Host "This may take 10-15 minutes for the initial build (includes VS Build Tools)."
Write-Host ""
Write-Host "Check status:"
Write-Host "  az vm extension show -g $ResourceGroup --vm-name $VMName --name CustomScriptExtension"
Write-Host ""
if ($Domain) {
    Write-Host "Once ready:  https://${Domain}:${Port}"
} else {
    Write-Host "Once ready:  https://<vm-public-ip>:${Port}"
}
