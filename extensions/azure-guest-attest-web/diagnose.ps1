# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Diagnose the Azure Guest Attestation Web UI extension on a Windows VM
# remotely using `az vm run-command invoke`.
#
# Prerequisites:
#   - Azure CLI (az) logged in
#   - The target VM must be running
#
# Usage:
#   .\diagnose.ps1 -ResourceGroup myRG -VMName myVM
#   .\diagnose.ps1 -ResourceGroup myRG -VMName myVM -Save diag.txt

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string]$VMName,

    [string]$Save = ""
)

$ErrorActionPreference = "Stop"

Write-Host "Running diagnostics on $VMName ($ResourceGroup) ..."
Write-Host ""

# ---------------------------------------------------------------------------
# The diagnosis script that runs on the VM
# ---------------------------------------------------------------------------
$diagScript = @'
$ErrorActionPreference = "Continue"

$InstallDir = "C:\azure-guest-attest-web"
$CertDir    = "$InstallDir\certs"
$RepoDir    = "$InstallDir\repo"
$BinPath    = "$InstallDir\azure-guest-attest-web.exe"
$TaskName   = "AzureGuestAttestWeb"
$LogFile    = "$InstallDir\install.log"

function Section($t) { Write-Output ""; Write-Output "=================================================================="; Write-Output "  $t"; Write-Output "==================================================================" }
function Ok($m)   { Write-Output "  [OK] $m" }
function Warn($m) { Write-Output "  [WARN] $m" }
function Fail($m) { Write-Output "  [FAIL] $m" }
function Info($m) { Write-Output "  $m" }

Write-Output "Azure Guest Attestation Web UI - Diagnosis Report"
Write-Output "Generated: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')"
Write-Output "Hostname:  $env:COMPUTERNAME"
Write-Output "OS:        $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Output "Build:     $([System.Environment]::OSVersion.Version)"

# 1. Scheduled task status
Section "Scheduled Task Status"
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Ok "Task '$TaskName' exists"
    Info "State: $($task.State)"
    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($taskInfo) {
        Info "Last run: $($taskInfo.LastRunTime)"
        Info "Last result: $($taskInfo.LastTaskResult)"
        Info "Next run: $($taskInfo.NextRunTime)"
    }
    # Show the action (command line)
    $action = $task.Actions | Select-Object -First 1
    if ($action) {
        Info "Command: $($action.Execute) $($action.Arguments)"
    }
} else {
    Fail "Task '$TaskName' not found"
}

# 2. Binary
Section "Binary"
if (Test-Path $BinPath) {
    $fileInfo = Get-Item $BinPath
    Ok "Binary exists at $BinPath"
    Info "Size: $([math]::Round($fileInfo.Length / 1MB, 1)) MB  Modified: $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
} else {
    Fail "Binary not found at $BinPath"
}

# 3. Network
Section "Network"
$port = 443
# Try to parse port from task action
if ($task) {
    $action = $task.Actions | Select-Object -First 1
    if ($action -and $action.Arguments -match '--bind\s+\S+:(\d+)') {
        $port = [int]$Matches[1]
    }
}
$listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    Ok "Port $port is listening"
    $listener | Select-Object LocalAddress, LocalPort, OwningProcess | ForEach-Object {
        Info "  $($_.LocalAddress):$($_.LocalPort) (PID $($_.OwningProcess))"
    }
} else {
    Fail "Port $port is NOT listening"
}
# Quick HTTPS check
try {
    $resp = Invoke-WebRequest -Uri "https://localhost:$port/" -SkipCertificateCheck -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Ok "HTTPS responds $($resp.StatusCode) on localhost:$port"
} catch {
    Fail "HTTPS connection failed on localhost:$port - $_"
}

# 4. TLS certificates
Section "TLS Certificates"
$certFile = "$CertDir\cert.pem"
$keyFile  = "$CertDir\key.pem"
if (Test-Path $certFile) {
    $certInfo = Get-Item $certFile
    Ok "cert.pem exists ($CertDir)"
    Info "Modified: $($certInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))  Size: $($certInfo.Length) bytes"
    # Try to parse cert with .NET
    try {
        $certContent = Get-Content $certFile -Raw
        $certBytes = [Convert]::FromBase64String(($certContent -replace '-----[^-]+-----', '' -replace "`r`n|`n", ''))
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
        Info "Subject: $($x509.Subject)"
        Info "Issuer:  $($x509.Issuer)"
        Info "Valid:   $($x509.NotBefore.ToString('yyyy-MM-dd')) to $($x509.NotAfter.ToString('yyyy-MM-dd'))"
        $san = $x509.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
        if ($san) { Info "SANs:    $($san.Format($false))" }
        if ($x509.NotAfter -lt (Get-Date)) {
            Fail "Certificate is EXPIRED"
        } else {
            Ok "Certificate is NOT expired"
            if ($x509.NotAfter -lt (Get-Date).AddDays(30)) {
                Warn "Certificate expires within 30 days"
            }
        }
        $x509.Dispose()
    } catch {
        Warn "Could not parse certificate: $_"
    }
} else {
    Fail "cert.pem not found in $CertDir"
}
if (Test-Path $keyFile) { Ok "key.pem exists" } else { Fail "key.pem not found" }

# 5. Repository
Section "Repository"
if (Test-Path "$RepoDir\.git") {
    Ok "Repo exists at $RepoDir"
    $sha    = git -C $RepoDir rev-parse --short HEAD 2>$null
    $branch = git -C $RepoDir symbolic-ref --short HEAD 2>$null
    if (-not $branch) { $branch = "(detached)" }
    $remote = git -C $RepoDir remote get-url origin 2>$null
    $last   = git -C $RepoDir log -1 --format='%h %s (%cr)' 2>$null
    Info "Commit:  $sha"
    Info "Branch:  $branch"
    Info "Remote:  $remote"
    Info "Last:    $last"
} else {
    Fail "Repo not found at $RepoDir"
}

# 6. Rust toolchain
Section "Rust Toolchain"
$cargoFound = $false
foreach ($p in @("$InstallDir\.cargo\bin", "$env:USERPROFILE\.cargo\bin")) {
    if (Test-Path "$p\cargo.exe") {
        $env:PATH = "$p;$env:PATH"
        $cargoFound = $true
        break
    }
}
if ($cargoFound) {
    Ok "rustc: $(rustc --version 2>$null)"
    Ok "cargo: $(cargo --version 2>$null)"
} else {
    Fail "Rust toolchain not found"
}

# 7. TPM access
Section "TPM Access"
$tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($tpm) {
    if ($tpm.TpmPresent) { Ok "TPM is present" } else { Fail "TPM not present" }
    if ($tpm.TpmReady)   { Ok "TPM is ready" }   else { Warn "TPM not ready" }
    Info "Manufacturer: $($tpm.ManufacturerIdTxt)"
} else {
    Warn "Get-Tpm not available or access denied"
}

# 8. Firewall rule
Section "Firewall"
$ruleName = "AzureGuestAttestWeb-HTTPS-$port"
$rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($rule) {
    Ok "Firewall rule '$ruleName' exists (Enabled: $($rule.Enabled), Action: $($rule.Action))"
} else {
    Warn "Firewall rule '$ruleName' not found"
}

# 9. Disk space
Section "Disk Space"
if (Test-Path $InstallDir) {
    $dirSize = (Get-ChildItem $InstallDir -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    Info "Install dir: $([math]::Round($dirSize / 1MB, 1)) MB"
}
$drive = Get-PSDrive C
Info "C: drive: $([math]::Round($drive.Used / 1GB, 1)) GB used, $([math]::Round($drive.Free / 1GB, 1)) GB free"

# 10. Install log (last 20 lines)
Section "Install Log (last 20 lines)"
if (Test-Path $LogFile) {
    Get-Content $LogFile | Select-Object -Last 20 | ForEach-Object { Info "  $_" }
} else {
    Warn "Install log not found at $LogFile"
}

# Summary
Section "Summary"
$issues = 0
if ($task -and $task.State -eq 'Running') { Ok "Task running" }         else { Fail "Task NOT running"; $issues++ }
if (Test-Path $BinPath)                   { Ok "Binary present" }       else { Fail "Binary missing";   $issues++ }
if (Test-Path $certFile)                  { Ok "Cert present" }         else { Fail "Cert missing";     $issues++ }
if ($listener)                            { Ok "Port $port open" }      else { Fail "Port $port closed"; $issues++ }
if (Test-Path "$RepoDir\.git")            { Ok "Repo present" }         else { Fail "Repo missing";     $issues++ }
Write-Output ""
if ($issues -eq 0) {
    Write-Output "  All checks passed. The extension appears healthy."
} else {
    Write-Output "  $issues issue(s) detected. See details above."
}
'@

# ---------------------------------------------------------------------------
# Run the diagnosis script on the VM
# ---------------------------------------------------------------------------
$output = az vm run-command invoke `
    --resource-group $ResourceGroup `
    --name $VMName `
    --command-id RunPowerShellScript `
    --scripts $diagScript `
    --query "value[0].message" -o tsv 2>&1

Write-Host $output

# ---------------------------------------------------------------------------
# Save output if requested
# ---------------------------------------------------------------------------
if ($Save) {
    $output | Out-File -FilePath $Save -Encoding utf8
    Write-Host ""
    Write-Host "Output saved to: $Save"
}
