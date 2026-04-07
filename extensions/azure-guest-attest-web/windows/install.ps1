# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Azure VM Extension install script (Windows)
#
# This script is invoked by the Azure VM Extension at VM
# provisioning time.  It:
#   1. Installs Rust + build prerequisites (if missing)
#   2. Clones the repo at the configured commit / branch
#   3. Builds azure-guest-attest-web in release mode
#   4. Registers a Windows scheduled task that starts the web server on boot
#      with persistent self-signed TLS certificates
#
# Configuration is passed as parameters (from Azure VM Extension settings):
#
#   -Commit   -- git ref to checkout (default: "main")
#   -Domain   -- extra SAN for the self-signed cert
#   -Port     -- HTTPS listen port (default: 443)
#   -Bind     -- bind address (default: "0.0.0.0")
#   -RepoUrl  -- git clone URL (default: this repo's GitHub URL)
#
# Usage (admin PowerShell):
#   .\install.ps1
#   .\install.ps1 -Commit "v1.0" -Domain "myvm.eastus.cloudapp.azure.com"
#   .\install.ps1 -SettingsFile "C:\path\to\settings.json"

[CmdletBinding()]
param(
    [string]$Commit   = "main",
    [string]$Domain   = "",
    [int]   $Port     = 443,
    [string]$Bind     = "0.0.0.0",
    [string]$RepoUrl  = "https://github.com/Azure/azure-guest-attestation-sdk.git",
    [string]$SettingsFile = ""
)

# NOTE: We use "Continue" instead of "Stop" because PowerShell 5.1 treats
# ANY stderr output from native commands (git, cargo, rustup, etc.) as a
# terminating error when ErrorActionPreference is "Stop" -- even when the
# command succeeds.  Since this script calls many native commands, "Continue"
# is the safe default.  Critical failures are caught via $LASTEXITCODE checks
# after native commands and -ErrorAction Stop on critical PowerShell cmdlets.
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$InstallDir = "C:\azure-guest-attest-web"
$CertDir    = "$InstallDir\certs"
$RepoDir    = "$InstallDir\repo"
$BinPath    = "$InstallDir\azure-guest-attest-web.exe"
$TaskName   = "AzureGuestAttestWeb"
$LogFile    = "$InstallDir\install.log"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    $line = "[$ts] $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Parse settings JSON (if provided or found via CSE convention)
# ---------------------------------------------------------------------------
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

if ($SettingsFile -and (Test-Path $SettingsFile)) {
    Log "Reading settings from $SettingsFile"
    $settings = Get-Content $SettingsFile -Raw | ConvertFrom-Json
    if ($settings.commit)   { $Commit  = $settings.commit }
    if ($settings.domain)   { $Domain  = $settings.domain }
    if ($settings.port)     { $Port    = [int]$settings.port }
    if ($settings.bind)     { $Bind    = $settings.bind }
    if ($settings.repoUrl)  { $RepoUrl = $settings.repoUrl }
}

Log "Configuration:"
Log "  commit   = $Commit"
Log "  domain   = $(if ($Domain) { $Domain } else { '(none)' })"
Log "  port     = $Port"
Log "  bind     = $Bind"
Log "  repoUrl  = $RepoUrl"

# ---------------------------------------------------------------------------
# 1. Install Git (if missing)
# ---------------------------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Log "Installing Git ..."
    # Use winget if available, otherwise download installer
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Git.Git -e --accept-package-agreements --accept-source-agreements --silent
    } else {
        $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.2/Git-2.47.1.2-64-bit.exe"
        $gitInstaller = "$env:TEMP\git-installer.exe"
        Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller -UseBasicParsing
        Start-Process -Wait -FilePath $gitInstaller -ArgumentList "/VERYSILENT", "/NORESTART", "/NOCANCEL"
        Remove-Item $gitInstaller -Force -ErrorAction SilentlyContinue
    }
    # Refresh PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + $env:PATH
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        # Common default install location
        $env:PATH = "C:\Program Files\Git\cmd;$env:PATH"
    }
    Log "Git installed: $(git --version)"
}

# ---------------------------------------------------------------------------
# 2. Install Visual Studio Build Tools (if cl.exe not found)
# ---------------------------------------------------------------------------
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$hasBuildTools = $false
if (Test-Path $vsWhere) {
    $instPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($instPath) { $hasBuildTools = $true }
}

if (-not $hasBuildTools) {
    Log "Installing Visual Studio Build Tools (C++ workload) ..."
    $vsUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
    $vsInstaller = "$env:TEMP\vs_BuildTools.exe"
    Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller -UseBasicParsing
    Start-Process -Wait -FilePath $vsInstaller -ArgumentList `
        "--quiet", "--wait", "--norestart", "--nocache", `
        "--add", "Microsoft.VisualStudio.Workload.VCTools", `
        "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", `
        "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621", `
        "--includeRecommended"
    Remove-Item $vsInstaller -Force -ErrorAction SilentlyContinue
    Log "Build Tools installed"
}

# ---------------------------------------------------------------------------
# 3. Install Rust (if missing)
# ---------------------------------------------------------------------------
# Try user-level and system-level Rust
$rustup = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustup) {
    # Check common locations
    foreach ($p in @("$env:USERPROFILE\.cargo\bin", "C:\Users\Default\.cargo\bin", "$InstallDir\.cargo\bin")) {
        if (Test-Path "$p\rustup.exe") {
            $env:PATH = "$p;$env:PATH"
            $rustup = Get-Command rustup -ErrorAction SilentlyContinue
            break
        }
    }
}

if (-not $rustup) {
    Log "Installing Rust toolchain ..."
    $env:RUSTUP_HOME = "$InstallDir\.rustup"
    $env:CARGO_HOME  = "$InstallDir\.cargo"
    $rustupInit = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
    Start-Process -Wait -FilePath $rustupInit -ArgumentList "-y", "--default-toolchain", "stable", "--no-modify-path"
    Remove-Item $rustupInit -Force -ErrorAction SilentlyContinue
    $env:PATH = "$env:CARGO_HOME\bin;$env:PATH"
    Log "Rust installed: $(rustc --version)"
} else {
    # Set env vars if using existing install
    if (-not $env:RUSTUP_HOME) {
        $env:RUSTUP_HOME = (Split-Path (Split-Path (Get-Command rustup).Source)) -replace "\\bin$", "" | Split-Path
        # Default fallback
        if (-not (Test-Path "$env:RUSTUP_HOME\toolchains")) {
            $env:RUSTUP_HOME = "$env:USERPROFILE\.rustup"
        }
    }
    if (-not $env:CARGO_HOME) {
        $env:CARGO_HOME = "$env:USERPROFILE\.cargo"
    }
    # Ensure a default toolchain is configured (CSE runs as SYSTEM, which
    # may not have a default even though rustup was previously installed)
    rustup default stable 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "rustup default stable failed (exit code $LASTEXITCODE)" }
    Log "Rust already present: $(rustc --version)"
}

# ---------------------------------------------------------------------------
# 4. Clone / update the repository
# ---------------------------------------------------------------------------
if (Test-Path "$RepoDir\.git") {
    Log "Repository already cloned, fetching ..."
    git -C $RepoDir fetch --all --quiet 2>&1 | Out-Null
} else {
    Log "Cloning repository ..."
    git clone --quiet $RepoUrl $RepoDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit code $LASTEXITCODE)" }
}

Log "Checking out $Commit ..."
git -C $RepoDir checkout $Commit --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "git checkout '$Commit' failed (exit code $LASTEXITCODE)" }
# If it's a branch, pull latest
$isBranch = git -C $RepoDir symbolic-ref HEAD 2>$null
if ($isBranch) {
    git -C $RepoDir pull --quiet 2>&1 | Out-Null
}

# ---------------------------------------------------------------------------
# 5. Build in release mode
# ---------------------------------------------------------------------------
Log "Building azure-guest-attest-web (release) ... this may take several minutes"

# Set up VS environment for the build
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
        $vcVars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $vcVars) {
            # Import environment from vcvars64.bat
            cmd /c "`"$vcVars`" && set" | ForEach-Object {
                if ($_ -match "^(.+?)=(.+)$") {
                    [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                }
            }
        }
    }
}

Push-Location $RepoDir
try {
    cargo build -p azure-guest-attest-web --release 2>&1 | Select-Object -Last 5
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

Copy-Item "$RepoDir\target\release\azure-guest-attest-web.exe" $BinPath -Force -ErrorAction Stop
Log "Binary installed to $BinPath"

# ---------------------------------------------------------------------------
# 6. Prepare cert directory
# ---------------------------------------------------------------------------
if (-not (Test-Path $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }

# ---------------------------------------------------------------------------
# 7. Register Windows Scheduled Task (runs at boot)
# ---------------------------------------------------------------------------
Log "Registering scheduled task '$TaskName' ..."

# Build the argument string
$arguments = "--bind ${Bind}:${Port} --tls-self-signed-dir `"$CertDir`""
if ($Domain) {
    $arguments += " --tls-san $Domain"
}

# Remove existing task if present
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create task action
$action = New-ScheduledTaskAction -Execute $BinPath -Argument $arguments -WorkingDirectory $InstallDir

# Trigger: at system startup
$trigger = New-ScheduledTaskTrigger -AtStartup

# Settings: restart on failure, don't stop on idle, run indefinitely
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -RestartCount 5 `
    -ExecutionTimeLimit (New-TimeSpan -Days 0)

# Register to run as SYSTEM
Register-ScheduledTask -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -User "SYSTEM" `
    -RunLevel Highest `
    -Description "Azure Guest Attestation Web UI (HTTPS on port $Port)" `
    -Force | Out-Null

# Start it now
Start-ScheduledTask -TaskName $TaskName

Log "Scheduled task '$TaskName' registered and started"

# ---------------------------------------------------------------------------
# 8. Open firewall port
# ---------------------------------------------------------------------------
Log "Configuring firewall rule ..."
$ruleName = "AzureGuestAttestWeb-HTTPS-$Port"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existing) {
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $Port `
        -Action Allow `
        -Profile Any | Out-Null
    Log "Firewall rule '$ruleName' created (TCP $Port inbound)"
} else {
    Log "Firewall rule '$ruleName' already exists"
}

# ---------------------------------------------------------------------------
# 9. Verify
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 3
$task = Get-ScheduledTask -TaskName $TaskName
if ($task.State -eq "Running") {
    Log "[OK] Task is running"
} else {
    Log "[WARNING] Task state: $($task.State) -- check Event Viewer for errors"
    Log "  Manual start: Start-ScheduledTask -TaskName $TaskName"
}

Log ""
Log "Installation complete."
Log "  Web UI:  https://${Domain}:${Port}"
Log "  Certs:   $CertDir"
Log "  Task:    $TaskName (runs at boot as SYSTEM)"
Log "  Logs:    $LogFile"
