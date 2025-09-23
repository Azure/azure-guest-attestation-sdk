<#
PowerShell setup script for development environment.
Installs rustup (if missing) and installs cbindgen via cargo.
Run as a normal user; rustup installs to the user's profile.
#>

param(
    [switch]$InstallCbindgen = $true
)

function Has-Command($name) {
    return (Get-Command $name -ErrorAction SilentlyContinue) -ne $null
}

Write-Host "Checking for rustup..."
if (-not (Has-Command rustup)) {
    Write-Host "rustup not found. Installing rustup (stable) ..."
    $tmp = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/" -OutFile $tmp -UseBasicParsing
    Start-Process -FilePath $tmp -ArgumentList "-y" -NoNewWindow -Wait
    Remove-Item $tmp -Force
} else {
    Write-Host "rustup found."
}

Write-Host "Ensuring stable toolchain is installed and active..."

# Ensure the user's Cargo bin directory is available in this session (so rustup/cargo are callable without restarting the shell)
$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $CargoBin) {
    if (-not ($env:PATH -split ';' | Where-Object { $_ -ieq $CargoBin })) {
        Write-Host "Adding $CargoBin to PATH for this session..."
        $env:PATH = "$CargoBin;$env:PATH"
    }
} else {
    Write-Host "Note: Cargo bin directory not found at $CargoBin. rustup/cargo may not be available until after installation completes."
}

# Prefer the rustup on PATH, otherwise fall back to the rustup.exe inside the user's cargo bin directory
$RustupCmd = (Get-Command rustup -ErrorAction SilentlyContinue)?.Source
if (-not $RustupCmd -and (Test-Path (Join-Path $CargoBin 'rustup.exe'))) {
    $RustupCmd = Join-Path $CargoBin 'rustup.exe'
}

if (-not $RustupCmd) {
    Write-Host "rustup not found; please open a new shell or add $CargoBin to PATH, then re-run this script."
} else {
    & $RustupCmd toolchain install stable
    & $RustupCmd default stable
}

if ($InstallCbindgen) {
    Write-Host "Installing cbindgen (via cargo)..."
    # Ensure cargo on path
    if (-not (Has-Command cargo)) {
        Write-Host "cargo not found in PATH after rustup install. You may need to start a new shell or source your profile."
    } else {
        cargo install --force cbindgen
    }
}

Write-Host "Developer tool setup complete."
Write-Host "Note: On Windows you may need Visual Studio Build Tools (MSVC) for building cdylib with the MSVC toolchain. Install the 'Desktop development with C++' workload or use the GNU toolchain via MinGW if preferred."