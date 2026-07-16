param(
    [switch]$Html,
    [switch]$Lcov,
    [string]$Output = "lcov.info"
)

$ErrorActionPreference = 'Stop'

function Ensure-Tool($name, $check, $install) {
    if (-not (Get-Command $check -ErrorAction SilentlyContinue)) {
        Write-Host "[$name] installing..." -ForegroundColor Cyan
        & cargo install $install
    }
}

Write-Host "== azure-guest-attestation-sdk coverage ==" -ForegroundColor Green
Push-Location (Join-Path $PSScriptRoot '..' 'rust-core')

Ensure-Tool 'cargo-llvm-cov' 'cargo-llvm-cov' 'cargo-llvm-cov'

# Always run a clean baseline to avoid stale profraw
Write-Host "Cleaning previous coverage artifacts" -ForegroundColor DarkGray
cargo llvm-cov clean --workspace

# Activate the in-process reference TPM harness via the custom cfg flag.
# cargo-llvm-cov appends its instrumentation flags to any existing RUSTFLAGS.
$env:RUSTFLAGS = '--cfg vtpm_tests'

$commonArgs = @('--','--test-threads=1')

if ($Html) {
    Write-Host "Generating HTML coverage report..." -ForegroundColor Cyan
    cargo llvm-cov --html @commonArgs
    $htmlPath = Join-Path (Get-Location) 'target/llvm-cov/html/index.html'
    if (Test-Path $htmlPath) {
        Write-Host "HTML report: $htmlPath" -ForegroundColor Green
    } else {
        Write-Warning "HTML report not found."
    }
} elseif ($Lcov) {
    Write-Host "Generating LCOV report $Output..." -ForegroundColor Cyan
    cargo llvm-cov --lcov --output-path $Output @commonArgs
    if (Test-Path $Output) {
        Write-Host "LCOV file: $(Resolve-Path $Output)" -ForegroundColor Green
    } else {
        Write-Warning "LCOV file not generated."
    }
} else {
    Write-Host "Running coverage summary (text)..." -ForegroundColor Cyan
    cargo llvm-cov @commonArgs
}

Pop-Location
