#!/usr/bin/env bash
set -euo pipefail

echo "Checking for rustup..."
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup not found. Installing..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
else
  echo "rustup found."
fi

echo "Ensuring stable toolchain is installed and active..."
rustup toolchain install stable
rustup default stable

echo "Installing cbindgen via cargo..."
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH after rustup install - restart your shell or source ~/.cargo/env"
else
  cargo install --force cbindgen
fi

echo "Developer tool setup complete."

echo "Note: For Windows builds you may need MSVC build tools (Visual Studio Build Tools). For cross builds consider using 'cross' with Docker."