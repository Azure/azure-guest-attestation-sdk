// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    // When the "static" feature is enabled on Windows, enforce static CRT linking
    #[cfg(feature = "static")]
    {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

        if target_os == "windows" {
            if target_env == "gnu" {
                // For GNU toolchain (MinGW), enable static CRT linking
                println!("cargo:rustc-link-arg=-static");
                println!("cargo:rustc-link-arg=-static-libgcc");
                println!("cargo:warning=Building with static CRT on Windows (GNU)");
            } else if target_env == "msvc" {
                // MSVC static CRT is handled by .cargo/config.toml at workspace root
                // which sets rustflags = ["-Ctarget-feature=+crt-static"]
                println!("cargo:warning=Building with static CRT on Windows (MSVC)");
            }
        }
    }
}
