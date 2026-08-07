//! Reads the SimplicityHL version the workspace pins, so the SDK cannot be wrong about it.
//!
//! It was a constant beside a test that failed when the two drifted. That catches the drift,
//! but only where tests run — a build that ships without running them would ship a constant
//! that lies, and a wallet whose compiler version is wrong refuses manifests that should have
//! built. Reading the manifest here makes the value correct at build time instead of merely
//! checked afterwards.

use std::{env, fs, path::PathBuf};

fn main() {
    let workspace = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets this")).join("../../Cargo.toml");

    println!("cargo:rerun-if-changed={}", workspace.display());

    let manifest = fs::read_to_string(&workspace)
        .unwrap_or_else(|error| panic!("the workspace manifest should be readable: {error}"));

    let version = manifest
        .lines()
        .find_map(|line| line.trim().strip_prefix("simplicityhl = { version = \""))
        .and_then(|rest| rest.split('"').next())
        .expect("the workspace should pin simplicityhl");

    println!("cargo:rustc-env=SMPLX_COMPILER_VERSION={version}");
}
