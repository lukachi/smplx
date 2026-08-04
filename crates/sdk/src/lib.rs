#![doc(html_logo_url = "https://raw.githubusercontent.com/BlockstreamResearch/smplx/master/docs/simplex_logo.png")]
#![doc(html_root_url = "https://docs.rs/smplx-sdk/latest/simplex/")]
#![cfg_attr(doc, doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR" ), "/", "README.md")))]
#![cfg_attr(not(doc), doc = "Simplex SDK")]
#![warn(clippy::all, clippy::pedantic, missing_docs)]

/// The SimplicityHL compiler this SDK compiles contracts with.
///
/// A wallet that refuses a manifest asking for another version has to be right about which
/// one it has, so this is pinned to the workspace's dependency by a test that reads the
/// manifest rather than by anyone remembering to update it.
pub const COMPILER_VERSION: &str = "0.6.0";

#[cfg(test)]
mod compiler_version_tests {
    use super::COMPILER_VERSION;

    /// Fails when the dependency moves and this constant does not, which is the only way the
    /// constant can lie — and a lying constant refuses a manifest that should have built.
    #[test]
    fn matches_the_workspace_dependency() {
        let workspace = include_str!("../../../Cargo.toml");
        let declared = workspace
            .lines()
            .find_map(|line| line.strip_prefix("simplicityhl = { version = \""))
            .and_then(|rest| rest.split('"').next())
            .expect("the workspace should pin simplicityhl");

        assert_eq!(declared, COMPILER_VERSION);
    }
}

/// Common constants and identifiers used across the Simplex SDK.
pub mod constants;
/// Global state, configuration, and shared context used throughout the SDK.
pub mod global;
/// Core abstractions, definitions, and errors for compiling and evaluating Simplicity programs.
pub mod program;
/// Interfaces and implementations for interacting with blockchain nodes and APIs.
pub mod provider;
/// Traits and mechanisms for signing transactions and satisfying witness requirements.
pub mod signer;
/// Constructs and builders for assembling, tracking, and managing Elements transactions.
pub mod transaction;
/// General utility functions, conversions, and helper tools.
pub mod utils;
