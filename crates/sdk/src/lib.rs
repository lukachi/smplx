#![doc(html_logo_url = "https://raw.githubusercontent.com/BlockstreamResearch/smplx/master/docs/simplex_logo.png")]
#![doc(html_root_url = "https://docs.rs/smplx-sdk/latest/simplex/")]
#![cfg_attr(doc, doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR" ), "/", "README.md")))]
#![cfg_attr(not(doc), doc = "Simplex SDK")]
#![warn(clippy::all, clippy::pedantic, missing_docs)]

/// The SimplicityHL compiler this SDK compiles contracts with.
///
/// Read from the workspace manifest by `build.rs` rather than written down here. A wallet
/// that refuses a manifest asking for another version has to be right about which one it
/// has, and a constant maintained by hand is right only until the dependency moves — which
/// a test can catch, but only where tests run.
pub const COMPILER_VERSION: &str = env!("SMPLX_COMPILER_VERSION");

#[cfg(test)]
mod compiler_version_tests {
    use super::COMPILER_VERSION;

    /// The build script can only fail loudly or hand back something unusable, and the second
    /// is the one nothing else would notice: an empty or malformed version reaches a wallet as
    /// a comparison that refuses every manifest declaring one. The drift test this replaces is
    /// gone because the value is no longer written by hand — what it protected is not.
    #[test]
    fn is_a_version_rather_than_whatever_the_manifest_happened_to_contain() {
        let parts: Vec<&str> = COMPILER_VERSION.split('.').collect();

        assert!(parts.len() >= 2, "not a version: {COMPILER_VERSION:?}");
        assert!(
            parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
            "not a version: {COMPILER_VERSION:?}"
        );
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
