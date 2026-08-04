#![warn(clippy::all, clippy::pedantic, missing_docs)]
//! WebAssembly bindings for the Simplex SDK.
//!
//! This crate exists so the SDK itself stays free of `wasm-bindgen` annotations and the
//! binding surface can be exactly what a host needs rather than the whole SDK. It follows
//! the arrangement `lwk_wasm` already uses.
//!
//! The surface is deliberately small and grows with the host that consumes it. What is
//! here is enough to establish that the module loads, that compilation runs inside the
//! browser, and that a value derived from a compiled contract crosses the boundary.

use std::sync::Arc;

use simplicityhl::Arguments;

use smplx_sdk::program::{ArgumentsTrait, Program};
use smplx_sdk::provider::SimplicityNetwork;

use wasm_bindgen::prelude::*;

/// Compile-time parameters for a contract, resolved before construction.
///
/// Held as an already-parsed `Arguments` so a malformed set is rejected when the caller
/// supplies it, rather than at the moment a covenant address is being derived.
#[derive(Clone)]
struct FixedArguments(Arguments);

impl ArgumentsTrait for FixedArguments {
    fn build_arguments(&self) -> Arguments {
        self.0.clone()
    }
}

/// Resolves a network name to the SDK's network enum.
fn network_from_str(network: &str) -> Result<SimplicityNetwork, JsError> {
    match network {
        "liquid" => Ok(SimplicityNetwork::Liquid),
        "liquid-testnet" | "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elements-regtest" | "elementsregtest" | "regtest" => Ok(SimplicityNetwork::default_regtest()),
        other => Err(JsError::new(&format!("Unknown network: {other}"))),
    }
}

/// A compiled SimplicityHL contract.
///
/// Holds the source rather than the compiled artifact: compilation runs on demand, so the
/// same object can be asked for a CMR and for an address without either being cached into
/// a state that could drift from the source it came from.
#[wasm_bindgen]
pub struct Contract {
    program: Program,
}

#[wasm_bindgen]
impl Contract {
    /// Creates a contract from SimplicityHL source text delivered at runtime.
    ///
    /// `argumentsJson` carries the contract's compile-time parameters in SimplicityHL's
    /// own `.args` shape — `{"NAME": {"value": "0x…", "type": "Pubkey"}}` — so the format
    /// is the compiler's rather than one invented here. Pass `null` for a contract that
    /// declares no parameters.
    ///
    /// Parameters participate in the covenant address, so supplying different ones for the
    /// same source yields a different address. That is the mechanism the address check
    /// relies on, not a caveat to it.
    ///
    /// # Errors
    /// Returns an error if the arguments are not valid SimplicityHL argument JSON.
    #[wasm_bindgen(constructor)]
    pub fn new(source: &str, arguments_json: Option<String>) -> Result<Contract, JsError> {
        let arguments = match arguments_json.as_deref() {
            Some(json) if !json.trim().is_empty() => serde_json::from_str::<Arguments>(json)
                .map_err(|e| JsError::new(&format!("Invalid contract arguments: {e}")))?,
            _ => Arguments::default(),
        };

        Ok(Self {
            program: Program::new(Arc::<str>::from(source), Box::new(FixedArguments(arguments))),
        })
    }

    /// Compiles the contract and returns its Commitment Merkle Root as lowercase hex.
    ///
    /// # Errors
    /// Returns an error if the source fails to compile.
    #[wasm_bindgen(js_name = commitmentMerkleRoot)]
    pub fn commitment_merkle_root(&self) -> Result<String, JsError> {
        let cmr = self
            .program
            .get_cmr()
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(hex::encode(cmr))
    }

    /// Compiles the contract and returns the taproot address its funds would sit at.
    ///
    /// # Errors
    /// Returns an error if the network name is unknown or the source fails to compile.
    #[wasm_bindgen(js_name = covenantAddress)]
    pub fn covenant_address(&self, network: &str) -> Result<String, JsError> {
        let network = network_from_str(network)?;

        Ok(self.program.get_tr_address(&network).to_string())
    }
}

/// Returns the version of the SDK compiled into this module.
#[wasm_bindgen(js_name = sdkVersion)]
#[must_use]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
