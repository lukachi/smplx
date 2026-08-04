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

use std::str::FromStr;
use std::sync::Arc;

use elements_miniscript::bitcoin::PublicKey;

use simplicityhl::elements;
use simplicityhl::elements::{AssetId, OutPoint, Script, TxOut, Txid};
use simplicityhl::Arguments;

use smplx_sdk::program::{ArgumentsTrait, Program};
use smplx_sdk::signer::Signer;
use smplx_sdk::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature, UTXO};
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

/// The wallet's signing key material, inside the module.
///
/// # This holds the whole account secret
///
/// It is constructed from an account mnemonic, so every key derivable from that account
/// lives here for as long as the object does — wider than any single action needs. That
/// is accepted debt, not an oversight: signing derives from a key at a fixed path while
/// blinding derives from a SLIP77 master key that an extended private key does not carry,
/// so the alternatives are two separate derived secrets or a callback interface holding
/// none of them.
///
/// The cost, the two rejected alternatives, and the conditions that should reopen the
/// choice are recorded under "Accepted debt: the account mnemonic crosses into the wasm
/// module" in the change record for this work. Narrow it before this module gains a code
/// path outliving a single action, before a release intended for people who are not us,
/// or before a second consumer depends on it.
///
/// Call `free()` when the action is done rather than letting it sit in the wasm heap.
#[wasm_bindgen]
pub struct WalletSigner {
    signer: Signer,
    network: SimplicityNetwork,
}

#[wasm_bindgen]
impl WalletSigner {
    /// Creates a signer from an account mnemonic.
    ///
    /// # Errors
    /// Returns an error if the network name is unknown.
    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: &str, network: &str) -> Result<WalletSigner, JsError> {
        let network = network_from_str(network)?;

        Ok(Self {
            signer: Signer::from_mnemonic(mnemonic, network),
            network,
        })
    }

    /// The unblinded address of the signer's own key.
    #[wasm_bindgen(js_name = address)]
    #[must_use]
    pub fn address(&self) -> String {
        let _ = &self.network;

        self.signer.get_address().to_string()
    }

    /// The confidential address of the signer's own key.
    #[wasm_bindgen(js_name = confidentialAddress)]
    #[must_use]
    pub fn confidential_address(&self) -> String {
        self.signer.get_confidential_address().to_string()
    }

    /// The x-only public key used for Schnorr and taproot, as lowercase hex.
    ///
    /// This is what a covenant locking to "the wallet's key" is parameterised with, so it
    /// is the value that goes into a manifest parameter naming the signer.
    #[wasm_bindgen(js_name = schnorrPublicKey)]
    #[must_use]
    pub fn schnorr_public_key(&self) -> String {
        hex::encode(self.signer.get_schnorr_public_key().serialize())
    }

    /// The blinding public key, as lowercase hex.
    #[wasm_bindgen(js_name = blindingPublicKey)]
    #[must_use]
    pub fn blinding_public_key(&self) -> String {
        hex::encode(self.signer.get_blinding_public_key().to_bytes())
    }
}


/// A transaction under construction.
///
/// Inputs cross as an outpoint plus the raw `TxOut` they spend; nothing secret crosses
/// per input, because the signer already holds the SLIP77 material that unblinds the
/// wallet's own confidential outputs.
///
/// Coin selection is the caller's — this assembles exactly what it is given and adds only
/// the change and fee outputs. That is deliberate: the wallet knows which of its outputs
/// it is willing to spend, and a module that selected for it would be choosing on its
/// behalf.
#[wasm_bindgen]
pub struct TransactionBuilder {
    transaction: FinalTransaction,
}

#[wasm_bindgen]
impl TransactionBuilder {
    /// Starts an empty transaction.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            transaction: FinalTransaction::new(),
        }
    }

    /// Adds an ordinary wallet input, spending the output at `txid:vout`.
    ///
    /// `tx_out_hex` is the consensus encoding of the output being spent, which is what the
    /// wallet already has from its own snapshot or a chain read.
    ///
    /// # Errors
    /// Returns an error if the txid or the encoded output cannot be parsed.
    #[wasm_bindgen(js_name = addWalletInput)]
    pub fn add_wallet_input(&mut self, txid: &str, vout: u32, tx_out_hex: &str) -> Result<(), JsError> {
        let outpoint = OutPoint {
            txid: Txid::from_str(txid).map_err(|e| JsError::new(&format!("Invalid txid: {e}")))?,
            vout,
        };

        let bytes = hex::decode(tx_out_hex)
            .map_err(|e| JsError::new(&format!("Invalid output encoding: {e}")))?;
        let txout: TxOut = elements::encode::deserialize(&bytes)
            .map_err(|e| JsError::new(&format!("Invalid output: {e}")))?;

        self.transaction.add_input(
            PartialInput::new(UTXO {
                outpoint,
                secrets: None,
                txout,
            }),
            RequiredSignature::NativeEcdsa,
        );

        Ok(())
    }

    /// Adds an output paying `amount_sats` of `asset_hex` to `script_pubkey_hex`.
    ///
    /// A blinding key makes the output confidential. Covenant and OP_RETURN outputs are
    /// always unblinded, because Simplicity's introspection jets cannot read a
    /// confidential commitment.
    ///
    /// # Errors
    /// Returns an error if the script, asset id or blinding key cannot be parsed.
    #[wasm_bindgen(js_name = addOutput)]
    pub fn add_output(
        &mut self,
        script_pubkey_hex: &str,
        amount_sats: u64,
        asset_hex: &str,
        blinding_key_hex: Option<String>,
    ) -> Result<(), JsError> {
        let script = Script::from(
            hex::decode(script_pubkey_hex)
                .map_err(|e| JsError::new(&format!("Invalid script: {e}")))?,
        );
        let asset = AssetId::from_str(asset_hex)
            .map_err(|e| JsError::new(&format!("Invalid asset id: {e}")))?;

        let mut output = PartialOutput::new(script, amount_sats, asset);

        if let Some(blinding_key) = blinding_key_hex.as_deref() {
            let key = PublicKey::from_str(blinding_key)
                .map_err(|e| JsError::new(&format!("Invalid blinding key: {e}")))?;

            output = output.with_blinding_key(key);
        }

        self.transaction.add_output(output);

        Ok(())
    }

    /// How many inputs and outputs this transaction currently carries.
    #[wasm_bindgen(js_name = inputCount)]
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.transaction.n_inputs()
    }

    /// How many outputs this transaction currently carries.
    #[wasm_bindgen(js_name = outputCount)]
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.transaction.n_outputs()
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the version of the SDK compiled into this module.
#[wasm_bindgen(js_name = sdkVersion)]
#[must_use]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
