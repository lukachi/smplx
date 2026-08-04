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
use simplicityhl::elements::{AssetId, OutPoint, Script, Sequence, TxOut, Txid};
use simplicityhl::{Arguments, WitnessValues};

use smplx_sdk::program::{ArgumentsTrait, Program, WitnessTrait};
use smplx_sdk::signer::Signer;
use smplx_sdk::transaction::{
    ChangeTarget, FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
    UTXO,
};
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
    /// `extraLeavesJson` is a JSON array of hex strings, each an already-encoded taproot
    /// leaf payload appended to the tree in declaration order. They are payloads rather than
    /// programs and are added as hidden nodes, and their bytes are as much a part of the
    /// address as the parameters are — which is why they arrive encoded rather than as values
    /// this module would have to guess a representation for.
    ///
    /// # Errors
    /// Returns an error if the arguments are not valid SimplicityHL argument JSON, or if the
    /// extra leaves are not a JSON array of hex strings.
    #[wasm_bindgen(constructor)]
    pub fn new(
        source: &str,
        arguments_json: Option<String>,
        extra_leaves_json: Option<String>,
        include_debug_symbols: Option<bool>,
    ) -> Result<Contract, JsError> {
        let arguments = match arguments_json.as_deref() {
            Some(json) if !json.trim().is_empty() => serde_json::from_str::<Arguments>(json)
                .map_err(|e| JsError::new(&format!("Invalid contract arguments: {e}")))?,
            _ => Arguments::default(),
        };

        let mut program =
            Program::new(Arc::<str>::from(source), Box::new(FixedArguments(arguments)));

        if let Some(include) = include_debug_symbols {
            program = program.with_debug_symbols(include);
        }

        if let Some(json) = extra_leaves_json.as_deref().filter(|json| !json.trim().is_empty()) {
            let leaves: Vec<String> = serde_json::from_str(json)
                .map_err(|e| JsError::new(&format!("Invalid extra leaves: {e}")))?;

            program = program.with_storage_capacity(leaves.len());

            for (index, leaf) in leaves.iter().enumerate() {
                let bytes = hex::decode(leaf.strip_prefix("0x").unwrap_or(leaf))
                    .map_err(|e| JsError::new(&format!("Extra leaf {index} is not hex: {e}")))?;

                program.set_storage_at(index, bytes);
            }
        }

        Ok(Self { program })
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

    /// Compiles the contract and returns the scriptPubKey its funds sit behind, as hex.
    ///
    /// The address is for showing a person; this is for comparing against an output and for
    /// building one, which is what the wallet actually does with it.
    ///
    /// # Errors
    /// Returns an error if the network name is unknown or the source fails to compile.
    #[wasm_bindgen(js_name = scriptPubKeyHex)]
    pub fn script_pubkey_hex(&self, network: &str) -> Result<String, JsError> {
        let network = network_from_str(network)?;

        Ok(hex::encode(
            self.program.get_script_pubkey(&network).as_bytes(),
        ))
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

    /// The scriptPubKey of the signer's own address, as lowercase hex.
    ///
    /// This is what a wallet output pays to, so it is what the caller encodes into the
    /// `TxOut` of an input it wants signed, and what it passes as the change script.
    #[wasm_bindgen(js_name = scriptPubKeyHex)]
    #[must_use]
    pub fn script_pubkey_hex(&self) -> String {
        hex::encode(self.signer.get_address().script_pubkey().as_bytes())
    }

    /// The blinding public key, as lowercase hex.
    #[wasm_bindgen(js_name = blindingPublicKey)]
    #[must_use]
    pub fn blinding_public_key(&self) -> String {
        hex::encode(self.signer.get_blinding_public_key().to_bytes())
    }

    /// Blinds, signs and finalises an assembled transaction.
    ///
    /// The fee rate and the change target are supplied rather than discovered: the module
    /// has no network, and change must go to an address the wallet actually watches. Coin
    /// selection is assumed done — this adds the change and fee outputs and nothing else.
    ///
    /// # Errors
    /// Returns an error if the change target cannot be parsed, or if the transaction
    /// cannot be balanced, blinded, signed or finalised.
    #[wasm_bindgen(js_name = finalizeTransaction)]
    pub fn finalize_transaction(
        &self,
        builder: &TransactionBuilder,
        fee_rate: f32,
        change_script_pubkey_hex: &str,
        change_blinding_key_hex: Option<String>,
    ) -> Result<SignedTransaction, JsError> {
        let script = Script::from(
            hex::decode(change_script_pubkey_hex)
                .map_err(|e| JsError::new(&format!("Invalid change script: {e}")))?,
        );

        let mut change = ChangeTarget::new(script);

        if let Some(blinding_key) = change_blinding_key_hex.as_deref() {
            let key = PublicKey::from_str(blinding_key)
                .map_err(|e| JsError::new(&format!("Invalid change blinding key: {e}")))?;

            change = change.with_blinding_key(key);
        }

        let (transaction, fee_sats) = self
            .signer
            .finalize_strict(builder.inner(), fee_rate, Some(&change))
            .map_err(|e| JsError::new(&format!("Could not finalise the transaction: {e}")))?;

        Ok(SignedTransaction {
            fee_sats,
            hex: elements::encode::serialize_hex(&transaction),
            txid: transaction.txid().to_string(),
        })
    }
}


/// Applies a manifest's declared sequence to an input, when it declared one.
///
/// A sequence is a relative timelock: it says how long after the output it spends was
/// confirmed this transaction may enter a block. A covenant can require one, and a
/// transaction built without it is rejected by the chain rather than by anything here, so
/// dropping the declaration silently would fail late and unexplainably.
fn with_sequence(input: PartialInput, sequence: Option<u32>) -> PartialInput {
    match sequence {
        Some(value) => input.with_sequence(Sequence(value)),
        None => input,
    }
}

/// Witness values for a covenant input, resolved before the transaction is assembled.
///
/// Held as parsed `WitnessValues` so a malformed set is rejected when the caller supplies
/// it rather than in the middle of signing.
#[derive(Clone)]
struct FixedWitness(WitnessValues);

impl WitnessTrait for FixedWitness {
    fn build_witness(&self) -> WitnessValues {
        self.0.clone()
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
    pub fn add_wallet_input(
        &mut self,
        txid: &str,
        vout: u32,
        tx_out_hex: &str,
        sequence: Option<u32>,
    ) -> Result<(), JsError> {
        let outpoint = OutPoint {
            txid: Txid::from_str(txid).map_err(|e| JsError::new(&format!("Invalid txid: {e}")))?,
            vout,
        };

        let bytes = hex::decode(tx_out_hex)
            .map_err(|e| JsError::new(&format!("Invalid output encoding: {e}")))?;
        let txout: TxOut = elements::encode::deserialize(&bytes)
            .map_err(|e| JsError::new(&format!("Invalid output: {e}")))?;

        self.transaction.add_input(
            with_sequence(
                PartialInput::new(UTXO {
                    outpoint,
                    secrets: None,
                    txout,
                }),
                sequence,
            ),
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

    /// Adds a covenant input: an output locked by a Simplicity program, spent by satisfying it.
    ///
    /// `witness_json` carries the witness values in SimplicityHL's own `.wit` shape. Passing
    /// `null` leaves them unset, which is what a pre-approval dry-run wants: unsupplied
    /// witnesses are zero-filled and pruned, so the program's shape can be checked without
    /// producing a signature before anyone has agreed to one.
    ///
    /// `signature_witness` names the witness the signer must fill with a Schnorr signature
    /// over this transaction. Most covenants authenticate whoever spends them, and a witness
    /// the caller cannot produce in advance is exactly the one the signer exists to make;
    /// leaving this `null` says the program needs no signature, which is true of very few
    /// real covenants and was previously the only thing this could say.
    ///
    /// # Errors
    /// Returns an error if the txid, the encoded output, the arguments or the witness cannot
    /// be parsed.
    #[wasm_bindgen(js_name = addCovenantInput)]
    pub fn add_covenant_input(
        &mut self,
        txid: &str,
        vout: u32,
        tx_out_hex: &str,
        source: &str,
        arguments_json: Option<String>,
        witness_json: Option<String>,
        signature_witness: Option<String>,
        sequence: Option<u32>,
    ) -> Result<(), JsError> {
        let outpoint = OutPoint {
            txid: Txid::from_str(txid).map_err(|e| JsError::new(&format!("Invalid txid: {e}")))?,
            vout,
        };

        let bytes = hex::decode(tx_out_hex)
            .map_err(|e| JsError::new(&format!("Invalid output encoding: {e}")))?;
        let txout: TxOut = elements::encode::deserialize(&bytes)
            .map_err(|e| JsError::new(&format!("Invalid output: {e}")))?;

        let arguments = match arguments_json.as_deref() {
            Some(json) if !json.trim().is_empty() => serde_json::from_str::<Arguments>(json)
                .map_err(|e| JsError::new(&format!("Invalid contract arguments: {e}")))?,
            _ => Arguments::default(),
        };

        let witness = match witness_json.as_deref() {
            Some(json) if !json.trim().is_empty() => serde_json::from_str::<WitnessValues>(json)
                .map_err(|e| JsError::new(&format!("Invalid witness values: {e}")))?,
            _ => WitnessValues::default(),
        };

        let program = Program::new(Arc::<str>::from(source), Box::new(FixedArguments(arguments)));

        self.transaction.add_program_input(
            with_sequence(
                PartialInput::new(UTXO {
                    outpoint,
                    secrets: None,
                    txout,
                }),
                sequence,
            ),
            ProgramInput {
                program: Box::new(program),
                witness: Box::new(FixedWitness(witness)),
            },
            match signature_witness {
                Some(name) if !name.trim().is_empty() => RequiredSignature::Witness(name),
                _ => RequiredSignature::None,
            },
        );

        Ok(())
    }

    /// Runs the Simplicity program of one covenant input against this transaction.
    ///
    /// This is the dry-run: it satisfies the witness, prunes the branches the spend does not
    /// take, and executes the result on a BitMachine. It proves the program runs against
    /// *this* transaction — not that a signature the caller has not made yet will satisfy it,
    /// which is a different claim and needs a second run after signing.
    ///
    /// # Errors
    /// Returns an error if the input is not a covenant input, or if the program fails to
    /// satisfy, prune or execute.
    #[wasm_bindgen(js_name = dryRunCovenantInput)]
    pub fn dry_run_covenant_input(&self, input_index: usize, network: &str) -> Result<(), JsError> {
        let network = network_from_str(network)?;
        let inputs = self.transaction.inputs();
        let input = inputs
            .get(input_index)
            .ok_or_else(|| JsError::new(&format!("There is no input at index {input_index}.")))?;
        let program_input = input.program_input.as_ref().ok_or_else(|| {
            JsError::new(&format!("Input {input_index} is not a covenant input."))
        })?;

        let (pst, _secrets) = self.transaction.extract_pst();

        program_input
            .program
            .execute(
                &pst,
                &program_input.witness.build_witness(),
                input_index,
                &network,
            )
            .map_err(|e| JsError::new(&format!("Input {input_index} did not execute: {e}")))?;

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

impl TransactionBuilder {
    /// The assembled transaction, for the signer in this crate.
    fn inner(&self) -> &FinalTransaction {
        &self.transaction
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A finished transaction and the fee it pays.
#[wasm_bindgen]
pub struct SignedTransaction {
    fee_sats: u64,
    hex: String,
    txid: String,
}

#[wasm_bindgen]
impl SignedTransaction {
    /// The consensus-encoded transaction, ready to broadcast.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hex(&self) -> String {
        self.hex.clone()
    }

    /// The transaction id it will have once broadcast.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn txid(&self) -> String {
        self.txid.clone()
    }

    /// The fee it pays, in satoshis.
    #[wasm_bindgen(getter, js_name = feeSats)]
    #[must_use]
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }
}

/// Returns the version of the SDK compiled into this module.
#[wasm_bindgen(js_name = sdkVersion)]
#[must_use]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The SimplicityHL compiler version compiled into this module.
///
/// Read from the dependency at build time rather than written down, because a wallet that
/// refuses a manifest asking for another version has to be right about which one it has.
/// A constant maintained by hand would drift from the compiler on the first upgrade, and
/// the failure would be a refusal of a manifest that should have built.
#[wasm_bindgen(js_name = compilerVersion)]
#[must_use]
pub fn compiler_version() -> String {
    smplx_sdk::COMPILER_VERSION.to_string()
}
