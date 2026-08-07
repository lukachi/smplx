use std::sync::{Arc, OnceLock};

use bitcoin_hashes::Hash;
use dyn_clone::DynClone;

use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::elements::pset::PartiallySignedTransaction;
use simplicityhl::elements::{Address, Script, Transaction, TxOut, taproot};
use simplicityhl::simplicity::bitcoin::{XOnlyPublicKey, secp256k1};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::{BitMachine, RedeemNode, Value, leaf_version};
use simplicityhl::{CompiledProgram, UnstableFeatures};
use simplicityhl::{Arguments, Parameters, WitnessTypes, WitnessValues};

use crate::global::GlobalConfig;
use crate::program::logger::ProgramLogger;

use super::arguments::ArgumentsTrait;
use super::error::ProgramError;

use crate::provider::SimplicityNetwork;
use crate::utils::{hash_script, tap_data_hash, tr_unspendable_key};

/// Executes `simplicity` programs at runtime.
///
/// This trait defines a core behavior related to testing and execution.
pub trait ProgramTrait: DynClone {
    /// Retrieves the types of arguments required by a `simplicity` program.
    ///
    /// # Errors
    /// Returns a `ProgramError` if parsing or generating ABI metadata fails.
    fn get_argument_types(&self) -> Result<Parameters, ProgramError>;

    /// Retrieves the witness types required by a `simplicity` program.
    ///
    /// # Errors
    /// Returns a `ProgramError` if parsing or generating ABI metadata fails.
    fn get_witness_types(&self) -> Result<WitnessTypes, ProgramError>;

    /// Constructs the Elements environment for a specified input index, PST, and network for further program execution.
    ///
    /// # Errors
    /// Returns a `ProgramError` if the input index is out of bounds or if the script pubkey of the UTXO mismatches the expected program script.
    fn get_env(
        &self,
        pst: &PartiallySignedTransaction,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<ElementsEnv<Arc<Transaction>>, ProgramError>;

    /// Executes a Simplicity program for the given input index of a partially signed transaction.
    ///
    /// This function evaluates a Simplicity script associated with a specific transaction input
    /// in a given network, producing the result of the computation along with the redeem node
    /// used during execution.
    ///
    /// # Errors
    /// Returns a `ProgramError` if loading the program, satisfying the witness, retrieving the environment, or executing the `BitMachine` fails.
    fn execute(
        &self,
        pst: &PartiallySignedTransaction,
        witness: &WitnessValues,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<(Arc<RedeemNode>, Value), ProgramError>;

    /// Finalizes and returns `pruned_witness` as output after executing the program on certain parameters.
    ///
    /// # Errors
    /// Returns a `ProgramError` if program execution or constructing the control block fails.
    fn finalize(
        &self,
        pst: &PartiallySignedTransaction,
        witness: &WitnessValues,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<Vec<Vec<u8>>, ProgramError>;
}

/// Represents a program structure containing its public key, compiled program, and associated storage.
///
/// Abstraction giving the power to execute Simplicity contracts without specifying any additional parameters.
#[derive(Clone)]
pub struct Program {
    source: Arc<str>,
    pub_key: XOnlyPublicKey,
    /// The compile-time arguments, built once at construction rather than held as a trait
    /// object and rebuilt.
    ///
    /// Upstream takes `&dyn ArgumentsTrait` and consumes it immediately, because it compiles
    /// in the constructor. This fork compiles later, so it has to keep something — and keeping
    /// the built value rather than the builder is what lets the signature stay upstream's:
    /// a stored `Box<dyn ArgumentsTrait>` would have to outlive the call, forcing a `'static`
    /// bound the code generator does not write.
    arguments: Arguments,
    storage: Vec<Vec<u8>>,
    /// Whether this program compiles with debug symbols, which changes its CMR.
    ///
    /// Per program rather than per process: a protocol declares the mode its contracts were
    /// built in, and the wallet has to build each one the way its own protocol states or the
    /// address it derives is not the address the funds sit at. A process-wide setting cannot
    /// express that when one transaction touches two protocols.
    include_debug_symbols: Option<bool>,
    /// The compiled program, kept once it has been built.
    ///
    /// Upstream compiles in the constructor and holds the result — `feat/sdk_program_optimization`,
    /// and the reason is that one covenant costs several compilations otherwise: a control block
    /// alone asks for the script twice, and the environment and the witness satisfaction ask
    /// again. This fork cannot compile in the constructor, because the source arrives at runtime
    /// and the build mode a protocol declares is set after it. So the compilation is deferred and
    /// then kept, which is upstream's saving without upstream's requirement.
    ///
    /// Shared across clones on purpose: a clone has the same source, arguments and mode, so it
    /// has the same compiled program. Anything that changes those replaces the cell rather than
    /// writing through it.
    compiled: Arc<OnceLock<CompiledProgram>>,
}

dyn_clone::clone_trait_object!(ProgramTrait);

impl ProgramTrait for Program {
    fn get_argument_types(&self) -> Result<Parameters, ProgramError> {
        self.get_argument_types()
    }

    fn get_witness_types(&self) -> Result<WitnessTypes, ProgramError> {
        self.get_witness_types()
    }

    fn get_env(
        &self,
        pst: &PartiallySignedTransaction,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<ElementsEnv<Arc<Transaction>>, ProgramError> {
        let genesis_hash = network.genesis_block_hash();
        let cmr = self.load()?.commit().cmr();
        let utxos: Vec<TxOut> = pst.inputs().iter().filter_map(|x| x.witness_utxo.clone()).collect();

        if utxos.len() <= input_index {
            return Err(ProgramError::UtxoIndexOutOfBounds {
                input_index,
                utxo_count: utxos.len(),
            });
        }

        let target_utxo = &utxos[input_index];
        let script_pubkey = self.get_tr_address(network).script_pubkey();

        if target_utxo.script_pubkey != script_pubkey {
            return Err(ProgramError::ScriptPubkeyMismatch {
                expected_hash: script_pubkey.script_hash().to_string(),
                actual_hash: target_utxo.script_pubkey.script_hash().to_string(),
            });
        }

        Ok(ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            utxos
                .iter()
                .map(|utxo| ElementsUtxo {
                    script_pubkey: utxo.script_pubkey.clone(),
                    asset: utxo.asset,
                    value: utxo.value,
                })
                .collect(),
            u32::try_from(input_index)?,
            cmr,
            self.control_block()?,
            None,
            genesis_hash,
        ))
    }

    fn execute(
        &self,
        pst: &PartiallySignedTransaction,
        witness: &WitnessValues,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<(Arc<RedeemNode>, Value), ProgramError> {
        let satisfied = self
            .load()?
            .satisfy(witness.clone())
            .map_err(ProgramError::WitnessSatisfaction)?;

        // execute() is called multiple times during fee estimation; output is buffered
        // so only the final successful execution's logs are emitted to stderr.
        let mut tracker = ProgramLogger::make_tracker(satisfied.debug_symbols(), GlobalConfig::get_log_level());

        let env = self.get_env(pst, input_index, network)?;

        let pruned = satisfied.redeem().prune_with_tracker(&env, &mut tracker)?;

        if GlobalConfig::is_max_verbose() {
            ProgramLogger::buffer_cost_log(&pruned);
        }

        let mut mac = BitMachine::for_program(&pruned)?;

        let result = mac.exec(&pruned, &env)?;

        Ok((pruned, result))
    }

    fn finalize(
        &self,
        pst: &PartiallySignedTransaction,
        witness: &WitnessValues,
        input_index: usize,
        network: &SimplicityNetwork,
    ) -> Result<Vec<Vec<u8>>, ProgramError> {
        let pruned = self.execute(pst, witness, input_index, network)?.0;

        let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
        let cmr = pruned.cmr();

        Ok(vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            self.control_block()?.serialize(),
        ])
    }
}

impl Program {
    /// Creates a new instance of the struct with the provided source string and arguments.
    ///
    /// The source is taken by value rather than as a `&'static str`, so a program whose
    /// text arrives at runtime is as ordinary as one baked in at compile time. The arguments
    /// are taken by reference, which is upstream's shape rather than this fork's earlier
    /// `Box`: the code generator emits a call written against upstream's signature, so
    /// keeping our own made every generated artifact fail to compile.
    #[must_use]
    pub fn new(source: impl Into<Arc<str>>, arguments: &dyn ArgumentsTrait) -> Self {
        Self {
            source: source.into(),
            pub_key: tr_unspendable_key(),
            arguments: arguments.build_arguments(),
            storage: Vec::new(),
            include_debug_symbols: None,
            compiled: Arc::new(OnceLock::new()),
        }
    }

    /// Sets the `pub_key` field of the struct to the provided `XOnlyPublicKey` value and returns the updated builder instance.
    /// This is used to set the taproot public key for the program.
    #[must_use]
    pub fn with_taproot_pubkey(mut self, pub_key: XOnlyPublicKey) -> Self {
        self.pub_key = pub_key;

        self
    }

    /// Builds this program in the mode its protocol declares, rather than the process's.
    ///
    /// The flag is not cosmetic: it wraps tracked expressions in extra Simplicity nodes, so
    /// it changes the CMR and therefore the covenant address. Leaving it unset falls back to
    /// the process-wide configuration, which is what a caller with no declaration to follow
    /// should do.
    #[must_use]
    pub fn with_debug_symbols(mut self, include: bool) -> Self {
        self.include_debug_symbols = Some(include);
        // The mode decides the CMR, so a result compiled under the old one is not this program's.
        self.compiled = Arc::new(OnceLock::new());

        self
    }

    /// Sets storage capacity for further usage.
    #[must_use]
    pub fn with_storage_capacity(mut self, capacity: usize) -> Self {
        self.storage = vec![vec![0u8; 32]; capacity];

        self
    }

    /// Sets a 32-byte value at the specified index in the storage.
    ///
    /// # Panics
    /// Panics if the `index` is out of bounds for the initiasized storage.
    pub fn set_storage_at(&mut self, index: usize, new_value: impl Into<Vec<u8>>) {
        let slot = self.storage.get_mut(index).expect("Index out of bounds");

        *slot = new_value.into();
    }

    /// Returns the number of storage chunks for a program.
    #[must_use]
    pub fn get_storage_len(&self) -> usize {
        self.storage.len()
    }

    /// Returns storage as a whole array of 32-byte chunks.
    #[must_use]
    pub fn get_storage(&self) -> &[Vec<u8>] {
        &self.storage
    }

    /// Returns storage value at a certain index.
    ///
    /// # Panics
    /// Panics if the `index` is out of bounds for the initiated storage.
    #[must_use]
    pub fn get_storage_at(&self, index: usize) -> Vec<u8> {
        self.storage[index].clone()
    }

    /// Returns a taproot address for a defined `SimplicityNetwork`.
    ///
    /// # Panics
    /// Panics if generating the taproot spending information fails.
    #[must_use]
    pub fn get_tr_address(&self, network: &SimplicityNetwork) -> Address {
        let spend_info = self.taproot_spending_info().unwrap();

        Address::p2tr(
            secp256k1::SECP256K1,
            spend_info.internal_key(),
            spend_info.merkle_root(),
            None,
            network.address_params(),
        )
    }

    /// Retrieves the `ScriptPubKey` associated with the Simplicity address for the specified network.
    #[must_use]
    pub fn get_script_pubkey(&self, network: &SimplicityNetwork) -> Script {
        self.get_tr_address(network).script_pubkey()
    }

    /// Retrieves the 32-byte `ScriptPubKey` hash associated with the Simplicity address for the specified network.
    #[must_use]
    pub fn get_script_hash(&self, network: &SimplicityNetwork) -> [u8; 32] {
        hash_script(&self.get_script_pubkey(network))
    }

    /// Compiles the program and returns its Commitment Merkle Root.
    ///
    /// The CMR is what a covenant address is derived from, so recomputing it is how a
    /// caller establishes for itself that a source is the one a deployed protocol used.
    ///
    /// # Errors
    /// Returns a `ProgramError` if compilation fails.
    pub fn get_cmr(&self) -> Result<[u8; 32], ProgramError> {
        Ok(self.load()?.commit().cmr().to_byte_array())
    }

    /// Returns the 32-byte tapleaf hash of the program's Simplicity script.
    ///
    /// From upstream, and fallible here rather than infallible there: this fork compiles on
    /// demand, so asking for the script can fail where upstream already held a compiled program.
    ///
    /// # Errors
    /// Returns a `ProgramError` if compilation fails.
    pub fn get_tapleaf_hash(&self) -> Result<[u8; 32], ProgramError> {
        let (script, version) = self.script_version()?;

        Ok(taproot::TapLeafHash::from_script(&script, version).to_byte_array())
    }

    /// Retrieves program ABI metadata for argument types.
    ///
    /// # Errors
    /// Returns a `ProgramError` if compilation fails or generating ABI metadata fails.
    pub fn get_argument_types(&self) -> Result<Parameters, ProgramError> {
        let abi_meta = self
            .load()?
            .generate_abi_meta()
            .map_err(ProgramError::ProgramGenAbiMeta)?;

        Ok(abi_meta.param_types)
    }

    /// Retrieves the witness types from the compiled program's ABI metadata.
    ///
    /// # Errors
    /// Returns a `ProgramError` if compilation fails or generating ABI metadata fails.
    pub fn get_witness_types(&self) -> Result<WitnessTypes, ProgramError> {
        let abi_meta = self
            .load()?
            .generate_abi_meta()
            .map_err(ProgramError::ProgramGenAbiMeta)?;

        Ok(abi_meta.witness_types)
    }

    fn load(&self) -> Result<&CompiledProgram, ProgramError> {
        if let Some(compiled) = self.compiled.get() {
            return Ok(compiled);
        }

        let compiled = CompiledProgram::new_with_unstable(
            Arc::clone(&self.source),
            &UnstableFeatures::all(),
            self.arguments.clone(),
            self.include_debug_symbols
                .unwrap_or_else(GlobalConfig::get_include_debug_symbols),
            Box::new(ElementsJetHinter),
        )
        .map_err(ProgramError::Compilation)?;

        Ok(self.compiled.get_or_init(|| compiled))
    }

    fn script_version(&self) -> Result<(Script, taproot::LeafVersion), ProgramError> {
        let cmr = self.load()?.commit().cmr();
        let script = Script::from(cmr.as_ref().to_vec());

        Ok((script, leaf_version()))
    }

    /// Depths of a left-folded tap tree, in the order `TaprootBuilder` wants them.
    ///
    /// The tree is `tapbranch(tapbranch(tapbranch(cmr, e1), e2), e3)`: the program's own leaf
    /// and the first extra leaf sit deepest, and each further leaf is one level shallower.
    ///
    /// This was a balanced tree, which is what upstream builds and what nobody deploys. The
    /// reference implementation folds left, and every covenant address in existence was
    /// derived by it — so a balanced tree produces a well-formed address for a contract whose
    /// funds sit somewhere else. The two agree up to three leaves and diverge from four, which
    /// is why nothing noticed until a protocol carried three extra leaves.
    fn taproot_leaf_depths(total_leaves: usize) -> Vec<usize> {
        assert!(total_leaves > 0, "Taproot tree must contain at least one leaf");

        let extra = total_leaves - 1;
        let mut depths = Vec::with_capacity(total_leaves);

        depths.push(extra);
        depths.extend((1..=extra).rev());

        depths
    }

    fn taproot_spending_info(&self) -> Result<taproot::TaprootSpendInfo, ProgramError> {
        let mut builder = taproot::TaprootBuilder::new();
        let (script, version) = self.script_version()?;
        let depths = Self::taproot_leaf_depths(1 + self.get_storage_len());

        builder = builder
            .add_leaf_with_ver(depths[0], script, version)
            .expect("tap tree should be valid");

        for (slot, depth) in self.get_storage().iter().zip(depths.into_iter().skip(1)) {
            builder = builder
                .add_hidden(depth, tap_data_hash(slot))
                .expect("tap tree should be valid");
        }

        Ok(builder
            .finalize(secp256k1::SECP256K1, self.pub_key)
            .expect("tap tree should be valid"))
    }

    fn control_block(&self) -> Result<taproot::ControlBlock, ProgramError> {
        let info = self.taproot_spending_info()?;
        let script_ver = self.script_version()?;

        Ok(info.control_block(&script_ver).expect("control block should exist"))
    }
}

#[cfg(test)]
mod tests {
    use simplicityhl::{
        Arguments,
        elements::{AssetId, confidential, pset::Input},
    };

    use super::*;

    // simplicityhl/examples/cat.simf
    const DUMMY_PROGRAM: &str = r"
        fn main() {
            let ab: u16 = <(u8, u8)>::into((0x10, 0x01));
            let c: u16 = 0x1001;
            assert!(jet::eq_16(ab, c));
            let ab: u8 = <(u4, u4)>::into((0b1011, 0b1101));
            let c: u8 = 0b10111101;
            assert!(jet::eq_8(ab, c));
        }
    ";

    #[derive(Clone)]
    struct EmptyArguments;

    impl ArgumentsTrait for EmptyArguments {
        fn build_arguments(&self) -> Arguments {
            Arguments::default()
        }
    }

    fn dummy_asset_id(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).unwrap()
    }

    // Upstream compiles in the constructor and keeps the result, and that is a saving rather
    // than a style: one covenant asks for the compiled program six to eight times — a control
    // block alone asks twice, then the environment and the witness satisfaction ask again. This
    // fork defers the compilation because the source arrives at runtime, so the saving has to be
    // kept deliberately. A merge with upstream dropped it once by resolving in this fork's
    // favour without asking what upstream's change was for; this is what makes that visible.
    #[test]
    fn compiles_once_and_keeps_it() {
        let program = dummy_program();

        let first = program.load().expect("the dummy program compiles");
        let second = program.load().expect("the dummy program compiles");

        assert!(std::ptr::eq(first, second), "the program was compiled twice");
    }

    // And a program asked to build differently is a different program, so the kept result must
    // not survive the change: the mode decides the CMR and therefore the address.
    #[test]
    fn a_changed_build_mode_is_not_served_the_old_compilation() {
        let plain = dummy_program();
        let plain_cmr = plain.get_cmr().expect("compiles");

        let debug = dummy_program().with_debug_symbols(true);
        let debug_cmr = debug.get_cmr().expect("compiles");

        assert_ne!(plain_cmr, debug_cmr, "the build mode did not reach the compiler");
    }

    fn dummy_program() -> Program {
        Program::new(DUMMY_PROGRAM, &EmptyArguments)
    }

    fn dummy_network() -> SimplicityNetwork {
        SimplicityNetwork::default_regtest()
    }

    fn make_pst_with_script(script: Script) -> PartiallySignedTransaction {
        let txout = TxOut {
            asset: confidential::Asset::Explicit(dummy_asset_id(0xAA)),
            value: confidential::Value::Explicit(1000),
            script_pubkey: script,
            ..Default::default()
        };
        let input = Input {
            witness_utxo: Some(txout),
            ..Default::default()
        };

        let mut pst = PartiallySignedTransaction::new_v2();

        pst.add_input(input);

        pst
    }

    #[test]
    fn test_get_env_idx() {
        let program = dummy_program();
        let network = dummy_network();

        let correct_script = program.get_script_pubkey(&network);
        let wrong_script = Script::new();

        let mut pst = make_pst_with_script(wrong_script);

        let correct_txout = TxOut {
            asset: confidential::Asset::Explicit(dummy_asset_id(0xAA)),
            value: confidential::Value::Explicit(1000),
            script_pubkey: correct_script,
            ..Default::default()
        };

        pst.add_input(Input {
            witness_utxo: Some(correct_txout),
            ..Default::default()
        });

        // take a script with a wrong pubkey
        assert!(matches!(
            program.get_env(&pst, 0, &network).unwrap_err(),
            ProgramError::ScriptPubkeyMismatch { .. }
        ));

        assert!(program.get_env(&pst, 1, &network).is_ok());
    }

    // Upstream's `test_taproot_leaf_depths_known_values` stood here and asserted a balanced
    // tree — [2, 2, 2, 2] at four leaves. This fork folds left, because every deployed covenant
    // address was derived by the reference implementation, which folds left. So that test had
    // been failing since the fold changed, and keeping it beside these would be two tests
    // asserting opposite things about one function. It is replaced rather than deleted: what it
    // was protecting — that the depths are pinned and cannot drift unnoticed — is what these do.
    // The reference implementation folds the tap tree left, and every deployed covenant
    // address was derived that way. These are the depths a left fold needs, in the order
    // TaprootBuilder consumes them: the program's leaf and the first extra sit deepest, and
    // each further extra leaf is one level shallower.
    #[test]
    fn left_folded_depths() {
        assert_eq!(Program::taproot_leaf_depths(1), vec![0]);
        assert_eq!(Program::taproot_leaf_depths(2), vec![1, 1]);
        assert_eq!(Program::taproot_leaf_depths(3), vec![2, 2, 1]);
        assert_eq!(Program::taproot_leaf_depths(4), vec![3, 3, 2, 1]);
        assert_eq!(Program::taproot_leaf_depths(5), vec![4, 4, 3, 2, 1]);
    }

    // The measured boundary: a balanced tree agrees with a left fold up to three leaves and
    // diverges from four. Four leaves balanced is [2, 2, 2, 2]; left-folded it is not.
    #[test]
    fn diverges_from_a_balanced_tree_at_four_leaves() {
        assert_eq!(Program::taproot_leaf_depths(3), vec![2, 2, 1]);
        assert_ne!(Program::taproot_leaf_depths(4), vec![2, 2, 2, 2]);
    }
}
