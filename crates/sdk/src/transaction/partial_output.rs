use elements_miniscript::bitcoin::PublicKey;

use simplicityhl::elements::pset::Output;
use simplicityhl::elements::{AssetId, Script};

/// Where a transaction's change should go, supplied by the caller.
///
/// A host that owns its own wallet derives change addresses itself; without this the
/// signer would send change to the single address it derives internally, which for a
/// ranged-descriptor wallet is an address it does not watch.
#[derive(Debug, Clone)]
pub struct ChangeTarget {
    /// The script the change output pays to.
    pub script_pubkey: Script,
    /// The blinding public key, when the change output is confidential.
    pub blinding_key: Option<PublicKey>,
}

impl ChangeTarget {
    /// Creates an explicit (unblinded) change target.
    #[must_use]
    pub fn new(script_pubkey: Script) -> Self {
        Self { script_pubkey, blinding_key: None }
    }

    /// Attaches a blinding public key, making the change output confidential.
    #[must_use]
    pub fn with_blinding_key(mut self, blinding_key: PublicKey) -> Self {
        self.blinding_key = Some(blinding_key);

        self
    }
}

/// Represents partially prepared output data for Elements transactions.
#[derive(Debug, Clone)]
pub struct PartialOutput {
    /// Represents a bound `ScriptPubKey` for arbitrary output.
    pub script_pubkey: Script,
    /// Amount of a certain transaction output
    pub amount: u64,
    /// Amount of a certain transaction output
    pub asset: AssetId,
    /// Public key of a blinding key
    pub blinding_key: Option<PublicKey>,
}

impl PartialOutput {
    /// Creates a new `PartialOutput` assigning a base script, amount, and `AssetId`.
    #[must_use]
    pub fn new(script: Script, amount: u64, asset: AssetId) -> Self {
        Self {
            script_pubkey: script,
            amount,
            asset,
            blinding_key: None,
        }
    }

    /// Creates a new `PartialOutput` representing an `OP_RETURN` data metadata output.
    #[must_use]
    pub fn new_metadata(data: &[u8]) -> Self {
        Self {
            script_pubkey: Script::new_op_return(data),
            amount: 0,
            asset: AssetId::default(),
            blinding_key: None,
        }
    }

    /// Attaches an optional blinding public key to the partial output.
    #[must_use]
    pub fn with_blinding_key(mut self, blinding_key: PublicKey) -> Self {
        self.blinding_key = Some(blinding_key);

        self
    }

    /// Converts this `PartialOutput` into a fully formed PSET `Output`.
    #[must_use]
    pub fn to_output(&self) -> Output {
        let mut output = Output::new_explicit(self.script_pubkey.clone(), self.amount, self.asset, self.blinding_key);

        // the index doesn't really matter as we are the only signer
        if self.blinding_key.is_some() {
            output.blinder_index = Some(0);
        }

        output
    }
}
