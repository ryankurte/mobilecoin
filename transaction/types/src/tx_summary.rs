//! Summary types for use when computing TxSummaries etc.


use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "prost")]
use prost::Message;

use mc_crypto_digestible::Digestible;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::CompressedCommitment;


/// A subset of the data of a TxOut.
///
/// Fog hint and memo are omitted to reduce size and complexity on HW device,
/// which can't really do much with those and isn't very interested in them
/// anyways.
#[derive(Clone, Digestible, Eq, Hash, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "prost", derive(Message))]
pub struct TxOutSummary {
    /// The amount being sent.
    // Note: These tags must match those of MaskedAmount enum in transaction-core
    #[cfg(todo)]
    #[cfg_attr(feature = "prost", prost(oneof = "MaskedAmount", tags = "1, 6"))]
    pub masked_amount: Option<MaskedAmount>,

    /// The one-time public address of this output.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "2"))]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[cfg_attr(feature = "prost", prost(message, required, tag = "3"))]
    pub public_key: CompressedRistrettoPublic,

    /// Whether or not this output is associated to an input with rules
    #[cfg_attr(feature = "prost", prost(bool, tag = "4"))]
    pub associated_to_input_rules: bool,
}

/// Data in a TxSummary associated to a transaction input.
///
/// This includes only the pseudo output commitment and the InputRules if any,
/// omitting the Ring and the proofs of membership.
#[derive(Clone, Digestible, Eq, Hash, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "prost", derive(Message))]
pub struct TxInSummary {
    /// Commitment of value equal to the real input.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "1"))]
    pub pseudo_output_commitment: CompressedCommitment,

    /// If there are input rules associated to this input, the canonical digest
    /// of these (per MCIP 52). If not, then this field is empty.
    #[cfg(todo)]
    #[cfg_attr(feature = "prost", prost(bytes, tag = "2"))]
    pub input_rules_digest: Vec<u8>,
}
