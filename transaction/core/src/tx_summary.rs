// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The TxSummary is meant to reduce the complexity of implementing a hardware
//! wallet. (See MCIP 52)
//!
//! Hardware wallets have the following issue:
//! * The main function they want to perform is signing RingMLSAG. This only
//!   requires sending about 1kb of data and can be fast even on a slow
//!   connection and slow device.
//! * However, if they want to be able to display to the user what it is that
//!   they are signing, i.e. how much money is being transferred to who, and
//!   verify that this is correct on the device, then they have to be able to
//!   trace the "extended message digest" back to the TxPrefix.outputs list and
//!   see where these inputs they are signing away are going to.
//! * Unfortunately, computing the extended message digest is very annoying,
//!   because it depends on essentially the entire TxPrefix. A Tx may have as
//!   many as 16 TxIn's. Each TxIn has 11 mixins. Each mixin may contain a
//!   merkle proof with say 30 merkle proof elements. Each merkle proof element
//!   is 40 bytes. So suddenly, we have a need to stream > 100 kb of data to the
//!   device so that it can compute this digest, and if any piece of data is
//!   skipped, then the digest will be wrong and cannot be verified.
//!
//! The point of the TxSummary is to avoid the need for them to have to stream
//! all of this data to be confident about what is the balance of the Tx that
//! they are signing.
//!
//! The idea is similar to merkle proof verification. You don't have to see the
//! entire data set to be convinced that the piece you care about is part of the
//! hash, you can be supplied with hashes for the branches of the tree that you
//! aren't specifically interested in, and then be convinced that the data you
//! are interested is part of the root hash.
//!
//! So, we:
//! * Take the existing extended message digest (32 bytes)
//! * Use that to start a new Merlin transcript
//! * Martial the TxSummary into this new Merlin transcript
//! * A 32 byte digest resulting from that is new "extended message with tx
//!   summary digest", and this is what the MLSAG actually sign.
//!
//! The TxSummary contains:
//! * For each output in TxPrefix.outputs, the public key, target key, and
//!   masked amount.
//! * The list of pseudo output commitments.
//!
//! These data can be produced easily during Tx validation without major
//! changes. They don't contain any secrets that the enclave isn't supposed to
//! have.
//!
//! For the hardware wallet, what we can do is:
//! * When we want to start signing MLSAGs, we send the 32 byte extended message
//!   digest, and the TxSummary. The device can compute the "extended message
//!   with tx summary digest" and sign MLSAGs over that.
//! * For each output in the summary, the device expects the host computer to
//!   ADDITONALLY supply this subset of the arguments to TxOut::new:
//!   * block_version,
//!   * amount,
//!   * recipient,
//!   * tx_private_key,
//! * These are not part of the TxSummary (because the consensus enclave can't
//!   know them) but can be part of TxSummaryUnblindingData or some such thing.
//! * For a given public key, target key, and masked amount, it is intractable
//!   to find a different amount, recipient, and tx private key that leads to
//!   the same data (discrete log hard). So the device can be convinced that
//!   these are the amounts and destinations of each such TxOut.
//! * For each pseudo output commitment, either this corresponds to an MLSAG
//!   that the device will actually sign, or it is coming from an SCI, which the
//!   device will not actually sign. For anything which the device will not
//!   actually sign, the TxSummaryUnblindingData can include the amount and
//!   blinding factor. The computer actually has this for all of the pseudo
//!   output commitments anyways.
//!
//! At this point, the device would then know the amount (value and token id) of
//! every input in the Tx, and the amount and recipient of every output in the
//! Tx. So it could completely account for the transfer of value caused by the
//! Tx, it could identify change outputs, and it could display b58 encodings of
//! the public addresses for outbound transfers. This should only require
//! sending a few KB in the worst case.
//!
//! It's reasonable to ask, what if the host computer lies to the device in the
//! TxSummary. What if, the TxPrefix actually says one thing, and the TxSummary
//! it gives to the device says another. The device cannot detect this if it
//! doesn't have insight into the extended message digest. However, in this
//! case, the transaction will simply be invalid when it is submitted, because
//! the consensus enclave will derive a different value for the TxSummary when
//! it attempts to validate the transaction, and that value will actually be
//! based on the TxPrefix. So the host computer can gain no advantage by lying
//! to the device in this way.

use crate::{
    tx::{TxOut, TxPrefix},
    CompressedCommitment, MaskedAmount,
};
use alloc::{collections::BTreeMap, vec::Vec};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_util_zip_exact::{zip_exact, ZipExactError};
use prost::Message;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A subset of the data in a Tx which enables efficient verification (e.g. by a
/// HW wallet) of the inputs and outputs of a transaction being signed.
#[derive(Clone, Deserialize, Digestible, Eq, Hash, Message, PartialEq, Serialize, Zeroize)]
pub struct TxSummary {
    /// The outputs which will be added to the blockchain as a result of this
    /// transaction
    #[prost(message, repeated, tag = "1")]
    pub outputs: Vec<TxOutSummary>,

    /// Data in the summary associated to each real input
    #[prost(message, repeated, tag = "2")]
    pub inputs: Vec<TxInSummary>,

    /// Fee paid to the foundation for this transaction
    #[prost(uint64, tag = "3")]
    pub fee: u64,

    /// Token id for the fee output of this transaction
    #[prost(uint64, tag = "4")]
    pub fee_token_id: u64,

    /// The block index at which this transaction is no longer valid.
    #[prost(uint64, tag = "5")]
    pub tombstone_block: u64,
}

impl TxSummary {
    /// Make a TxSummary for a given TxPrefix and pseudo-output commitments
    pub fn new(
        tx_prefix: &TxPrefix,
        pseudo_output_commitments: &[CompressedCommitment],
    ) -> Result<Self, ZipExactError> {
        // Scratch which helps us associate outputs to inputs with rules
        let mut input_rules_associated_tx_outs: BTreeMap<CompressedRistrettoPublic, TxOut> =
            Default::default();

        // Compute the inputs
        let inputs: Vec<TxInSummary> =
            zip_exact(tx_prefix.inputs.iter(), pseudo_output_commitments.iter())?
                .map(|(input, commitment)| {
                    let mut result = TxInSummary {
                        pseudo_output_commitment: *commitment,
                        ..Default::default()
                    };
                    if let Some(rules) = &input.input_rules {
                        result.input_rules_digest = rules.canonical_digest().to_vec();
                        let mut associated_tx_outs = rules.associated_tx_outs();
                        input_rules_associated_tx_outs.append(&mut associated_tx_outs);
                    }
                    result
                })
                .collect();

        let outputs: Vec<TxOutSummary> = tx_prefix
            .outputs
            .iter()
            .map(|src| TxOutSummary {
                masked_amount: src.masked_amount.clone(),
                target_key: src.target_key,
                public_key: src.public_key,
                // Check if the public key and target key of this TxOutSummary match to a TxOut in
                // the associated_tx_outs list. The masked amount is not necessarily
                // expected to match, and no other fields of TxOut are in the TxOutSummary
                // This should generally agree with `TxOut::eq_ignoring_amount`
                associated_to_input_rules: input_rules_associated_tx_outs
                    .get(&src.public_key)
                    .map(|tx_out| tx_out.target_key == src.target_key)
                    .unwrap_or(false),
            })
            .collect();

        Ok(Self {
            outputs,
            inputs,
            fee: tx_prefix.fee,
            fee_token_id: tx_prefix.fee_token_id,
            tombstone_block: tx_prefix.tombstone_block,
        })
    }
}

/// A subset of the data of a TxOut.
///
/// Fog hint and memo are omitted to reduce size and complexity on HW device,
/// which can't really do much with those and isn't very interested in them
/// anyways.
#[derive(Clone, Deserialize, Digestible, Eq, Hash, Message, PartialEq, Serialize, Zeroize)]
pub struct TxOutSummary {
    /// The amount being sent.
    // Note: These tags must match those of MaskedAmount enum in transaction-core
    #[prost(oneof = "MaskedAmount", tags = "1, 6")]
    pub masked_amount: Option<MaskedAmount>,

    /// The one-time public address of this output.
    #[prost(message, required, tag = "2")]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[prost(message, required, tag = "3")]
    pub public_key: CompressedRistrettoPublic,

    /// Whether or not this output is associated to an input with rules
    #[prost(bool, tag = "4")]
    pub associated_to_input_rules: bool,
}

/// Data in a TxSummary associated to a transaction input.
///
/// This includes only the pseudo output commitment and the InputRules if any,
/// omitting the Ring and the proofs of membership.
#[derive(Clone, Deserialize, Digestible, Eq, Hash, Message, PartialEq, Serialize, Zeroize)]
pub struct TxInSummary {
    /// Commitment of value equal to the real input.
    #[prost(message, required, tag = "1")]
    pub pseudo_output_commitment: CompressedCommitment,

    /// If there are input rules associated to this input, the canonical digest
    /// of these (per MCIP 52). If not, then this field is empty.
    #[prost(bytes, tag = "2")]
    pub input_rules_digest: Vec<u8>,
}
