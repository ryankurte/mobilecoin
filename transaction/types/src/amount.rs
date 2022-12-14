// Copyright (c) 2018-2022 The MobileCoin Foundation

//! An aggregate which represents an amount of some token in the MobileCoin
//! blockchain.

use crate::token::TokenId;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "prost")]
use prost::Message;
use zeroize::Zeroize;

use mc_crypto_ring_signature::CurveScalar;
use mc_crypto_digestible::Digestible;

/// An amount of some token, in the "base" (u64) denomination.
#[derive(Clone, Copy, Debug, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Amount {
    /// The "raw" value of this amount as a u64
    pub value: u64,
    /// The token-id which is the denomination of this amount
    pub token_id: TokenId,
}

impl Amount {
    /// Create a new amount
    pub fn new(value: u64, token_id: TokenId) -> Self {
        Self { value, token_id }
    }
}

impl Default for Amount {
    fn default() -> Self {
        Amount::new(0, 0.into())
    }
}

/// The "unmasked" data of an amount commitment
#[derive(Clone, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "prost", derive(Message))]
pub struct UnmaskedAmount {
    /// The value of the amount commitment
    #[cfg_attr(feature = "prost", prost(fixed64, tag = 1))]
    pub value: u64,

    /// The token id of the amount commitment
    #[cfg_attr(feature = "prost", prost(fixed64, tag = 2))]
    pub token_id: u64,

    /// The blinding factor of the amount commitment
    #[cfg_attr(feature = "prost", prost(message, required, tag = 3))]
    pub blinding: CurveScalar,
}
