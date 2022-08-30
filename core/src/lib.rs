//! Mobilecoin core types / functions

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]
#![allow(non_snake_case)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "protos")]
use core::fmt::Debug;

pub mod consts;

pub mod keys;

pub mod subaddress;
pub use subaddress::Subaddress;

pub mod account;

pub mod mlsag;

pub mod slip10;

pub mod container;

#[cfg(feature = "protos")]
pub mod protos;

/// [`Rpc`] trait implemented for protobuf RPC-able types
#[cfg(feature = "protos")]
pub trait Rpc<'a>: TryFrom<Self::Message> + Debug + 'a {
    /// Protobuf message for a given RPC object
    type Message: prost::Message + From<&'a Self> + Debug + Default + 'a;

    /// Encode an RPC-able type to vector via `Self::Message`
    fn encode(&'a self) -> alloc::vec::Vec<u8> {
        use prost::Message;

        let m = Self::Message::from(self);
        m.encode_to_vec()
    }

    /// Decode an RPC-able type via `Self::Message`
    fn decode(buff: &[u8]) -> Result<Self, RpcError<<Self as TryFrom<Self::Message>>::Error>> {
        use prost::Message;

        let m = Self::Message::decode(buff).map_err(RpcError::Prost)?;
        let s = Self::try_from(m).map_err(RpcError::Decode)?;
        Ok(s)
    }
}

/// [`Rpc`] error type wrapping prost and type errors
#[cfg(feature = "protos")]
#[derive(Debug, Clone, PartialEq)]
pub enum RpcError<E> {
    /// Prost decoding error
    Prost(prost::DecodeError),
    /// Type conversion error
    Decode(E),
}

