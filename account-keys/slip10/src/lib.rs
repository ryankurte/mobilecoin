//! MobileCoin SLIP-0010-Based Key Derivation

// NOTE: implementation _and_ tests moved to `core/src/slip10.rs`

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]

// Re-export to minimise change propagation
// TODO: chat about preferred approach to this
pub use mc_core::slip10::{Slip10Key, Slip10KeyGenerator};

