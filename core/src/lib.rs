//! Mobilecoin core types / functions

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]
#![allow(non_snake_case)]

use zeroize::Zeroize;

pub mod consts;
use consts::*;

mod keys;
pub use keys::*;

pub mod subaddress;
pub use subaddress::Subaddress;

pub mod slip10;

/// Mobilecoin basic account object.
/// 
/// Typiclly derived via slip10, and containing root view and spend private keys.
#[derive(Zeroize)]
pub struct Account {
    /// Root view private key
    // TODO: can we make this non-public?
    pub view_private: RootViewPrivate,
    /// Root spend private key
    // TODO: can we make this non-public?
    pub spend_private: RootSpendPrivate,
}


impl Account {
    /// Create an account from existing private keys
    pub fn new(view_private: RootViewPrivate, spend_private: RootSpendPrivate) -> Self {
        Self { view_private, spend_private }
    }

    /// Fetch keys for the default subaddress
    pub fn default_subaddress(&self) -> SpendSubaddress {
        self.subaddress(DEFAULT_SUBADDRESS_INDEX)
    }
}

impl Subaddress for Account {
    type Output = SpendSubaddress;

    /// Fetch private keys for the i^th subaddress
    fn subaddress(&self, index: u64) -> Self::Output {
        let (view_private, spend_private) = (&self.view_private, &self.spend_private).subaddress(index);

        SpendSubaddress{view_private, spend_private}
    }
}

/// Mobilecoin private subaddress object
#[derive(Clone, Debug, PartialEq)]
pub struct SpendSubaddress {
    /// sub-address view private key
    pub view_private: SubaddrViewPrivate,
    /// sub-address spend private key
    pub spend_private: SubaddrSpendPrivate,
}


impl SpendSubaddress {
    /// Fetch view public address
    pub fn view_public(&self) -> SubaddrViewPublic {
        SubaddrViewPublic::from(&self.view_private)
    }

    /// Fetch spend public address
    pub fn spend_public(&self) -> SubaddrSpendPublic {
        SubaddrSpendPublic::from(&self.spend_private)
    }
}

/// Mobilecoin view-only subaddress object
#[derive(Clone, Debug, PartialEq)]
pub struct ViewSubaddress {
    /// sub-address view private key
    pub view_private: SubaddrViewPrivate,
    /// sub-address spend private key
    pub spend_public: SubaddrSpendPublic,
}

impl ViewSubaddress {
    /// Fetch view public address
    pub fn view_public(&self) -> SubaddrViewPublic {
        SubaddrViewPublic::from(&self.view_private)
    }
}

/// Mobilecoin public subaddress object
#[derive(Clone, Debug, PartialEq)]
pub struct PublicSubaddress {
    /// Public address view public key
    pub view_public: SubaddrViewPublic,
    /// Public address spend public key
    pub spend_public: SubaddrSpendPublic,
}

/// Create a [`PublicSubaddress`] object from a [`SpendSubaddress`]
impl From<&SpendSubaddress> for PublicSubaddress {
    fn from(addr: &SpendSubaddress) -> Self {
        Self{ 
            view_public: addr.view_public(),
            spend_public: addr.spend_public(),
        }
    }
}

/// Create a [`PublicSubaddress`] object from a [`ViewSubaddress`]
impl From<&ViewSubaddress> for PublicSubaddress {
    fn from(addr: &ViewSubaddress) -> Self {
        Self{ 
            view_public: addr.view_public(),
            spend_public: addr.spend_public.clone(),
        }
    }
}

