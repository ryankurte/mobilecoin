//! Account and subaddress objects
//! 
//! 
//! 

use zeroize::Zeroize;

use crate::keys::{
    RootSpendPrivate, RootViewPrivate,
    RootSpendPublic, RootViewPublic,
    SubaddrSpendPrivate, SubaddrSpendPublic,
    SubaddrViewPrivate, SubaddrViewPublic,
};

/// An object which represents a subaddress, and has RingCT-style
/// view and spend public keys.
pub trait RingCtAddress {
    /// Get the subaddress' view public key
    fn view_public_key(&self) -> SubaddrViewPublic;
    /// Get the subaddress' spend public key
    fn spend_public_key(&self) -> SubaddrSpendPublic;
}


/// Mobilecoin basic account object.
/// 
/// Typically derived via slip10, and containing root view and spend private keys.
#[derive(Debug, Zeroize)]
pub struct Account {
    /// Root view private key
    view_private: RootViewPrivate,
    /// Root spend private key
    spend_private: RootSpendPrivate,
}

impl Account {
    /// Create an account from existing private keys
    pub fn new(view_private: RootViewPrivate, spend_private: RootSpendPrivate) -> Self {
        Self { view_private, spend_private }
    }

    /// Fetch account view public key
    pub fn view_public_key(&self) -> RootViewPublic {
        RootViewPublic::from(&self.view_private)
    }

    /// Fetch account spend public key
    pub fn spend_public_key(&self) -> RootSpendPublic {
        RootSpendPublic::from(&self.spend_private)
    }

    /// Fetch account view private key
    pub fn view_private_key(&self) -> &RootViewPrivate {
        &self.view_private
    }

    /// Fetch account spend private key
    pub fn spend_private_key(&self) -> &RootSpendPrivate {
        &self.spend_private
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


impl RingCtAddress for SpendSubaddress {
    /// Fetch view public address
    fn view_public_key(&self) -> SubaddrViewPublic {
        SubaddrViewPublic::from(&self.view_private)
    }

    /// Fetch spend public address
    fn spend_public_key(&self) -> SubaddrSpendPublic {
        SubaddrSpendPublic::from(&self.spend_private)
    }
}

impl SpendSubaddress {
    /// Fetch subaddress view private key
    pub fn view_private_key(&self) -> &SubaddrViewPrivate {
        &self.view_private
    }

    /// Fetch subaddress spend private key
    pub fn spend_private_key(&self) -> &SubaddrSpendPrivate {
        &self.spend_private
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

impl RingCtAddress for ViewSubaddress {
    /// Fetch view public address
    fn view_public_key(&self) -> SubaddrViewPublic {
        SubaddrViewPublic::from(&self.view_private)
    }

    /// Fetch spend public address
    fn spend_public_key(&self) -> SubaddrSpendPublic {
        self.spend_public.clone()
    }
}

impl ViewSubaddress {
    /// Fetch subaddress view private key
    pub fn view_private_key(&self) -> &SubaddrViewPrivate {
        &self.view_private
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

impl RingCtAddress for PublicSubaddress {
    /// Fetch view public address
    fn view_public_key(&self) -> SubaddrViewPublic {
        self.view_public.clone()
    }

    /// Fetch spend public address
    fn spend_public_key(&self) -> SubaddrSpendPublic {
        self.spend_public.clone()
    }
}

/// Create a [`PublicSubaddress`] object from a [`SpendSubaddress`]
impl From<&SpendSubaddress> for PublicSubaddress {
    fn from(addr: &SpendSubaddress) -> Self {
        Self{ 
            view_public: addr.view_public_key(),
            spend_public: addr.spend_public_key(),
        }
    }
}

/// Create a [`PublicSubaddress`] object from a [`ViewSubaddress`]
impl From<&ViewSubaddress> for PublicSubaddress {
    fn from(addr: &ViewSubaddress) -> Self {
        Self{ 
            view_public: addr.view_public_key(),
            spend_public: addr.spend_public_key(),
        }
    }
}
