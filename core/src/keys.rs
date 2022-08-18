//! Mobilecoin basic key types

use core::marker::PhantomData;

use zeroize::{Zeroize};

use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic, KeyError};

/// Subaddress marker type
#[derive(Copy, Clone, Debug)]
pub struct Subaddr;

/// Root address marker type
#[derive(Copy, Clone, Debug)]
pub struct Root;

/// View key marker type
#[derive(Copy, Clone, Debug)]
pub struct View;

/// Spend key marker type
#[derive(Copy, Clone, Debug)]
pub struct Spend;

/// Generic key object, see type aliases for use
#[derive(Clone, Debug, Zeroize)]
pub struct Key<ADDR, KIND, KEY: Default + Zeroize> {
    key: KEY,
    #[zeroize(skip)]
    _addr: PhantomData<ADDR>,
    #[zeroize(skip)]
    _kind: PhantomData<KIND>,
}

/// Subaddress view private key
pub type SubaddrViewPrivate = Key<Subaddr, View, RistrettoPrivate>;
/// Subaddress spend private key
pub type SubaddrSpendPrivate = Key<Subaddr, Spend, RistrettoPrivate>;

/// Subaddress view public key
pub type SubaddrViewPublic = Key<Subaddr, View, RistrettoPublic>;
/// Subaddress spend public key
pub type SubaddrSpendPublic = Key<Subaddr, Spend, RistrettoPublic>;

/// Root view private key
pub type RootViewPrivate = Key<Root, View, RistrettoPrivate>;
/// Root spend private key
pub type RootSpendPrivate = Key<Root, Spend, RistrettoPrivate>;

/// Root view public key
pub type RootViewPublic = Key<Root, View, RistrettoPublic>;
/// Root spend public key
pub type RootSpendPublic = Key<Root, Spend, RistrettoPublic>;


/// AsRef to internal key type for backwards compatibility
impl <ADDR, KIND, KEY: Default + Zeroize> AsRef<KEY> for Key<ADDR, KIND, KEY> {
    fn as_ref(&self) -> &KEY {
        &self.key
    }
}

/// Create a default key object
impl <ADDR, KIND, KEY: Default + Zeroize> Default for Key<ADDR, KIND, KEY> {
    fn default() -> Self {
        Self{ key: KEY::default(), _addr: PhantomData, _kind: PhantomData }
    }
}

/// Shared public key methods
impl <ADDR, KIND> Key<ADDR, KIND, RistrettoPublic> {
    /// Fetch public key bytes in compressed form
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// Fetch the public key for a private key instance
impl <ADDR, KIND> From<&Key<ADDR, KIND, RistrettoPrivate>> for Key<ADDR, KIND, RistrettoPublic> {
    fn from(p: &Key<ADDR, KIND, RistrettoPrivate>) -> Self {
        Self{ key: RistrettoPublic::from(&p.key), _addr: PhantomData, _kind: PhantomData }
    }
}

/// Create a public key from [`RistrettoPublic`] object
impl <ADDR, KIND> From<RistrettoPublic> for Key<ADDR, KIND, RistrettoPublic> {
    fn from(p: RistrettoPublic) -> Self {
        Self{ key: p, _addr: PhantomData, _kind: PhantomData }
    }
}

/// Attempt to create a public key from a compressed point, wrapping [`RistrettoPublic::try_from`]
impl <ADDR, KIND> TryFrom<&[u8; 32]> for Key<ADDR, KIND, RistrettoPublic> {
    type Error = KeyError;

    fn try_from(p: &[u8; 32]) -> Result<Self, Self::Error> {
        let key = RistrettoPublic::try_from(p)?;
        Ok(Self{ key, _addr: PhantomData, _kind: PhantomData })
    }
}

/// PartialEq for public key objects
impl <ADDR, KIND> PartialEq for Key<ADDR, KIND, RistrettoPublic> {
    fn eq(&self, other: &Self) -> bool {
        &self.key == &other.key
    }
}


/// Shared private key methods
impl <ADDR, KIND> Key<ADDR, KIND, RistrettoPrivate> {
    /// Fetch private key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// Create a private key from [`RistrettoPrivate`] object
impl <ADDR, KIND> From<RistrettoPrivate> for Key<ADDR, KIND, RistrettoPrivate> {
    fn from(p: RistrettoPrivate) -> Self {
        Self{ key: p, _addr: PhantomData, _kind: PhantomData }
    }
}

/// Attempt to create a private key from a compressed point, wrapping [`RistrettoPrivate::try_from`]
impl <ADDR, KIND> TryFrom<&[u8; 32]> for Key<ADDR, KIND, RistrettoPrivate> {
    type Error = KeyError;

    fn try_from(p: &[u8; 32]) -> Result<Self, Self::Error> {
        let key = RistrettoPrivate::try_from(p)?;
        Ok(Self{ key, _addr: PhantomData, _kind: PhantomData })
    }
}

/// PartialEq via public key conversion for Private key objects
impl <ADDR, KIND> PartialEq for Key<ADDR, KIND, RistrettoPrivate> {
    fn eq(&self, other: &Self) -> bool {
        RistrettoPublic::from(&self.key) == RistrettoPublic::from(&other.key)
    }
}
