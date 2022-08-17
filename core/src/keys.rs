//! Mobilecoin basic key types

use zeroize::Zeroize;

use sha2::{Sha512, Digest};

use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic, KeyError};

/// Mobilecoin view private key
#[derive(Clone, Debug, Zeroize)]
pub struct ViewPrivate(RistrettoPrivate);

impl ViewPrivate {
    /// Fetch view private key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// PartialEq via hash...
/// TODO: is this the correct approach?
impl PartialEq for ViewPrivate {
    fn eq(&self, other: &Self) -> bool {
        Sha512::digest(&self.0) == Sha512::digest(&other.0)
    }
}

/// Create a [`ViewPrivate`] key from [`RistrettoPrivate`] object
impl From<RistrettoPrivate> for ViewPrivate {
    fn from(p: RistrettoPrivate) -> Self {
        Self(p)
    }
}

/// Attempt to create a [`ViewPrivate`] key from raw bytes, wrapping [`RistrettoPrivate::try_from`]
impl TryFrom<&[u8; 32]> for ViewPrivate {
    type Error = KeyError;

    fn try_from(s: &[u8; 32]) -> Result<Self, Self::Error> {
        let p = RistrettoPrivate::try_from(s)?;
        Ok(Self(p))
    }
}


/// AsRef to [`RistrettoPrivate`] for backwards compatibility
impl AsRef<RistrettoPrivate> for ViewPrivate {
    fn as_ref(&self) -> &RistrettoPrivate {
        &self.0
    }
}

/// Fetch view public key from private key
impl From<&ViewPrivate> for ViewPublic {
    fn from(view_private: &ViewPrivate) -> Self {
        Self(RistrettoPublic::from(view_private.as_ref()))
    }
}


/// Mobilecoin view public key
#[derive(Clone, PartialEq, Debug, Zeroize)]
pub struct ViewPublic(RistrettoPublic);


impl From<RistrettoPublic> for ViewPublic {
    fn from(p: RistrettoPublic) -> Self {
        Self(p)
    }
}

/// AsRef to [`RistrettoPublic`] for backwards compatibility
impl AsRef<RistrettoPublic> for ViewPublic {
    fn as_ref(&self) -> &RistrettoPublic {
        &self.0
    }
}

impl ViewPublic {
    /// Fetch view public key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Mobilecoin spend private key
#[derive(Clone, Debug, Zeroize)]
pub struct SpendPrivate(RistrettoPrivate);

/// Create a [`SpendPrivate`] key from [`RistrettoPrivate`] object
impl From<RistrettoPrivate> for SpendPrivate {
    fn from(p: RistrettoPrivate) -> Self {
        Self(p)
    }
}

/// PartialEq via hash...
/// TODO: is this the correct approach?
impl PartialEq for SpendPrivate {
    fn eq(&self, other: &Self) -> bool {
        Sha512::digest(&self.0) == Sha512::digest(&other.0)
    }
}

/// Attempt to create a [`SpendPrivate`] key from raw bytes, wrapping [`RistrettoPrivate::try_from`]
impl TryFrom<&[u8; 32]> for SpendPrivate {
    type Error = KeyError;

    fn try_from(s: &[u8; 32]) -> Result<Self, Self::Error> {
        let p = RistrettoPrivate::try_from(s)?;
        Ok(Self(p))
    }
}

/// AsRef to [`RistrettoPrivate`] for backwards compatibility
impl AsRef<RistrettoPrivate> for SpendPrivate {
    fn as_ref(&self) -> &RistrettoPrivate {
        &self.0
    }
}

impl SpendPrivate {
    /// Fetch spend private key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Fetch spend public key from private key
impl From<&SpendPrivate> for SpendPublic {
    fn from(view_private: &SpendPrivate) -> Self {
        Self(RistrettoPublic::from(view_private.as_ref()))
    }
}

/// Mobilecoin spend public key
#[derive(Clone, PartialEq, Debug, Zeroize)]
pub struct SpendPublic(RistrettoPublic);

/// AsRef to [`RistrettoPublic`] for backwards compatibility
impl AsRef<RistrettoPublic> for SpendPublic {
    fn as_ref(&self) -> &RistrettoPublic {
        &self.0
    }
}

impl From<RistrettoPublic> for SpendPublic {
    fn from(p: RistrettoPublic) -> Self {
        Self(p)
    }
}

impl TryFrom<&[u8; 32]> for SpendPublic {
    type Error = KeyError;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        let p = RistrettoPublic::try_from(value)?;
        Ok(Self(p))
    }
}

impl SpendPublic {
    /// Fetch spend public key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

fn display_private(key: &[u8], f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    // Compute digest of key (to avoid displaying real value)
    let h = Sha512::digest(key);

    // Encode to b64 for conciseness
    let mut buff = [0u8; 64 * 4 / 3 + 3];
    let n = base64::encode_config_slice(&h, base64::STANDARD, &mut buff);

    // Convert to string, should be infallible but no unsafe allowed here
    let s = match core::str::from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => return Err(core::fmt::Error),
    };

    // Write display string
    write!(f, "sha512:{}", s)
}

fn display_public(key: &[u8], f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    // Encode to b64 for conciseness
    let mut buff = [0u8; 64 * 4 / 3 + 3];
    let n = base64::encode_config_slice(key, base64::STANDARD, &mut buff);

    // Convert to string, should be infallible but no unsafe allowed here
    let s = match core::str::from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => return Err(core::fmt::Error),
    };

    // Write display string
    write!(f, "{}", s)
}
