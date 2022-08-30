//! Container type alternative approach to newtype/macro magic
//! in repr-bytes etc.

use core::{marker::PhantomData, any::type_name};

use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;

/// Container type for byte-array / points etc.
pub struct Container<TY: Marker, INNER> {
    inner: INNER,
    _ty: PhantomData<TY>,
}

/// Default conversion from inner type
impl <TY: Marker, INNER> From<INNER> for Container<TY, INNER> {
    fn from(inner: INNER) -> Self {
        Self{ inner, _ty: PhantomData }
    }
}

/// Default conversion from clonable inner type reference
impl <TY: Marker, INNER: Clone> From<&INNER> for Container<TY, INNER> {
    fn from(inner: &INNER) -> Self {
        Self{ inner: inner.clone(), _ty: PhantomData }
    }
}

/// Access inner value as reference
impl <TY: Marker, INNER> AsRef<INNER> for Container<TY, INNER> {
    fn as_ref(&self) -> &INNER {
        &self.inner
    }
}

/// Access inner value as mutable reference
impl <TY: Marker, INNER> AsMut<INNER> for Container<TY, INNER> {
    fn as_mut(&mut self) -> &mut INNER {
        &mut self.inner
    }
}

/// Implement [`Digestible`] for inner digestible types
impl <TY: Marker, INNER: Digestible> Digestible for Container<TY, INNER> {
    fn append_to_transcript<DT: mc_crypto_digestible::DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        self.inner.append_to_transcript(context, transcript)
    }
}

/// [`core::fmt::LowerHex`] for containers with inner types implementing `AsRef<[u8]>`
impl <TY: Marker, INNER: AsRef<[u8]>> core::fmt::LowerHex for Container<TY, INNER> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data = self.inner.as_ref();
        for d in data {
            write!(f, "{:02x}", d)?;
        }
        Ok(())
    }
}

/// [`core::fmt::UpperHex`] for containers with inner types implementing `AsRef<[u8]>`
impl <TY: Marker, INNER: AsRef<[u8]>> core::fmt::UpperHex for Container<TY, INNER> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data = self.inner.as_ref();
        for d in data {
            write!(f, "{:02X}", d)?;
        }
        Ok(())
    }
}

/// [`core::fmt::Debug`] for containers with inner types implementing `AsRef<[u8]>`
impl <TY: Marker, INNER: AsRef<[u8]>> core::fmt::Debug for Container<TY, INNER> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({})", type_name::<TY>(), self)
    }
}

/// [`core::fmt::Display`] for containers with inner types implementing `AsRef<[u8]>`
impl <TY: Marker, INNER: AsRef<[u8]>> core::fmt::Display for Container<TY, INNER> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self)
    }
}

/// Marker trait to be implemented by marker types
pub trait Marker {}


/// Key image marker type
pub struct KeyImageX;

impl Marker for KeyImageX {}

/// The "image" of a private key `x`: I = x * Hp(x * G) = x * Hp(P).
pub type KeyImage = Container<KeyImageX, CompressedRistretto>;

// TODO: on a whole this is pretty neat, but, there are conditions this breaks down, like subfield serialization :-( unsure whether this can be addressed / avoided
