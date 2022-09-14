//! Basic RingMLSAG implementation
//! 
//! (`no_std` equivalent of [`mc_crypto_ring_signature::RingMLSAG`])

use zeroize::Zeroize;

use mc_crypto_ring_signature::{
    CryptoRngCore, Error, Scalar,
    CompressedCommitment,
};

pub use mc_crypto_ring_signature::{
    MlsagSignParams, MlsagSignCtx, MlsagVerify, Ring,
};

use mc_crypto_ring_signature::{CurveScalar, KeyImage};

#[cfg(feature = "protos")]
use crate::protos;

use crate::consts::MAX_TXOUTS;

/// Maximum number of challenges in ring signature
pub const MAX_RESPONSES: usize = MAX_TXOUTS * 2;

/// RingMLSAG Signature object
/// 
/// Mirrors [`mc_crypto_ring_signature::RingMLSAG`] while using internal allocation,
/// provides proto compatibility via [`crate::Rpc`] interface where `protos` feature is enabled.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingMLSAG<const RING_SIZE: usize = MAX_TXOUTS, const RESP_SIZE: usize = MAX_RESPONSES> {
    /// The initial challenge `c[0]`.
    pub c_zero: CurveScalar,

    /// Responses `r_{0,0}, r_{0,1}, ... , r_{ring_size-1,0},
    /// r_{ring_size-1,1}`.
    pub responses: heapless::Vec<CurveScalar, RESP_SIZE>,

    /// Key image "spent" by this signature.
    pub key_image: KeyImage,
}

impl <const RING_SIZE: usize, const RESP_SIZE: usize> RingMLSAG<RING_SIZE, RESP_SIZE> {
    /// Generate a ring signature with the provided options
    pub fn sign<'a>(ring: impl Ring, opts: &MlsagSignParams<'a>, rng: impl CryptoRngCore) -> Result<Self, Error> {
        let ring_size = ring.size();

        // Check bounds
        if ring_size > RING_SIZE {
            return Err(Error::LengthMismatch(ring_size, RING_SIZE));
        }
        if ring_size * 2 > RESP_SIZE {
            return Err(Error::LengthMismatch(ring_size * 2, RESP_SIZE));
        }

        // Setup buffers for recomputed_c and decompressed rings
        let (mut challenges, mut responses) = (
            heapless::Vec::<_, RING_SIZE>::new(),
            heapless::Vec::<_, RESP_SIZE>::new(),
        );

        challenges.resize(ring_size, Scalar::zero()).unwrap();
        responses.resize(ring_size * 2, CurveScalar::from(Scalar::zero())).unwrap();

        let mut decompressed_ring = heapless::Vec::<_, RING_SIZE>::new();
        for i in 0..ring_size {
            decompressed_ring.push(ring.index(i)?).unwrap();
        }

        // Perform ring signing
        let key_image = opts.sign(&decompressed_ring[..], rng, &mut challenges, &mut responses)?;


        let r = RingMLSAG {
            c_zero: CurveScalar::from(challenges[0]),
            key_image,
            responses,
        };

        // Zeroize buffers
        challenges.iter_mut().for_each(|v| v.zeroize() );

        Ok(r)
    }

    /// Verify a ring signature with the provided options
    pub fn verify<R: Ring>(
        &self,
        message: &[u8],
        ring: R,
        output_commitment: &CompressedCommitment,
    ) -> Result<(), Error> {
        let ring_size = ring.size();

        // Setup buffer for recomputed challenges
        let mut recomputed_c = heapless::Vec::<_, RING_SIZE>::new();
        for _i in 0..ring_size {
            let _ = recomputed_c.push(Scalar::zero());
        }

        let mut decompressed_ring = heapless::Vec::<_, RING_SIZE>::new();
        for i in 0..ring_size {
            let _ = decompressed_ring.push(ring.index(i)?);
        }

        // Setup and execute verification
        let opts = MlsagVerify{
            key_image: &self.key_image,
            c_zero: &self.c_zero,
            responses: &self.responses,
            message,
            ring: &decompressed_ring[..],
            output_commitment,
        };

        // Execute verification
        // (not returning here to ensure buffers get zeroized)
        let res = opts.verify(&mut recomputed_c);
    
        // Zeroize buffers
        recomputed_c.iter_mut().for_each(|v| v.zeroize() );

        res
    }
    
}

// NOTE: this protos stuff sorta duplicates that in `api`, why do we need prost everywhere given there are already prost / non-prost conversions there?

/// Convert from mc_core [`RingMLSAG`] to RPC compatible [`protos::RingMLSAG`] message
#[cfg(feature = "protos")]
impl TryFrom<protos::RingMlsag> for RingMLSAG {
    type Error = mc_crypto_ring_signature::Error;

    fn try_from(k: protos::RingMlsag) -> Result<RingMLSAG, Self::Error> {
        let c_zero = match &k.c_zero {
            Some(v) => CurveScalar::try_from(v.data.as_slice())?,
            None => todo!(),
        };

        let key_image = match &k.key_image {
            Some(v) => KeyImage::try_from(v.data.as_slice())?,
            None => todo!(),
        };

        let responses = heapless::Vec::new();

        Ok(RingMLSAG{ c_zero, responses, key_image })
    } 
}

/// Convert from RPC compatible [`protos::RingMLSAG`] to internal [`RingMLSAG`] message
#[cfg(feature = "protos")]
impl From<RingMLSAG> for protos::RingMlsag {
    fn from(k: RingMLSAG) -> protos::RingMlsag {
        protos::RingMlsag{
            c_zero: Some(protos::CurveScalar{
                data: k.c_zero.as_bytes().to_vec() }),
            key_image: Some(protos::KeyImage{ 
                data: k.key_image.as_bytes().to_vec() }),
            responses: k.responses.iter()
                .map(|r| protos::CurveScalar{ data: r.as_bytes().to_vec() } )
                .collect(),
        }
    } 
}

#[cfg(test)]
mod test {
    // TODO
}
