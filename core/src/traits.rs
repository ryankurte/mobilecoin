//! Traits supporting driver (or other hardware) implementations

use core::fmt::Debug;
use alloc::boxed::Box;

use async_trait::async_trait;
use rand_core::CryptoRngCore;

use mc_core_types::account::{PublicSubaddress};
use mc_crypto_keys::{RistrettoPublic, CompressedRistrettoPublic};
use mc_crypto_ring_signature::{RingMLSAG, Scalar, KeyImage};
//use mc_crypto_ring_signature_signer::SignableInputRing;

/// Transaction key image computer
#[async_trait]
pub trait KeyImageComputer {
    /// TODO
    type Error: Debug;

    /// Compute key images for a given subaddress and tx_out_public_key
    async fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<KeyImage, Self::Error>;
}

/// Transaction memo signer
#[async_trait]
pub trait MemoHmacSigner {
    /// TODO
    type Error: Debug;

    /// Compute the HMAC signature for the provided memo and target address
    async fn compute_memo_hmac_sig(
        &mut self,
        tx_public_key: RistrettoPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error>;
}

/// Transaction memo encryptor
#[async_trait]
pub trait MemoEncryptor {
    /// TODO
    type Error: Debug;

    /// Compute the HMAC signature for the provided memo and target address
    async fn encrypt_memo(
        &mut self,
        tx_public_key: RistrettoPublic,
        target_subaddress: PublicSubaddress,
        memo_payload: &[u8; 64],
    ) -> Result<[u8; 16], Self::Error>;
}


/// Generic signable input ring
pub trait SignableRing {

}

/// Transaction ring signer
#[async_trait]
pub trait RingSigner {
    /// TODO
    type Error: Debug;

    /// Sign an input ring, returning the signed object
    async fn sign<RNG: CryptoRngCore + Sync + Send>(
        &mut self,
        message: &[u8],
        signable_ring: impl SignableRing,
        output_blinding: Scalar,
        rng: RNG,
    ) -> Result<RingMLSAG, Self::Error>;
}

