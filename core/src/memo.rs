//! Memo types, signing and encryption helpers
//! 

use hkdf::Hkdf;
use sha2::Sha512;
use aes::{
    cipher::{FromBlockCipher, StreamCipher},
    Aes256, Aes256Ctr, NewBlockCipher,
};
use generic_array::{
    GenericArray,
    sequence::Split,
    typenum::{U32, U48},
};


use mc_core_types::{
    keys::{
        SubaddressSpendPrivate, SubaddressSpendPublic,
        SubaddressViewPrivate, SubaddressViewPublic,
    },
};
use mc_crypto_keys::{
    RistrettoPrivate, RistrettoPublic, RistrettoSecret,
    CompressedRistrettoPublic,
    KexReusablePrivate,
};
use mc_crypto_memo_mac::compute_category1_hmac;

/// Cleartext memo payload container
#[derive(Clone, PartialEq, Debug)]
pub struct MemoPayloadCleartext([u8; 66]);

/// Encrypted memo payload container
#[derive(Clone, PartialEq, Debug)]
pub struct MemoPayloadEncrypted([u8; 66]);

impl MemoPayloadCleartext {
    /// Encrypt a cleartext memo payload
    pub fn encrypt(self,
        sender_default_spend_private: &SubaddressSpendPrivate,
        receiver_view_public: &SubaddressViewPublic,
    ) -> MemoPayloadEncrypted {
        let MemoPayloadCleartext(mut payload) = self;

        // Perform KX against receiver subaddress view pubic key
        let shared_secret = shared_secret(sender_default_spend_private, receiver_view_public);

        // Apply encryption
        apply_keystream(&shared_secret, &mut payload);

        // Return encrypted object
        MemoPayloadEncrypted(payload)
    }
}

impl MemoPayloadEncrypted {
    /// Decrypt an encrypted memo payload
    pub fn decrypt(self,
        sender_default_spend_public: &SubaddressSpendPublic,
        receiver_view_private: &SubaddressViewPrivate,
    ) -> MemoPayloadCleartext {
        let MemoPayloadEncrypted(mut payload) = self;

        // Perform KX against sender subaddress spend public key
        let shared_secret = shared_secret(receiver_view_private, sender_default_spend_public);

        // Apply decryption
        apply_keystream(&shared_secret, &mut payload);

        // Return decrypted object
        MemoPayloadCleartext(payload)
    }
}

/// Memo HMAC container
pub struct Hmac ([u8; 16]);

impl Hmac {
    /// Compute HMAC for a given memo body
    pub fn build(
        kind: [u8; 2],
        data: &[u8; 48],
        tx_out_public_key: &RistrettoPublic,
        sender_default_spend_public: &SubaddressSpendPublic,
        receiver_view_private: &SubaddressViewPrivate,
    ) -> Result<Hmac, ()> {

        // Compute shared secret
        let shared_secret = shared_secret(receiver_view_private, sender_default_spend_public);

        // Compute HMAC for memo data
        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            &CompressedRistrettoPublic::from(tx_out_public_key),
            kind,
            &data,
        );

        Ok(Hmac(hmac_value))
    }

    /// Compute received HMAC for a given memo body
    pub fn check(
        kind: [u8; 2],
        data: &[u8; 48],
        tx_out_public_key: &RistrettoPublic,
        sender_default_spend_private: &SubaddressSpendPrivate,
        receiver_view_public: &SubaddressViewPublic,
    ) -> Result<Hmac, ()> {

        // Compute shared secret
        let shared_secret = shared_secret(sender_default_spend_private, receiver_view_public);

        // Compute HMAC for memo data
        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            &CompressedRistrettoPublic::from(tx_out_public_key),
            kind,
            &data,
        );

        Ok(Hmac(hmac_value))
    }
    
}

/// KX using sender default subaddress spend private and receiver subaddress view public
/// to determine shared secret for memo signing / encryption
pub fn shared_secret(
    private_key: impl AsRef<RistrettoPrivate>,
    public_key: impl AsRef<RistrettoPublic>,
) -> RistrettoSecret {
    let private_key: &RistrettoPrivate = private_key.as_ref();
    let shared_secret =
        private_key.key_exchange(public_key.as_ref());
    
    shared_secret
}

/// Apply AES256 keystream to the provided memo buffer
fn apply_keystream(
    shared_secret: &RistrettoSecret,
    buff: &mut [u8],
) -> () {
    // Use HKDF-SHA512 to produce an AES key and AES nonce
    let kdf = Hkdf::<Sha512>::new(Some(b"mc-memo-okm"), shared_secret.as_ref());

    // OKM is "output key material", see RFC HKDF for discussion of terms
    let mut okm = GenericArray::<u8, U48>::default();
    kdf.expand(b"", &mut okm[..])
        .expect("Digest output size is insufficient");

    let (key, nonce) = Split::<u8, U32>::split(okm);

    // Apply AES-256 in counter mode to the buffer
    let mut aes256ctr = Aes256Ctr::from_block_cipher(Aes256::new(&key), &nonce);
    aes256ctr.apply_keystream(buff);
}
