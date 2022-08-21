//! Mobilecoin Subaddress Derivations
 
use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};

use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

use crate::consts::*;

use crate::keys::*;


/// Generate a subaddress for a given input key set
pub trait Subaddress {
    /// Subaddress type
    type Output: core::fmt::Debug;

    /// Generate the subaddress for the corresponding index
    fn subaddress(&self, index: u64) -> Self::Output;
}

/// Generate subadress private keys from root private keys
impl <'a> Subaddress for (&'a RootViewPrivate, &'a RootSpendPrivate) {
    type Output = (SubaddrViewPrivate, SubaddrSpendPrivate);

    fn subaddress(&self, index: u64) -> Self::Output {
        let (view_private, spend_private) = (&self.0, &self.1);

        let a: &Scalar = view_private.as_ref().as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b512::new();
            digest.update(SUBADDRESS_DOMAIN_TAG);
            digest.update(a.as_bytes());
            digest.update(n.as_bytes());
            Scalar::from_hash(digest)
        };

        // Return private subaddress keys
        let b: &Scalar = spend_private.as_ref().as_ref();
        (
            SubaddrViewPrivate::from(RistrettoPrivate::from(a * (Hs + b))),
            SubaddrSpendPrivate::from(RistrettoPrivate::from(Hs + b))
        )
    }
}

/// Generate subaddress public keys from root view private and spend public keys
impl <'a> Subaddress for (&'a RootViewPrivate, &'a RootSpendPublic) {
    type Output = (SubaddrViewPublic, SubaddrSpendPublic);

    fn subaddress(&self, index: u64) -> Self::Output {
        let (view_private, spend_public) = (&self.0, &self.1);

        // Generate spend public
        let a: &Scalar = view_private.as_ref().as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b512::new();
            digest.update(SUBADDRESS_DOMAIN_TAG);
            digest.update(a.as_bytes());
            digest.update(n.as_bytes());
            Scalar::from_hash(digest)
        };

        let b = RistrettoPrivate::from(Hs);
        let B = RistrettoPublic::from(&b);

        // Return public subaddress keys
        let C: RistrettoPoint = B.as_ref() + spend_public.as_ref().as_ref();
        (
            SubaddrViewPublic::from(RistrettoPublic::from(a * C)),
            SubaddrSpendPublic::from(RistrettoPublic::from(C)),
        )
    }
}

#[cfg(test)]
mod tests {

    use mc_util_test_vector::TestVector;
    use mc_util_test_with_data::test_with_data;
    use mc_test_vectors_definitions::account_keys::DefaultSubaddrKeysFromAcctPrivKeys;

    use super::*;
    
    #[test_with_data(DefaultSubaddrKeysFromAcctPrivKeys::from_jsonl("../test-vectors/vectors"))]
    fn default_subaddr_keys_from_acct_priv_keys(case: DefaultSubaddrKeysFromAcctPrivKeys) {
        // Load in keys from test vector
        let root_spend_private = RootSpendPrivate::try_from(&case.spend_private_key).unwrap();
        let root_view_private = RootViewPrivate::try_from(&case.view_private_key).unwrap();

        // Generate private subaddress keys from root view and spend private
        let (subaddr_view_private, subaddr_spend_private) = (&root_view_private, &root_spend_private).subaddress(DEFAULT_SUBADDRESS_INDEX);

        // Test subaddress private keys match expectations
        assert_eq!(
            subaddr_view_private.to_bytes(),
            case.subaddress_view_private_key
        );
        assert_eq!(
            subaddr_spend_private.to_bytes(),
            case.subaddress_spend_private_key
        );

        // Check subaddress public keys match expectations
        assert_eq!(
            SubaddrViewPublic::from(&subaddr_view_private).to_bytes(),
            case.subaddress_view_public_key
        );
        assert_eq!(
            SubaddrSpendPublic::from(&subaddr_spend_private).to_bytes(),
            case.subaddress_spend_public_key
        );
    }

    #[test_with_data(DefaultSubaddrKeysFromAcctPrivKeys::from_jsonl("../test-vectors/vectors"))]
    fn default_subaddr_keys_from_acct_view_keys(case: DefaultSubaddrKeysFromAcctPrivKeys) {
        // Load in keys from test vector
        let root_spend_private = RootSpendPrivate::try_from(&case.spend_private_key).unwrap();
        let root_view_private = RootViewPrivate::try_from(&case.view_private_key).unwrap();
        let root_spend_public = RootSpendPublic::from(&root_spend_private);

        // Generate public subaddress keys from root view private and spend public
        let (subaddr_view_public, subaddr_spend_public) = (&root_view_private, &root_spend_public).subaddress(DEFAULT_SUBADDRESS_INDEX);

        // Check expectations match
        assert_eq!(
            subaddr_view_public.to_bytes(),
            case.subaddress_view_public_key
        );
        assert_eq!(
            subaddr_spend_public.to_bytes(),
            case.subaddress_spend_public_key
        );
    }
}
