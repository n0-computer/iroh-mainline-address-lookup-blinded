//! Ed25519 key blinding in the style of Tor v3 onion services (rend-spec-v3 A.2).
//!
//! A blinded key `A' = h·A` with `h = H(domain | A | context)` is a valid ed25519
//! verifying key. The owner of the master secret can sign under `A'`; anyone who
//! knows the master public key `A` can derive `A'`; nobody else can link `A'` back
//! to `A` or register `A'` themselves.
//!
//! Note: soundness assumes the master key is an honestly generated ed25519 key
//! (a point in the prime-order subgroup), which holds for iroh endpoint ids.

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::{Scalar, clamp_integer},
};
use ed25519_dalek::{
    Signature, VerifyingKey,
    hazmat::{ExpandedSecretKey, raw_sign},
};
use sha2::{Digest, Sha512};

/// Domain separation for the blinding factor. Baked into every derived id:
/// changing it re-keys all pseudonyms, so treat it like a wire-format constant.
const BLIND_DOMAIN: &[u8] = b"iroh blinded-lookup v0 key blinding";
/// Domain separation for the deterministic nonce prefix of blinded signing.
const PREFIX_DOMAIN: &[u8] = b"iroh blinded-lookup v0 nonce prefix";

/// Error for a master key that is not a valid ed25519 point.
#[derive(Debug, thiserror::Error)]
#[error("invalid ed25519 public key")]
pub struct InvalidKey;

/// Computes the clamped blinding factor `h` for a master public key and context.
fn blinding_factor(master_pk: &[u8; 32], context: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(BLIND_DOMAIN);
    h.update(master_pk);
    h.update(context);
    let digest = h.finalize();
    let mut factor = [0u8; 32];
    factor.copy_from_slice(&digest[..32]);
    Scalar::from_bytes_mod_order(clamp_integer(factor))
}

/// Blinds a master public key for the given context.
///
/// This is the outsider-computable half: it needs only the master *public* key.
pub fn blind_public_key(master_pk: &[u8; 32], context: &[u8]) -> Result<[u8; 32], InvalidKey> {
    let point = CompressedEdwardsY(*master_pk)
        .decompress()
        .ok_or(InvalidKey)?;
    let factor = blinding_factor(master_pk, context);
    Ok((point * factor).compress().0)
}

/// A blinded ed25519 signing key, derived from a master secret key and a context.
///
/// Signatures made with [`BlindedKeypair::sign`] verify under the standard ed25519
/// verification algorithm against [`BlindedKeypair::public_bytes`], which equals
/// [`blind_public_key`] of the master public key.
pub struct BlindedKeypair {
    esk: ExpandedSecretKey,
    public: VerifyingKey,
}

impl std::fmt::Debug for BlindedKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlindedKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl BlindedKeypair {
    /// Derives the blinded keypair from an iroh secret key and a context.
    pub fn from_master(secret: &iroh::SecretKey, context: &[u8]) -> Self {
        // Standard RFC 8032 key expansion, identical to what ed25519-dalek's
        // SigningKey does internally (clamp + reduce lower half, keep upper
        // half as the nonce prefix).
        let expanded: [u8; 64] = Sha512::digest(secret.to_bytes()).into();
        let master_esk = ExpandedSecretKey::from_bytes(&expanded);

        let master_pk = *secret.public().as_bytes();
        let factor = blinding_factor(&master_pk, context);
        let scalar = master_esk.scalar * factor;

        // The blinded key has no seed, so the nonce prefix cannot come from key
        // expansion. Derive it from the master prefix + context, domain-separated,
        // as Tor does. It only needs to be secret and deterministic per key.
        let mut h = Sha512::new();
        h.update(PREFIX_DOMAIN);
        h.update(master_esk.hash_prefix);
        h.update(context);
        let digest = h.finalize();
        let mut hash_prefix = [0u8; 32];
        hash_prefix.copy_from_slice(&digest[..32]);

        let public_point = EdwardsPoint::mul_base(&scalar).compress();
        let public = VerifyingKey::from_bytes(&public_point.0)
            .expect("scalar multiple of the base point is a valid key");

        Self {
            esk: ExpandedSecretKey {
                scalar,
                hash_prefix,
            },
            public,
        }
    }

    /// The blinded public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Signs a message under the blinded key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        raw_sign::<Sha512>(&self.esk, message, &self.public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinded_signatures_verify_and_keys_agree() {
        let secret = iroh::SecretKey::from_bytes(&[7u8; 32]);
        let master_pk = *secret.public().as_bytes();
        let context = b"test-context";

        let keypair = BlindedKeypair::from_master(&secret, context);
        // Insider derivation from the public key matches the owner's keypair.
        let derived = blind_public_key(&master_pk, context).unwrap();
        assert_eq!(keypair.public_bytes(), derived);
        // The pseudonym is not the master key, and contexts don't collide.
        assert_ne!(derived, master_pk);
        assert_ne!(
            derived,
            blind_public_key(&master_pk, b"other-context").unwrap()
        );

        // Signatures verify under the plain ed25519 verifier (what DHT nodes run).
        let message = b"3:seqi1e1:v5:hello";
        let sig = keypair.sign(message);
        let verifier = VerifyingKey::from_bytes(&derived).unwrap();
        verifier.verify_strict(message, &sig).unwrap();
    }
}
