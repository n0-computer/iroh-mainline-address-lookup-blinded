//! Payload sealing for blinded records.
//!
//! The symmetric key is derived from the master *public* key: anyone who knows
//! the endpoint id (the same capability needed to even find the record) can
//! decrypt; DHT crawlers see only an opaque, fixed-size blob. This is a
//! capability scheme, not public-key encryption.
//!
//! The nonce is random, so every seal produces a fresh ciphertext even for
//! unchanged data: an observer of the pseudonym cannot distinguish a periodic
//! republish from an actual change of the record. What remains observable is
//! liveness only.

use chacha20poly1305::{
    AeadCore, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload},
};
use sha2::{Digest, Sha512};

/// Domain separation for the symmetric key. A wire-format constant.
const KEY_DOMAIN: &[u8] = b"iroh blinded-lookup v1 payload key";

/// Plaintexts are zero-padded to this size before sealing so that record sizes
/// don't fingerprint their contents. Sealed size is `PAD_TO` + 24 (nonce) + 16
/// (tag) = 488 bytes, comfortably under the 1000 byte BEP44 value limit.
pub const PAD_TO: usize = 448;

/// Errors from [`open`].
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("sealed record too short")]
    TooShort,
    #[error("decryption failed")]
    Failed,
}

fn derive_key(master_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(KEY_DOMAIN);
    h.update(master_pk);
    let digest = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

/// Seals a plaintext for the given master public key.
///
/// Returns `nonce || ciphertext`. The plaintext is zero-padded to [`PAD_TO`]
/// (postcard tolerates trailing zeros, so no length prefix is needed); longer
/// plaintexts are sealed unpadded rather than rejected.
pub fn seal(master_pk: &[u8; 32], context: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = derive_key(master_pk);

    let mut padded = plaintext.to_vec();
    if padded.len() < PAD_TO {
        padded.resize(PAD_TO, 0);
    }

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let cipher = XChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &padded,
                aad: context,
            },
        )
        .expect("encryption is infallible for in-memory buffers");

    let mut sealed = Vec::with_capacity(24 + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed
}

/// Opens a sealed record for the given master public key.
///
/// Returns the padded plaintext; decode with a format that tolerates trailing
/// zeros (postcard does).
pub fn open(master_pk: &[u8; 32], context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < 24 + 16 {
        return Err(SealError::TooShort);
    }
    let key = derive_key(master_pk);
    let (nonce, ciphertext) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new(&key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: context,
            },
        )
        .map_err(|_| SealError::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let pk = [3u8; 32];
        let context = b"ctx";
        let plaintext = b"hello world";

        let sealed = seal(&pk, context, plaintext);
        // Fixed size regardless of content; fresh ciphertext on every seal,
        // so republishes are indistinguishable from data changes.
        assert_eq!(sealed.len(), PAD_TO + 24 + 16);
        assert_ne!(sealed, seal(&pk, context, plaintext));

        let opened = open(&pk, context, &sealed).unwrap();
        assert_eq!(&opened[..plaintext.len()], plaintext);
        assert!(opened[plaintext.len()..].iter().all(|&b| b == 0));

        // Wrong key or context fails closed.
        assert!(open(&[4u8; 32], context, &sealed).is_err());
        assert!(open(&pk, b"other-ctx", &sealed).is_err());
    }
}
