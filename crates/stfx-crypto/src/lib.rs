//! stfx-crypto: Layer 1 cryptographic primitives for ToIP/TSP.
//!
//! Provides trait-based interfaces for signing, hashing, key agreement, and AEAD operations.

// Module declarations
mod encoding;
mod error;
mod traits;

pub mod aead;
pub mod hash;
pub mod keys;
pub mod rand;

// Re-export core traits
pub use traits::{Aead, Hasher, KeyAgreement, KeyPair, Signer, Verifier};

// Public error types
pub use error::{AeadError, CryptoError};

// Re-export key implementations
pub use keys::{Ed25519Keypair, X25519Keypair};

// Re-export hash implementations
pub use hash::{Blake2b256Hasher, Sha256Hasher};

// Re-export encoding utilities
pub use encoding::{base64url_decode, base64url_encode};

// Convenience aliases
/// Convenience alias — default key type (Ed25519)
pub type DefaultKeypair = Ed25519Keypair;
/// Convenience alias — default hasher (Blake2b-256)
pub type DefaultHasher = Blake2b256Hasher;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_integration() {
        let kp = Ed25519Keypair::generate().unwrap();
        let msg = b"hello TSP";
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(kp.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn trait_based_signing() {
        let kp = Ed25519Keypair::generate().unwrap();
        let msg = b"test message";

        // Use through trait
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(kp.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn trait_based_hashing() {
        let sha = Sha256Hasher;
        let blake = Blake2b256Hasher;

        let data = b"test data";
        assert_eq!(Hasher::hash(&sha, data).len(), 32);
        assert_eq!(Hasher::hash(&blake, data).len(), 32);
    }

    #[test]
    fn trait_based_key_agreement() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let shared_a = KeyAgreement::diffie_hellman(&alice, bob.public_key());
        let shared_b = KeyAgreement::diffie_hellman(&bob, alice.public_key());
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn trait_based_aead() {
        let cipher = aead::ChaCha20Poly1305Cipher;
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = b"metadata";

        let mut data = b"secret".to_vec();
        let original = data.clone();

        Aead::encrypt(&cipher, &key, &nonce, aad, &mut data).unwrap();
        assert_ne!(data, original);

        Aead::decrypt(&cipher, &key, &nonce, aad, &mut data).unwrap();
        assert_eq!(data, original);
    }
}
