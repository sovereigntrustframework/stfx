//! stfx-crypto: Layer 1 cryptographic primitives for ToIP/TSP.
//!
//! Provides trait-based interfaces for signing, hashing, key agreement, and AEAD operations.

// Module declarations
mod traits;
mod error;
mod random;
mod encoding;
pub mod keys {
    pub mod ed25519_impl;
    pub mod x25519_impl;
}
pub mod hash;
mod aead_impl;

// Re-export core traits
pub use traits::{Aead, Hasher, KeyAgreement, Signer, Verifier};

// Re-export implementations as modules
pub mod ed25519 {
    pub use crate::keys::ed25519_impl::*;
}

// `hash` module declared above; use directly as `crate::hash::*`

pub mod x25519 {
    pub use crate::keys::x25519_impl::*;
}

pub mod aead {
    pub use crate::aead_impl::*;
}

pub mod rand {
    pub use crate::random::*;
}

pub mod encode {
    pub use crate::encoding::*;
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_integration() {
        let kp = ed25519::Ed25519Keypair::generate();
        let msg = b"hello TSP";
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(kp.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn trait_based_signing() {
        let kp = ed25519::Ed25519Keypair::generate();
        let msg = b"test message";
        
        // Use through trait
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(kp.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn trait_based_hashing() {
        let sha = hash::Sha256Hasher;
        let blake = hash::Blake2b256Hasher;
        
        let data = b"test data";
        assert_eq!(Hasher::hash(&sha, data).len(), 32);
        assert_eq!(Hasher::hash(&blake, data).len(), 32);
    }

    #[test]
    fn trait_based_key_agreement() {
        let alice = x25519::X25519Keypair::generate();
        let bob = x25519::X25519Keypair::generate();
        
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


