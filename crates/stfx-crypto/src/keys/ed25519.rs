//! Ed25519 digital signature implementation.

use crate::error::CryptoError;
use crate::traits::{KeyPair, Signer, Verifier};
use ed25519_dalek::{SecretKey, Signature, Signer as _, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

/// Ed25519 keypair for signing and verification.
pub struct Ed25519Keypair {
    signing_key: SigningKey,
    public_key: VerifyingKey,
}

impl Ed25519Keypair {
    /// Get the public verifying key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    /// Get the secret key bytes (use with caution).
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.signing_key.as_bytes()
    }
}

// Implement KeyPair trait
impl KeyPair for Ed25519Keypair {
    fn generate() -> Result<Self, CryptoError> {
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        let secret = SecretKey::from(sk_bytes);
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            public_key,
        })
    }

    fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    fn secret_key_bytes(&self) -> &[u8] {
        self.signing_key.as_bytes()
    }

    fn from_secret_key_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CryptoError> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidSecretKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(bytes);
        let secret = SecretKey::from(sk_bytes);
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            public_key,
        })
    }
}

impl Signer for Ed25519Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, crate::error::CryptoError> {
        let sig: Signature = self.signing_key.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for Ed25519Keypair {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), crate::error::CryptoError> {
        self.public_key.verify(msg, signature)
    }
}

impl Verifier for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), crate::error::CryptoError> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| crate::error::CryptoError::InvalidInput(e.to_string()))?;
        ed25519_dalek::Verifier::verify(self, msg, &sig)
            .map_err(|_| crate::error::CryptoError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let kp = Ed25519Keypair::generate().unwrap();
        let msg = b"hello world";
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(kp.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn keypair_trait_implementation() {
        let kp: Ed25519Keypair = KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), 32);
        assert_eq!(kp.secret_key_bytes().len(), 32);
    }

    #[test]
    fn from_secret_key_bytes() {
        let kp1 = Ed25519Keypair::generate().unwrap();
        let sk_bytes = kp1.secret_key_bytes();
        let kp2 = Ed25519Keypair::from_secret_key_bytes(sk_bytes).unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn from_secret_key_bytes_invalid_length() {
        let result = Ed25519Keypair::from_secret_key_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(CryptoError::InvalidSecretKeyLength { .. })));
    }
}
