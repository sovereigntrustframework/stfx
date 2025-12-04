//! Ed25519 digital signature implementation.

use crate::traits::{Signer, Verifier};
use ed25519_dalek::{SecretKey, Signature, SignatureError, Signer as _, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

/// Ed25519 keypair for signing and verification.
pub struct Ed25519Keypair {
    signing_key: SigningKey,
    public_key: VerifyingKey,
}

impl Ed25519Keypair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        let secret = SecretKey::from(sk_bytes);
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        Self { signing_key, public_key }
    }

    /// Get the public verifying key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

impl Signer for Ed25519Keypair {
    type Signature = Signature;
    type Error = SignatureError;

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
        Ok(self.signing_key.sign(msg))
    }
}

impl Verifier for VerifyingKey {
    type Signature = Signature;
    type Error = SignatureError;

    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::Error> {
        ed25519_dalek::Verifier::verify(self, msg, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let kp = Ed25519Keypair::generate();
        let msg = b"hello world";
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(kp.public_key(), msg, &sig).unwrap();
    }
}
