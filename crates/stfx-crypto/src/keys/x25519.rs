//! X25519 Diffie-Hellman key agreement implementation.

use crate::traits::KeyAgreement;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// X25519 keypair for Diffie-Hellman key agreement.
pub struct X25519Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519Keypair {
    /// Generate a new random X25519 keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

impl KeyAgreement for X25519Keypair {
    type PublicKey = PublicKey;

    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let shared_a = alice.diffie_hellman(bob.public_key());
        let shared_b = bob.diffie_hellman(alice.public_key());

        assert_eq!(shared_a, shared_b);
    }
}
