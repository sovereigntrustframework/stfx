//! Core cryptographic traits for algorithm-agnostic interfaces.

/// Cryptographic signing trait.
pub trait Signer {
    type Signature;
    type Error;
    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
}

/// Signature verification trait.
pub trait Verifier {
    type Signature;
    type Error;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::Error>;
}

/// Hash function trait (256-bit output).
pub trait Hasher {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// Key agreement trait (Diffie-Hellman).
pub trait KeyAgreement {
    type PublicKey;
    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32];
}

/// Authenticated encryption with associated data (AEAD).
pub trait Aead {
    type Error;
    fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;
    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;
}
