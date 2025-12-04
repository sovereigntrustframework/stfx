/// Key agreement trait (Diffie-Hellman) - retained for compatibility.
pub trait KeyAgreement {
    type PublicKey;
    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32];
}

/// Authenticated encryption with associated data (AEAD) - retained for compatibility.
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
