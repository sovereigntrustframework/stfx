use crate::CryptoError;

/// Generates or loads cryptographic key material.
#[allow(dead_code)]
pub trait KeyManager {
    /// Generates a new random keypair.
    fn generate() -> Result<Self, CryptoError>
    where
        Self: Sized;

    /// Returns the raw public key bytes (algorithm-specific).
    fn public_key_bytes(&self) -> &[u8];
}
