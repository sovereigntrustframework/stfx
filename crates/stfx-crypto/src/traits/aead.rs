//! Authenticated Encryption with Associated Data (AEAD) trait.

/// AEAD cipher trait for authenticated encryption.
///
/// Implemented by cipher types like ChaCha20-Poly1305, AES-GCM, etc.
/// Provides both confidentiality and authenticity.
pub trait Aead {
    /// Error type returned by encryption/decryption operations.
    type Error;

    /// Encrypts plaintext in-place with authenticated associated data.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte nonce (must be unique for each message with the same key)
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    /// * `plaintext` - Data to encrypt (modified in-place, authentication tag appended)
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if encryption fails.
    fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;

    /// Decrypts ciphertext in-place and verifies authentication.
    ///
    /// # Arguments
    /// * `key` - 32-byte decryption key
    /// * `nonce` - 12-byte nonce (must match the one used for encryption)
    /// * `aad` - Additional authenticated data (must match encryption)
    /// * `ciphertext` - Data to decrypt (modified in-place, authentication tag removed)
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if decryption or authentication fails.
    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;
}
