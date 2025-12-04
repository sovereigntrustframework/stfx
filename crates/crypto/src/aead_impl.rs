//! ChaCha20-Poly1305 authenticated encryption implementation.

use crate::traits::Aead;
use crate::error::AeadError;
use chacha20poly1305::{
    aead::{Aead as AeadTrait, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

/// ChaCha20-Poly1305 AEAD cipher.
pub struct ChaCha20Poly1305Cipher;

impl Aead for ChaCha20Poly1305Cipher {
    type Error = AeadError;

    fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), Self::Error> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let payload = Payload {
            msg: plaintext.as_slice(),
            aad,
        };
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| AeadError)?;
        *plaintext = ciphertext;
        Ok(())
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), Self::Error> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let payload = Payload {
            msg: ciphertext.as_slice(),
            aad,
        };
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| AeadError)?;
        *ciphertext = plaintext;
        Ok(())
    }
}

// Error type moved to crate::error

/// Convenience function to encrypt data in-place.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &mut Vec<u8>,
) -> Result<(), AeadError> {
    ChaCha20Poly1305Cipher.encrypt(key, nonce, aad, plaintext)
}

/// Convenience function to decrypt data in-place.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &mut Vec<u8>,
) -> Result<(), AeadError> {
    ChaCha20Poly1305Cipher.decrypt(key, nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aad = b"additional data";
        let mut data = b"secret message".to_vec();
        let original = data.clone();

        encrypt(&key, &nonce, aad, &mut data).unwrap();
        assert_ne!(data, original);

        decrypt(&key, &nonce, aad, &mut data).unwrap();
        assert_eq!(data, original);
    }
}
