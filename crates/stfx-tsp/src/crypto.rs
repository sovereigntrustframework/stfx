//! Cryptographic operations for TSP messages.
//!
//! Provides message encryption/decryption with CESR encoding of the nonce
//! for text-safe transmission.

use crate::error::Result;
use crate::types::TspPayload;
use serde::{Deserialize, Serialize};
use stfx_crypto::{
    aead::ChaCha20Poly1305Cipher, hash::Blake2b256Hasher, Aead, Hasher,
};

/// Message wrapper for encryption with CESR-encoded nonce.
///
/// The nonce is CESR-encoded for text-safe transmission,
/// while ciphertext and AAD are kept as binary for efficiency.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Nonce for the cipher (CESR-encoded hex string).
    pub nonce_cesr: String,

    /// Encrypted payload (binary).
    pub ciphertext: Vec<u8>,

    /// Additional authenticated data (binary).
    pub aad: Vec<u8>,
}

impl EncryptedMessage {
    /// Create a new encrypted message with CESR-encoded nonce.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> Result<Self> {
        let nonce_cesr = crate::cesr_utils::encode_nonce(&nonce)?;

        Ok(Self {
            nonce_cesr,
            ciphertext,
            aad,
        })
    }

    /// Get the raw nonce bytes (decoded from CESR).
    pub fn get_nonce(&self) -> Result<Vec<u8>> {
        crate::cesr_utils::decode_nonce(&self.nonce_cesr)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
    }
}

/// Seal a TSP payload with encryption.
pub fn seal_payload(
    payload: &TspPayload,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<EncryptedMessage> {
    // Serialize payload
    let mut plaintext = serde_json::to_vec(payload)
        .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))?;

    // Generate nonce (in practice, use random; for now use deterministic for testing)
    let mut nonce = [0u8; 12];
    let hasher = Blake2b256Hasher;
    let hash = Hasher::hash(&hasher, aad);
    nonce.copy_from_slice(&hash[..12]);

    // Encrypt
    let cipher = ChaCha20Poly1305Cipher;
    cipher
        .encrypt(key, &nonce, aad, &mut plaintext)
        .map_err(|e| crate::error::TspError::Crypto(e.to_string()))?;

    EncryptedMessage::new(nonce.to_vec(), plaintext, aad.to_vec())
}

/// Open a sealed TSP payload with decryption.
pub fn open_payload(
    encrypted: &EncryptedMessage,
    key: &[u8; 32],
) -> Result<TspPayload> {
    let mut ciphertext = encrypted.ciphertext.clone();
    let nonce_bytes = encrypted.get_nonce()?;

    if nonce_bytes.len() != 12 {
        return Err(crate::error::TspError::MessageFormat(
            "Invalid nonce length".to_string(),
        ));
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    // Decrypt
    let cipher = ChaCha20Poly1305Cipher;
    cipher
        .decrypt(key, &nonce, &encrypted.aad, &mut ciphertext)
        .map_err(|e| crate::error::TspError::Crypto(e.to_string()))?;

    // Deserialize
    serde_json::from_slice(&ciphertext)
        .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_payload() {
        let payload = TspPayload::Content(b"hello TSP".to_vec());
        let key = [42u8; 32];
        let aad = b"additional_data".as_slice();

        // Seal
        let encrypted = seal_payload(&payload, &key, aad).unwrap();

        // Open
        let decrypted = open_payload(&encrypted, &key).unwrap();

        // Verify
        if let TspPayload::Content(data) = decrypted {
            assert_eq!(data, b"hello TSP".to_vec());
        } else {
            panic!("Expected Content variant");
        }
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]; // Valid 12-byte nonce
        let encrypted = EncryptedMessage::new(
            nonce.clone(),
            vec![4, 5, 6],
            vec![7, 8, 9],
        ).unwrap();

        let bytes = encrypted.to_bytes().unwrap();
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

        // Verify CESR-encoded nonce is preserved (not comparing raw bytes)
        assert_eq!(restored.get_nonce().unwrap(), nonce);
        assert_eq!(restored.ciphertext, encrypted.ciphertext);
        assert_eq!(restored.aad, encrypted.aad);
    }

    #[test]
    fn test_encrypted_message_cesr_roundtrip() {
        let nonce = vec![5; 12];
        let enc1 = EncryptedMessage::new(nonce.clone(), vec![1, 2], vec![3, 4]).unwrap();
        
        let bytes = enc1.to_bytes().unwrap();
        let enc2 = EncryptedMessage::from_bytes(&bytes).unwrap();
        
        // Verify nonce is correctly round-tripped through CESR encoding
        assert_eq!(enc1.get_nonce().unwrap(), enc2.get_nonce().unwrap());
    }
}
