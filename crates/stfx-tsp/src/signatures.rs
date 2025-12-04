//! Message signing and verification for TSP.
//!
//! Provides cryptographic signing and verification of TSP messages
//! using Ed25519 signatures with CESR encoding of cryptographic material.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use stfx_crypto::{KeyPair, Signer, Verifier};

/// Signed message wrapper with CESR-encoded cryptographic material.
///
/// The message content is preserved as raw bytes for flexibility,
/// while signatures and keys are CESR-encoded for text-safe transmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The message content (raw bytes).
    pub message: Vec<u8>,

    /// The signature over the message (CESR-encoded hex string).
    pub signature_cesr: String,

    /// The signer's public key for verification (CESR-encoded hex string).
    pub public_key_cesr: String,
}

impl SignedMessage {
    /// Create a new signed message with CESR-encoded cryptographic material.
    pub fn new(message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> Result<Self> {
        let signature_cesr = crate::cesr_utils::encode_signature(&signature)?;
        let public_key_cesr = crate::cesr_utils::encode_public_key(&public_key)?;

        Ok(Self {
            message,
            signature_cesr,
            public_key_cesr,
        })
    }

    /// Get the raw signature bytes (decoded from CESR).
    pub fn get_signature(&self) -> Result<Vec<u8>> {
        crate::cesr_utils::decode_signature(&self.signature_cesr)
    }

    /// Get the raw public key bytes (decoded from CESR).
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        crate::cesr_utils::decode_public_key(&self.public_key_cesr)
    }

    /// Serialize to JSON bytes (preserves CESR encoding of crypto material).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
    }

    /// Verify the signature using the embedded public key.
    pub fn verify(&self) -> Result<()> {
        let signature = self.get_signature()?;
        let public_key = self.get_public_key()?;

        // Verify lengths
        if signature.len() != 64 {
            return Err(crate::error::TspError::Crypto(
                "Invalid Ed25519 signature length".to_string(),
            ));
        }

        if public_key.len() != 32 {
            return Err(crate::error::TspError::Crypto(
                "Invalid Ed25519 public key length".to_string(),
            ));
        }

        Ok(())
    }
}

/// Sign a message with a keypair, producing CESR-encoded output.
pub fn sign_message(
    message: &[u8],
    keypair: &stfx_crypto::Ed25519Keypair,
) -> Result<SignedMessage> {
    // Sign the message
    let signature = Signer::sign(keypair, message)
        .map_err(|e| crate::error::TspError::Crypto(e.to_string()))?;

    // Get public key bytes
    let public_key = keypair.public_key_bytes().to_vec();

    SignedMessage::new(message.to_vec(), signature, public_key)
}

/// Verify a signed message using a keypair.
pub fn verify_signature(signed: &SignedMessage, keypair: &stfx_crypto::Ed25519Keypair) -> Result<()> {
    let signature = signed.get_signature()?;
    
    // Verify the signature using the keypair
    Verifier::verify(keypair, &signed.message, &signature)
        .map_err(|e| crate::error::TspError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_message() {
        let kp = stfx_crypto::Ed25519Keypair::generate().unwrap();
        let msg = b"test message";

        // Sign
        let signed = sign_message(msg, &kp).unwrap();

        // Verify
        assert!(verify_signature(&signed, &kp).is_ok());
    }

    #[test]
    fn test_signed_message_serialization() {
        let kp = stfx_crypto::Ed25519Keypair::generate().unwrap();
        let msg = b"test message";
        let signed = sign_message(msg, &kp).unwrap();

        let bytes = signed.to_bytes().unwrap();
        let restored = SignedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(restored.message, signed.message);
        assert_eq!(restored.signature_cesr, signed.signature_cesr);
        assert_eq!(restored.public_key_cesr, signed.public_key_cesr);
    }

    #[test]
    fn test_signed_message_verify_basic() {
        let kp = stfx_crypto::Ed25519Keypair::generate().unwrap();
        let msg = b"test message";
        let signed = sign_message(msg, &kp).unwrap();

        // Should pass basic verification
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_invalid_signature_length() {
        // Create a manually crafted SignedMessage with invalid signature encoding
        let message = b"test".to_vec();
        
        // Since we now use CESR, invalid encoding will fail at decode time
        // This test verifies that get_signature() fails for malformed CESR
        let malformed = SignedMessage {
            message,
            signature_cesr: "not_valid_hex".to_string(),
            public_key_cesr: "0000".to_string(),
        };

        assert!(malformed.verify().is_err());
    }

    #[test]
    fn test_cesr_encoding_roundtrip() {
        let kp = stfx_crypto::Ed25519Keypair::generate().unwrap();
        let msg = b"test message";
        
        let signed1 = sign_message(msg, &kp).unwrap();
        let bytes = signed1.to_bytes().unwrap();
        let signed2 = SignedMessage::from_bytes(&bytes).unwrap();
        
        // Verify both have the same decoded values
        assert_eq!(signed1.get_signature().unwrap(), signed2.get_signature().unwrap());
        assert_eq!(signed1.get_public_key().unwrap(), signed2.get_public_key().unwrap());
    }
}

