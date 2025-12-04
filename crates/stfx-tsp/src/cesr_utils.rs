//! CESR encoding/decoding utilities for cryptographic material.
//!
//! Provides helpers for encoding cryptographic primitives (signatures, keys, hashes)
//! into CESR text format for safe transmission and storage.

use crate::error::Result;
use stfx_cesr::{decode_variable_data, encode_variable_data};

/// CESR type identifier for Ed25519 signatures (64 bytes).
/// Using a variable-length encoding identifier.
const ED25519_SIG_ID: u32 = 0x0D40; // Placeholder - adjust based on actual CESR mapping

/// CESR type identifier for Ed25519 public keys (32 bytes).
const ED25519_PUB_KEY_ID: u32 = 0x0D41; // Placeholder

/// CESR type identifier for Blake2b-256 digests (32 bytes).
const BLAKE2B_256_ID: u32 = 0x0D42; // Placeholder

/// CESR type identifier for ChaCha20Poly1305 nonces (12 bytes).
const NONCE_ID: u32 = 0x0D43; // Placeholder

/// Encode raw bytes as CESR variable-length data with base64url encoding.
///
/// Variable-length encoding allows flexible payload sizes.
fn encode_as_cesr(identifier: u32, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    encode_variable_data(identifier, data, &mut output);
    output
}

/// Decode CESR-encoded data back to raw bytes.
///
/// Expects data to be in CESR variable-length format.
fn decode_from_cesr(identifier: u32, data: &[u8]) -> Result<Vec<u8>> {
    let mut stream = data;
    let decoded: &[u8] = decode_variable_data(identifier, &mut stream).ok_or_else(|| {
        crate::error::TspError::Cesr("Failed to decode CESR: invalid format".to_string())
    })?;
    Ok(decoded.to_vec())
}

/// Encode an Ed25519 signature to CESR format.
///
/// Ed25519 signatures are 64 bytes. This encodes them with CESR framing
/// for text-safe transmission.
pub fn encode_signature(signature: &[u8]) -> Result<String> {
    if signature.len() != 64 {
        return Err(crate::error::TspError::Crypto(format!(
            "Invalid Ed25519 signature length: {} (expected 64)",
            signature.len()
        )));
    }
    let cesr_bytes = encode_as_cesr(ED25519_SIG_ID, signature);
    Ok(hex::encode(&cesr_bytes))
}

/// Decode a CESR-encoded Ed25519 signature.
pub fn decode_signature(cesr_hex: &str) -> Result<Vec<u8>> {
    let cesr_bytes = hex::decode(cesr_hex).map_err(|e| {
        crate::error::TspError::Cesr(format!("Invalid hex encoding: {}", e))
    })?;
    decode_from_cesr(ED25519_SIG_ID, &cesr_bytes)
}

/// Encode an Ed25519 public key to CESR format.
///
/// Ed25519 public keys are 32 bytes.
pub fn encode_public_key(key: &[u8]) -> Result<String> {
    if key.len() != 32 {
        return Err(crate::error::TspError::Crypto(format!(
            "Invalid Ed25519 public key length: {} (expected 32)",
            key.len()
        )));
    }
    let cesr_bytes = encode_as_cesr(ED25519_PUB_KEY_ID, key);
    Ok(hex::encode(&cesr_bytes))
}

/// Decode a CESR-encoded Ed25519 public key.
pub fn decode_public_key(cesr_hex: &str) -> Result<Vec<u8>> {
    let cesr_bytes = hex::decode(cesr_hex).map_err(|e| {
        crate::error::TspError::Cesr(format!("Invalid hex encoding: {}", e))
    })?;
    decode_from_cesr(ED25519_PUB_KEY_ID, &cesr_bytes)
}

/// Encode a Blake2b-256 digest (thread ID) to CESR format.
///
/// Blake2b-256 digests are 32 bytes.
pub fn encode_digest(digest: &[u8]) -> Result<String> {
    if digest.len() != 32 {
        return Err(crate::error::TspError::Crypto(format!(
            "Invalid Blake2b-256 digest length: {} (expected 32)",
            digest.len()
        )));
    }
    let cesr_bytes = encode_as_cesr(BLAKE2B_256_ID, digest);
    Ok(hex::encode(&cesr_bytes))
}

/// Decode a CESR-encoded Blake2b-256 digest.
pub fn decode_digest(cesr_hex: &str) -> Result<Vec<u8>> {
    let cesr_bytes = hex::decode(cesr_hex).map_err(|e| {
        crate::error::TspError::Cesr(format!("Invalid hex encoding: {}", e))
    })?;
    decode_from_cesr(BLAKE2B_256_ID, &cesr_bytes)
}

/// Encode a ChaCha20Poly1305 nonce to CESR format.
///
/// Nonces are 12 bytes.
pub fn encode_nonce(nonce: &[u8]) -> Result<String> {
    if nonce.len() != 12 {
        return Err(crate::error::TspError::Crypto(format!(
            "Invalid nonce length: {} (expected 12)",
            nonce.len()
        )));
    }
    let cesr_bytes = encode_as_cesr(NONCE_ID, nonce);
    Ok(hex::encode(&cesr_bytes))
}

/// Decode a CESR-encoded ChaCha20Poly1305 nonce.
pub fn decode_nonce(cesr_hex: &str) -> Result<Vec<u8>> {
    let cesr_bytes = hex::decode(cesr_hex).map_err(|e| {
        crate::error::TspError::Cesr(format!("Invalid hex encoding: {}", e))
    })?;
    decode_from_cesr(NONCE_ID, &cesr_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_signature() {
        let sig = vec![0u8; 64];
        let encoded = encode_signature(&sig).unwrap();
        let decoded = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn test_encode_decode_public_key() {
        let key = vec![0u8; 32];
        let encoded = encode_public_key(&key).unwrap();
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_encode_decode_digest() {
        let digest = vec![0u8; 32];
        let encoded = encode_digest(&digest).unwrap();
        let decoded = decode_digest(&encoded).unwrap();
        assert_eq!(decoded, digest);
    }

    #[test]
    fn test_invalid_signature_length() {
        let invalid_sig = vec![0u8; 32]; // Wrong length
        assert!(encode_signature(&invalid_sig).is_err());
    }

    #[test]
    fn test_invalid_public_key_length() {
        let invalid_key = vec![0u8; 64]; // Wrong length
        assert!(encode_public_key(&invalid_key).is_err());
    }

    #[test]
    fn test_encode_decode_nonce() {
        let nonce = vec![42u8; 12];
        let encoded = encode_nonce(&nonce).unwrap();
        let decoded = decode_nonce(&encoded).unwrap();
        assert_eq!(decoded, nonce);
    }

    #[test]
    fn test_invalid_nonce_length() {
        let invalid_nonce = vec![0u8; 16]; // Wrong length
        assert!(encode_nonce(&invalid_nonce).is_err());
    }
}
