//! Unified error type for the Sovereign Trust Framework cryptographic layer (Layer 1)
//!
//! This error type is deliberately small and focused — higher layers (DID, VC, ZK)
//! will wrap it with their own domain-specific variants when needed.

use thiserror::Error;

/// Main error type re-exported as `stfx_crypto::CryptoError`
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Generic internal error — use only when no better variant exists
    #[error("Internal crypto error: {0}")]
    Internal(String),

    /// Invalid or malformed input (key material, signature, digest, multibase, etc.)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Key generation failed (entropy source, etc.)
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Secret key has wrong length or format
    #[error("Invalid secret key length (expected {expected}, got {actual})")]
    InvalidSecretKeyLength { expected: usize, actual: usize },

    /// Public key has wrong length or format
    #[error("Invalid public key length (expected {expected}, got {actual})")]
    InvalidPublicKeyLength { expected: usize, actual: usize },

    /// Signature operation failed
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Signature verification failed (does NOT leak timing information)
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Hashing operation failed
    #[error("Hashing failed: {0}")]
    Hashing(String),

    /// AEAD operation failed (encrypt/decrypt)
    #[error("AEAD operation failed: {0}")]
    Aead(String),

    /// Key agreement (Diffie-Hellman) failed
    #[error("Key agreement failed: {0}")]
    KeyAgreement(String),

    /// Multibase encoding/decoding error
    #[error("Multibase error: {0}")]
    Multibase(String),

    /// Multicodec prefix mismatch or unsupported algorithm
    #[error("Unsupported or unknown multicodec code: {0:#x}")]
    UnsupportedMulticodec(u64),

    /// Serialization / deserialization error (e.g. JWK import/export)
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Randomness source failure
    #[error("Failed to acquire secure randomness")]
    RandomnessFailure,
}

// =============================================================================
// Convenient From impls — permite ? em todos os sítios
// =============================================================================

impl From<&str> for CryptoError {
    fn from(s: &str) -> Self {
        CryptoError::InvalidInput(s.to_string())
    }
}

impl From<String> for CryptoError {
    fn from(s: String) -> Self {
        CryptoError::InvalidInput(s)
    }
}

// Para integração com crates externos
impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        CryptoError::Signing(err.to_string())
    }
}

impl From<rand::Error> for CryptoError {
    fn from(err: rand::Error) -> Self {
        CryptoError::KeyGeneration(err.to_string())
    }
}

/// Tipo público — usado por todo o ecossistema SFT
pub type Result<T> = std::result::Result<T, CryptoError>;

/// AEAD error type (legacy compatibility).
#[derive(Debug)]
pub struct AeadError;

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AEAD operation failed")
    }
}

impl std::error::Error for AeadError {}

impl From<AeadError> for CryptoError {
    fn from(_: AeadError) -> Self {
        CryptoError::Aead("AEAD operation failed".to_string())
    }
}
