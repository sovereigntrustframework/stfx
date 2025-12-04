//! Common error types for the crypto crate.

use std::fmt;

/// General cryptographic error type.
#[derive(Debug)]
pub enum CryptoError {
    /// AEAD operation failed
    Aead,
    /// Signature operation failed
    Signature(String),
    /// Invalid input
    InvalidInput(String),
    /// Encoding/decoding failed
    Encoding(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => write!(f, "AEAD operation failed"),
            Self::Signature(msg) => write!(f, "Signature error: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::Encoding(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// AEAD error type (legacy compatibility).
#[derive(Debug)]
pub struct AeadError;

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AEAD operation failed")
    }
}

impl std::error::Error for AeadError {}

impl From<AeadError> for CryptoError {
    fn from(_: AeadError) -> Self {
        Self::Aead
    }
}
