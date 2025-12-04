//! Common error types for the crypto crate.

/// AEAD error type.
#[derive(Debug)]
pub struct AeadError;

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AEAD operation failed")
    }
}

impl std::error::Error for AeadError {}
