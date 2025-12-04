use crate::CryptoError;

/// Algorithm-agnostic signing of arbitrary messages.
pub trait Signer {
    /// Signs a message and returns the raw signature bytes.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
