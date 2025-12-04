use crate::CryptoError;

/// Algorithm-agnostic verification (public-key only).
pub trait Verifier {
    /// Verifies a signature over a message.
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}
