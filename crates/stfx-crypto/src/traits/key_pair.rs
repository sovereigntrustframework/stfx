use super::{KeyManager, Signer, Verifier};

/// Unified interface for any keypair (public + secret).
#[allow(dead_code)]
pub trait KeyPair: KeyManager + Signer + Verifier {
    /// Returns a reference to the raw secret key bytes (zeroize on drop).
    fn secret_key_bytes(&self) -> &[u8];
}
