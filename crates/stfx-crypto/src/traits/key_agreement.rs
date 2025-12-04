//! Key agreement trait (Diffie-Hellman).

/// Key agreement trait for Diffie-Hellman key exchange.
///
/// Implemented by keypair types that support key agreement protocols,
/// such as X25519 (Elliptic Curve Diffie-Hellman).
pub trait KeyAgreement {
    /// The type of public key used in the key agreement.
    type PublicKey;

    /// Performs Diffie-Hellman key agreement.
    ///
    /// Returns a 32-byte shared secret derived from this keypair's secret key
    /// and the other party's public key.
    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32];
}
