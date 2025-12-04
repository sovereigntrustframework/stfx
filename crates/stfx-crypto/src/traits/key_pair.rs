//! Trait `KeyPair` — Unified interface for any cryptographic keypair
//!
//! This trait sits at the heart of the Sovereign Trust Framework (SFT)
//! Layer 1 abstraction. It combines the most common operations needed
//! across all ToIP layers (DID creation, signing VCs, DIDComm, etc.)
//! while remaining completely algorithm-agnostic.
//!
//! Design principles:
//! • Zero coupling with JWK, JSON-LD or any specific serialization format
//! • All key material is zeroized on drop (via `zeroize` crate — future)
//! • Public methods never expose secret key bytes directly (only via safe signing)
//! • Ready for `no-std`, WASM, embedded and post-quantum future

use crate::CryptoError;
use super::{Signer, Verifier};

/// A complete cryptographic keypair (public + secret).
///
/// This is the primary type that higher layers (`stfx-did`, `stfx-vc`, etc.)
/// will depend on. Implementing this trait for a new algorithm automatically
/// gives you full compatibility with the entire SFT stack.
///
/// # Security
/// Implementations MUST ensure secret key material is zeroized on drop.
/// Use `zeroize::Zeroizing` or the `Zeroize` derive on the struct.
#[allow(dead_code)]
pub trait KeyPair: Signer + Verifier + Sized {
    // ======================================================================
    // Key generation and access
    // ======================================================================

    /// Generates a new random keypair.
    ///
    /// # Errors
    /// Returns `CryptoError::KeyGeneration` if the random number generator
    /// fails or if key generation is not supported in the current environment.
    fn generate() -> Result<Self, CryptoError>;

    /// Returns the raw public key bytes (algorithm-specific format).
    ///
    /// This method is safe to expose and is used for verification,
    /// key exchange, and DID creation.
    fn public_key_bytes(&self) -> &[u8];

    // ======================================================================
    // Secret key access (safe — only for internal use or advanced KMS)
    // ======================================================================

    /// Returns the raw secret key bytes.
    ///
    /// # Security
    /// The returned slice is **not** cloned. Implementations MUST ensure
    /// the underlying secret is zeroized on drop (use `zeroize::Zeroizing`
    /// or the `Zeroize` derive on the struct).
    fn secret_key_bytes(&self) -> &[u8];

    /// Attempts to construct a keypair from raw secret key bytes.
    ///
    /// This is the counterpart of `secret_key_bytes()` and is used by
    /// key import, KMS integration, and DID rotation mechanisms.
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidSecretKeyLength` if the byte slice
    /// does not match the algorithm's expected key size.
    fn from_secret_key_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CryptoError>;

    // ======================================================================
    // Future extensions (when Multicodec/Multibase traits are implemented)
    // ======================================================================
    
    // TODO: Add default implementations when traits are ready:
    // fn public_key_multicodec(&self) -> Vec<u8>
    // fn to_did_key(&self) -> String
}
