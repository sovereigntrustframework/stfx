// crates/stfx-crypto/src/traits/randomness.rs
//! Trait `Randomness` — secure and configurable entropy source abstraction
//!
//! This trait is the sole dependency for key generation in Layer 1.
//! Thanks to Cargo features, you can:
//! • Use OsRng (default in std)
//! • Inject a custom RNG (useful in WASM, embedded, tests)
//! • Completely disable key generation (ultra-lean binaries)

use crate::error::CryptoError;

#[cfg(feature = "std")]
use rand_core::RngCore;

/// Cryptographically secure entropy source.
///
/// Implemented by:
/// - `OsRng` (default on platforms with `/dev/urandom`, `getrandom`, etc.)
/// - `ThreadRng` (for fast tests)
/// - Any `impl RngCore + CryptoRng` that the user wants to inject
pub trait Randomness: Sized {
    /// Fills the buffer with secure random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError>;

    /// Generates a 32-byte array — frequently used for seeds and keys.
    #[inline]
    fn gen_32_bytes(&mut self) -> Result<[u8; 32], CryptoError> {
        let mut bytes = [0u8; 32];
        self.fill_bytes(&mut bytes)?;
        Ok(bytes)
    }

    /// Generates an N-byte array (generic size).
    #[inline]
    fn gen_bytes<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        let mut bytes = [0u8; N];
        self.fill_bytes(&mut bytes)?;
        Ok(bytes)
    }
}

// =============================================================================
// Default implementations (enabled by features)
// =============================================================================

/// Blanket impl for any type implementing `RngCore + CryptoRng`.
/// This automatically covers:
/// - `OsRng` (operating system)
/// - `ThreadRng` (rand::thread_rng)
/// - `StdRng`, `ChaCha20Rng`, etc.
/// - Any custom user RNG
impl<R> Randomness for R
where
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.try_fill_bytes(dest)
            .map_err(|_| CryptoError::RandomnessFailure)
    }
}

// =============================================================================
// Helper for users who don't want key generation
// =============================================================================

/// Type that always fails — used when the generation feature is disabled
#[derive(Debug, Clone, Copy)]
pub struct NoRandomness;

impl Randomness for NoRandomness {
    fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::RandomnessDisabled)
    }
}
