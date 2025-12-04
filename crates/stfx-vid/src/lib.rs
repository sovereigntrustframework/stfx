//! STFx Verifiable Identifiers (VID): Layer-1 primitives and utilities.
//!
//! This crate provides the core abstractions and trait definitions for TSP Layer-1
//! Verifiable Identifiers, supporting both controller-side and evaluator-side operations.
//!
//! # Core Traits
//!
//! - [`L1Vid`]: Main trait for VID operations (resolution, key retrieval, verification).
//! - Error types: [`L1Error`], [`L1VidVerifyError`] for comprehensive error handling.
//!
//! # Key Types
//!
//! - [`L1PrivateKey`]: Secret key abstraction for controllers.
//! - [`L1PublicKey`]: Public key abstraction for evaluators.
//!
//! # Implementations
//!
//! Concrete implementations (URL-based, socket-based, etc.) are in the `implementations` module.

pub mod error;
pub mod implementations;
pub mod traits;

// Public API re-exports
pub use error::{L1Error, L1VidVerifyError};
pub use traits::{L1PrivateKey, L1PublicKey, L1Vid};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that L1Vid trait is properly defined and can be used.
    #[test]
    fn test_l1vid_trait_structure() {
        // This test verifies that the trait compiles and is accessible.
        // Concrete implementations will test actual behavior.
        let _: Option<&dyn L1Vid<Address = String>> = None;
    }

    /// Test that error types are properly defined.
    #[test]
    fn test_error_types() {
        let _err = L1Error::InvalidVid("test".into());
        let _verify_err = L1VidVerifyError::VidExpired;
    }

    /// Test that key types are properly defined.
    #[test]
    fn test_key_types() {
        let priv_key = L1PrivateKey::new(vec![1, 2, 3], "signing");
        assert_eq!(priv_key.bytes(), &[1, 2, 3]);
        assert_eq!(priv_key.purpose(), "signing");

        let pub_key = L1PublicKey::new(vec![4, 5, 6], "encryption");
        assert_eq!(pub_key.bytes(), &[4, 5, 6]);
        assert_eq!(pub_key.purpose(), "encryption");
    }
}
