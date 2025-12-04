//! STFx Verifiable Identifiers (VID): primitives and utilities.
//!
//! This crate provides the core abstractions and trait definitions for TSP
//! Verifiable Identifiers, supporting both controller-side and evaluator-side operations.
//!
//! # Core Traits
//!
//! - [`Vid`]: Main trait for VID operations (resolution, key retrieval, verification).
//! - Error types: [`Error`], [`VerifyError`] for comprehensive error handling.
//!
//! # Key Types
//!
//! - [`PrivateKey`]: Secret key abstraction for controllers.
//! - [`PublicKey`]: Public key abstraction for evaluators.
//!
//! # Implementations
//!
//! Concrete implementations (URL-based, socket-based, etc.) are in the `implementations` module.

pub mod error;
pub mod implementations;
pub mod traits;

// Public API re-exports
pub use error::{Error, VerifyError};
pub use traits::{PrivateKey, PublicKey, Vid};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that Vid trait is properly defined and can be used.
    #[test]
    fn test_vid_trait_structure() {
        // This test verifies that the trait compiles and is accessible.
        // Concrete implementations will test actual behavior.
        let _: Option<&dyn Vid<Address = String>> = None;
    }

    /// Test that error types are properly defined.
    #[test]
    fn test_error_types() {
        let _err = Error::InvalidVid("test".into());
        let _verify_err = VerifyError::VidExpired;
    }

    /// Test that key types are properly defined.
    #[test]
    fn test_key_types() {
        let priv_key = PrivateKey::new(vec![1, 2, 3], "signing");
        assert_eq!(priv_key.bytes(), &[1, 2, 3]);
        assert_eq!(priv_key.purpose(), "signing");

        let pub_key = PublicKey::new(vec![4, 5, 6], "encryption");
        assert_eq!(pub_key.bytes(), &[4, 5, 6]);
        assert_eq!(pub_key.purpose(), "encryption");
    }
}
