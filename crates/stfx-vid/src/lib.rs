//! STFx Verifiable Identifiers (VID): primitives and utilities.
//!
//! This crate provides the core abstractions and trait definitions for TSP
//! Verifiable Identifiers, supporting both controller-side and evaluator-side operations.
//!
//! # Core Traits
//!
//! - [`Vid`]: Base trait for all VID operations (resolution, string representation).
//! - [`ControllerView`]: Optional trait for controller-side operations (secret key access).
//! - [`EvaluatorView`]: Optional trait for evaluator-side operations (public key access).
//! - [`Verifiable`]: Optional trait for VID verification (state, policy, trust chain).
//!
//! Implementations can selectively implement these traits based on their capabilities.
//! For example:
//! - A local controller VID might implement `Vid + ControllerView + EvaluatorView + Verifiable`
//! - A remote evaluator VID might implement `Vid + EvaluatorView + Verifiable`
//! - A sealed VID might implement only `Vid + EvaluatorView`
//!
//! # Error Types
//!
//! - [`Error`]: General VID operation errors (resolution, key access).
//! - [`VerifyError`]: Specialized errors for VID verification.
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
pub use traits::{ControllerView, EvaluatorView, PrivateKey, PublicKey, Verifiable, Vid};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that Vid trait is properly defined and can be used.
    #[test]
    fn test_vid_trait_structure() {
        // This test verifies that the core trait compiles and is accessible.
        let _: Option<&dyn Vid<Address = String>> = None;
    }

    /// Test that ControllerView trait is properly defined.
    #[test]
    fn test_controller_view_trait_structure() {
        // This test verifies trait structure for implementations.
        let _: Option<&dyn ControllerView> = None;
    }

    /// Test that EvaluatorView trait is properly defined.
    #[test]
    fn test_evaluator_view_trait_structure() {
        // This test verifies trait structure for implementations.
        let _: Option<&dyn EvaluatorView> = None;
    }

    /// Test that Verifiable trait is properly defined.
    #[test]
    fn test_verifiable_trait_structure() {
        // This test verifies trait structure for implementations.
        let _: Option<&dyn Verifiable> = None;
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

    /// Test that PrivateKey and PublicKey Display implementations work.
    #[test]
    fn test_key_display() {
        let priv_key = PrivateKey::new(vec![1, 2, 3], "signing");
        let priv_str = priv_key.to_string();
        assert!(priv_str.contains("PrivateKey"));
        assert!(priv_str.contains("signing"));
        assert!(priv_str.contains("3 bytes"));

        let pub_key = PublicKey::new(vec![4, 5, 6], "encryption");
        let pub_str = pub_key.to_string();
        assert!(pub_str.contains("PublicKey"));
        assert!(pub_str.contains("encryption"));
        assert!(pub_str.contains("3 bytes"));
    }
}
