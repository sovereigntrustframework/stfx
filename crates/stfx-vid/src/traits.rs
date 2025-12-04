use crate::error::{Error, VerifyError};
use std::fmt;

/// Core VID trait: Abstraction for cryptographically-bound identifiers.
///
/// This is the base trait that all VID implementations must support.
/// It provides core identity resolution and representation operations.
///
/// Additional capabilities (key access, verification) are provided by
/// separate traits (`ControllerView`, `EvaluatorView`, `Verifiable`)
/// that implementations can selectively implement.
///
/// # Associated Types
///
/// - `Address`: Transport address type (e.g., `Url`, `SocketAddr`, `String`).
pub trait Vid: fmt::Display {
    /// Transport address type (e.g., `String`, `Url`, `SocketAddr`).
    type Address: Clone + fmt::Debug;

    /// Return VID as string representation.
    fn as_str(&self) -> &str;

    /// Resolve transport address for this VID.
    ///
    /// Maps VID to addressable endpoint (e.g., HTTP endpoint, network socket).
    /// Corresponds to `VID.RESOLVEADDRESS` in TSP Layer-1 spec.
    fn resolve_address(&self) -> Result<Self::Address, Error>;
}

/// Controller-side view: Access to secret keys for local VID control.
///
/// Only VIDs controlled by the local endpoint should implement this trait.
/// Remote/evaluator-only VIDs will not have secret key material available.
///
/// # Usage
///
/// Implement this trait when the VID is controlled locally and secret keys
/// (for encryption and signing) are available to the endpoint.
pub trait ControllerView {
    /// Retrieve encryption secret key (VID.SK_e).
    ///
    /// Only available when VID is controlled locally.
    fn sk_e(&self) -> Result<PrivateKey, Error>;

    /// Retrieve signing secret key (VID.SK_s).
    ///
    /// Only available when VID is controlled locally.
    fn sk_s(&self) -> Result<PrivateKey, Error>;
}

/// Evaluator-side view: Access to public keys for VID verification.
///
/// All VIDs must support public key retrieval for verification purposes.
/// This trait should be implemented by all VID types.
///
/// # Usage
///
/// Implement this trait to provide public key material for:
/// - Signature verification
/// - Encryption (if using public-key encryption)
/// - Trust chain validation
pub trait EvaluatorView {
    /// Retrieve encryption public key (VID.PK_e).
    ///
    /// Available to any verifier; no local control required.
    fn pk_e(&self) -> Result<PublicKey, Error>;

    /// Retrieve signing public key (VID.PK_s).
    ///
    /// Available to any verifier; no local control required.
    fn pk_s(&self) -> Result<PublicKey, Error>;
}

/// Verifiable trait: Integrity and policy validation for VIDs.
///
/// Provides comprehensive VID verification including cryptographic validation,
/// policy compliance checking, and trust chain verification.
///
/// # Usage
///
/// Implement this trait when the VID supports full verification including:
/// - Signature verification
/// - Policy compliance checking
/// - Status validation (not revoked, not expired, etc.)
/// - Trust chain verification
pub trait Verifiable {
    /// Verify VID integrity, state, policy, and records.
    ///
    /// Corresponds to `VID.VERIFY` in TSP Layer-1 spec.
    /// Validates:
    /// - Cryptographic signatures
    /// - Policy compliance
    /// - Status (not revoked, not expired, etc.)
    /// - Trust chain records
    fn verify(&self) -> Result<(), VerifyError>;
}

/// VID private key abstraction.
///
/// Represents a secret/private key material used for decryption or signing.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    /// Raw key bytes (typically encrypted or zero-copied).
    bytes: Vec<u8>,
    /// Key purpose: "encryption" or "signing".
    purpose: String,
}

impl PrivateKey {
    /// Create a new private key.
    pub fn new(bytes: Vec<u8>, purpose: impl Into<String>) -> Self {
        Self {
            bytes,
            purpose: purpose.into(),
        }
    }

    /// Access raw key bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Key purpose label.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey({}; {} bytes)", self.purpose, self.bytes.len())
    }
}

/// VID public key abstraction.
///
/// Represents a public key material used for signature verification or decryption.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Raw key bytes.
    bytes: Vec<u8>,
    /// Key purpose: "encryption" or "signing".
    purpose: String,
}

impl PublicKey {
    /// Create a new public key.
    pub fn new(bytes: Vec<u8>, purpose: impl Into<String>) -> Self {
        Self {
            bytes,
            purpose: purpose.into(),
        }
    }

    /// Access raw key bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Key purpose label.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}; {} bytes)", self.purpose, self.bytes.len())
    }
}
