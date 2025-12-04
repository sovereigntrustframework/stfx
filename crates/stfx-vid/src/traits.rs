use crate::error::{Error, VerifyError};
use std::fmt;

/// VID trait: Abstraction for cryptographically-bound identifiers.
///
/// This trait provides TSP (Trust Spanning Protocol) Layer-1 primitives,
/// supporting both controller-side operations (with secret key access)
/// and evaluator-side operations (public key only).
///
/// # Associated Types
///
/// - `Address`: Transport address type (e.g., `Url`, `SocketAddr`, `String`).
///
/// # Methods
///
/// - **View Access**: `sk_e()`, `sk_s()`, `pk_e()`, `pk_s()`
///   - `sk_*`: Controller/endpoint view (requires secret key access)
///   - `pk_*`: Evaluator/remote view (public key only)
///   - `_e`: Encryption key
///   - `_s`: Signing key
///
/// - **Verification**: `verify()` validates VID state, policy, and records.
///
/// - **Resolution**: `resolve_address()` translates VID to transport address.
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

    /// Retrieve encryption secret key (controller view, VID.SK_e).
    ///
    /// Only available when VID is controlled locally.
    /// Remote evaluators cannot call this method.
    fn sk_e(&self) -> Result<PrivateKey, Error>;

    /// Retrieve signing secret key (controller view, VID.SK_s).
    ///
    /// Only available when VID is controlled locally.
    /// Remote evaluators cannot call this method.
    fn sk_s(&self) -> Result<PrivateKey, Error>;

    /// Retrieve encryption public key (evaluator view, VID.PK_e).
    ///
    /// Available to any verifier; no local control required.
    fn pk_e(&self) -> Result<PublicKey, Error>;

    /// Retrieve signing public key (evaluator view, VID.PK_s).
    ///
    /// Available to any verifier; no local control required.
    fn pk_s(&self) -> Result<PublicKey, Error>;

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
