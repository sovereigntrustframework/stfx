use crate::error::{L1Error, L1VidVerifyError};
use std::fmt;

/// Layer-1 VID trait: Abstraction for cryptographically-bound identifiers.
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
pub trait L1Vid: fmt::Display {
    /// Transport address type (e.g., `String`, `Url`, `SocketAddr`).
    type Address: Clone + fmt::Debug;

    /// Return VID as string representation.
    fn as_str(&self) -> &str;

    /// Resolve transport address for this VID.
    ///
    /// Maps VID to addressable endpoint (e.g., HTTP endpoint, network socket).
    /// Corresponds to `VID.RESOLVEADDRESS` in TSP Layer-1 spec.
    fn resolve_address(&self) -> Result<Self::Address, L1Error>;

    /// Retrieve encryption secret key (controller view, VID.SK_e).
    ///
    /// Only available when VID is controlled locally.
    /// Remote evaluators cannot call this method.
    fn sk_e(&self) -> Result<L1PrivateKey, L1Error>;

    /// Retrieve signing secret key (controller view, VID.SK_s).
    ///
    /// Only available when VID is controlled locally.
    /// Remote evaluators cannot call this method.
    fn sk_s(&self) -> Result<L1PrivateKey, L1Error>;

    /// Retrieve encryption public key (evaluator view, VID.PK_e).
    ///
    /// Available to any verifier; no local control required.
    fn pk_e(&self) -> Result<L1PublicKey, L1Error>;

    /// Retrieve signing public key (evaluator view, VID.PK_s).
    ///
    /// Available to any verifier; no local control required.
    fn pk_s(&self) -> Result<L1PublicKey, L1Error>;

    /// Verify VID integrity, state, policy, and records.
    ///
    /// Corresponds to `VID.VERIFY` in TSP Layer-1 spec.
    /// Validates:
    /// - Cryptographic signatures
    /// - Policy compliance
    /// - Status (not revoked, not expired, etc.)
    /// - Trust chain records
    fn verify(&self) -> Result<(), L1VidVerifyError>;
}

/// Layer-1 private key abstraction.
///
/// Represents a secret/private key material used for decryption or signing.
#[derive(Debug, Clone)]
pub struct L1PrivateKey {
    /// Raw key bytes (typically encrypted or zero-copied).
    bytes: Vec<u8>,
    /// Key purpose: "encryption" or "signing".
    purpose: String,
}

impl L1PrivateKey {
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

impl fmt::Display for L1PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L1PrivateKey({}; {} bytes)", self.purpose, self.bytes.len())
    }
}

/// Layer-1 public key abstraction.
///
/// Represents a public key material used for signature verification or decryption.
#[derive(Debug, Clone)]
pub struct L1PublicKey {
    /// Raw key bytes.
    bytes: Vec<u8>,
    /// Key purpose: "encryption" or "signing".
    purpose: String,
}

impl L1PublicKey {
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

impl fmt::Display for L1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L1PublicKey({}; {} bytes)", self.purpose, self.bytes.len())
    }
}
