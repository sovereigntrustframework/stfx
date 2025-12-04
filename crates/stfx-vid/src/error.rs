use thiserror::Error;

/// Comprehensive error type for VID Layer-1 operations.
#[derive(Debug, Clone, Error)]
pub enum L1Error {
    /// Address resolution failed.
    #[error("Address resolution failed: {0}")]
    AddressResolutionFailed(String),

    /// Secret key is not available (e.g., remote endpoint has no SK access).
    #[error("Secret key not available: {0}")]
    SecretKeyNotAvailable(String),

    /// Public key retrieval failed.
    #[error("Public key retrieval failed: {0}")]
    PublicKeyRetrievalFailed(String),

    /// VID is invalid or malformed.
    #[error("Invalid VID: {0}")]
    InvalidVid(String),

    /// Key material is unavailable or corrupted.
    #[error("Key material unavailable: {0}")]
    KeyMaterialUnavailable(String),

    /// Cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Generic error for other Layer-1 failures.
    #[error("Layer-1 error: {0}")]
    Other(String),
}

/// Specialized error type for VID verification failures.
#[derive(Debug, Clone, Error)]
pub enum L1VidVerifyError {
    /// VID signature verification failed.
    #[error("VID signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// VID has expired.
    #[error("VID has expired")]
    VidExpired,

    /// VID status is invalid (e.g., revoked, suspended).
    #[error("VID status invalid: {0}")]
    InvalidStatus(String),

    /// VID policy check failed.
    #[error("VID policy check failed: {0}")]
    PolicyCheckFailed(String),

    /// VID records are inconsistent or incomplete.
    #[error("VID records invalid: {0}")]
    RecordsInvalid(String),

    /// Trust chain verification failed.
    #[error("Trust chain verification failed: {0}")]
    TrustChainFailed(String),

    /// Generic verification error.
    #[error("VID verification error: {0}")]
    Other(String),
}
