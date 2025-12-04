//! TSP error types.

use thiserror::Error;

/// TSP operation result type.
pub type Result<T> = std::result::Result<T, TspError>;

/// Errors that can occur during TSP operations.
#[derive(Debug, Error)]
pub enum TspError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("VID error: {0}")]
    Vid(String),

    #[error("CESR encoding error: {0}")]
    Cesr(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Message format error: {0}")]
    MessageFormat(String),

    #[error("Relationship error: {0}")]
    Relationship(String),

    #[error("Unverified VID: {0}")]
    UnverifiedVid(String),

    #[error("Missing private VID: {0}")]
    MissingPrivateVid(String),

    #[error("Unverified source: {0}")]
    UnverifiedSource(String),

    #[error("Invalid route: {0}")]
    InvalidRoute(String),

    #[error("Invalid next hop: {0}")]
    InvalidNextHop(String),

    #[error("Unresolved next hop: {0}")]
    UnresolvedNextHop(String),

    #[error("Missing drop-off: {0}")]
    MissingDropOff(String),

    #[error("Thread ID mismatch")]
    ThreadIdMismatch,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Custom: {0}")]
    Custom(String),
}

impl From<stfx_crypto::CryptoError> for TspError {
    fn from(e: stfx_crypto::CryptoError) -> Self {
        TspError::Crypto(e.to_string())
    }
}

impl From<stfx_store::StoreError> for TspError {
    fn from(e: stfx_store::StoreError) -> Self {
        TspError::Storage(e.to_string())
    }
}

impl From<stfx_vid::VidError> for TspError {
    fn from(e: stfx_vid::VidError) -> Self {
        TspError::Vid(e.to_string())
    }
}

impl From<stfx_cesr::error::EncodeError> for TspError {
    fn from(e: stfx_cesr::error::EncodeError) -> Self {
        TspError::Cesr(format!("{:?}", e))
    }
}

impl From<stfx_cesr::error::DecodeError> for TspError {
    fn from(e: stfx_cesr::error::DecodeError) -> Self {
        TspError::Cesr(format!("{:?}", e))
    }
}

impl From<stfx_transport::TransportError> for TspError {
    fn from(e: stfx_transport::TransportError) -> Self {
        TspError::Transport(e.to_string())
    }
}

impl From<url::ParseError> for TspError {
    fn from(e: url::ParseError) -> Self {
        TspError::Custom(format!("URL parse error: {}", e))
    }
}
