use crate::CryptoError;

/// Strongly-typed digest output (avoids raw Vec<u8> everywhere).
#[allow(dead_code)]
pub trait Digest: AsRef<[u8]> + Sized {
    /// Length of the digest in bytes.
    const LENGTH: usize;

    /// Creates a digest from raw bytes (panics or returns error if wrong length).
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CryptoError>;
}
