use crate::CryptoError;

/// Handles multicodec prefixes (e.g., 0xed = ed25519-pub).
#[allow(dead_code)]
pub trait MulticodecEncoder {
    /// Returns the multicodec code for this type.
    fn code(&self) -> u64;

    /// Encodes value with multicodec varint prefix.
    fn encode_prefixed(&self, data: &[u8]) -> Vec<u8>;

    /// Decodes and validates multicodec prefix.
    fn decode_prefixed(input: &[u8]) -> Result<(u64, &[u8]), CryptoError>;
}
