use crate::CryptoError;

/// Encodes/decodes multibase (base58btc, base64url, etc.).
#[allow(dead_code)]
pub trait MultibaseEncoder {
    /// Encodes bytes using a specific multibase variant.
    fn encode(&self, data: &[u8]) -> String;

    /// Decodes a multibase string back to bytes.
    fn decode(&self, input: &str) -> Result<Vec<u8>, CryptoError>;
}
