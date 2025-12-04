/// Deterministic hashing (used for DID anchoring, Merkle trees, etc.).
pub trait Hasher {
    /// Hashes arbitrary data and returns raw digest bytes.
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}
