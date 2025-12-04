//! SHA-256 hash function implementation.

use crate::traits::Hasher;
use sha2::{Digest, Sha256};

/// SHA-256 hasher.
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Convenience function for SHA-256 hashing.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let vec = Sha256Hasher.hash(data);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&vec);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_len() {
        let digest = sha256(b"test");
        assert_eq!(digest.len(), 32);
    }
}
