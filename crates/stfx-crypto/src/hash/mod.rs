//! Hash function implementations (SHA-256, BLAKE2b-256).

use crate::traits::Hasher;
use blake2::{digest::consts::U32, Blake2b};
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

/// BLAKE2b-256 hasher (256-bit output).
pub struct Blake2b256Hasher;

impl Hasher for Blake2b256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2b::<U32>::new();
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

/// Convenience function for BLAKE2b-256 hashing.
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let vec = Blake2b256Hasher.hash(data);
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

    #[test]
    fn blake2b256_len() {
        let digest = blake2b256(b"test");
        assert_eq!(digest.len(), 32);
    }
}
