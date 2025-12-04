//! Cryptographically secure random number generation.

use rand::RngCore;
use rand::rngs::OsRng;

/// Generate cryptographically secure random bytes.
pub fn bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes() {
        let a = bytes(32);
        let b = bytes(32);
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a, b); // extremely unlikely to be equal
    }
}
