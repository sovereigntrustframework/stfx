/// Secure randomness source abstraction (OsRng, getrandom, WASM, etc.).
#[allow(dead_code)]
pub trait Randomness {
    /// Fills a buffer with cryptographically secure randomness.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}
