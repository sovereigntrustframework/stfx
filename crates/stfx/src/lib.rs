pub use stfx_crypto as crypto;

/// Returns the crate name to verify linkage works.
pub fn name() -> &'static str {
    "stfx"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_call_crypto() {
        // Minimal smoke test: ensure the crypto crate is linked.
        assert_eq!(name(), "stfx");
        // If stfx-crypto exposes symbols later, invoke here.
    }
}
