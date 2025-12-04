//! Core cryptographic traits of the Sovereign Trust Framework (SFT)
//! Layer 1 — ToIP cryptographic foundations
//! Designed for maximum modularity, zero coupling, and long-term extensibility.

pub mod key_pair;
pub mod signer;
pub mod verifier;
pub mod hasher;
pub mod digest;
pub mod randomness;
pub mod multibase;
pub mod multicodec;
pub mod compat;

pub use key_pair::KeyPair;
pub use signer::Signer;
pub use verifier::Verifier;
pub use hasher::Hasher;
pub use digest::Digest;
pub use randomness::Randomness;
pub use multibase::MultibaseEncoder;
pub use multicodec::MulticodecEncoder;

// Back-compat traits still used by implementations
pub use compat::{KeyAgreement, Aead};
