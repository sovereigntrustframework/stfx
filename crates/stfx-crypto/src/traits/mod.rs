//! Core cryptographic traits of the Sovereign Trust Framework (SFT)
//! Layer 1 — ToIP cryptographic foundations
//! Designed for maximum modularity, zero coupling, and long-term extensibility.

pub mod aead;
pub mod digest;
pub mod hasher;
pub mod key_agreement;
pub mod key_pair;
pub mod multibase;
pub mod multicodec;
pub mod randomness;
pub mod signer;
pub mod verifier;

pub use aead::Aead;
pub use digest::Digest;
pub use hasher::Hasher;
pub use key_agreement::KeyAgreement;
pub use key_pair::KeyPair;
pub use multibase::MultibaseEncoder;
pub use multicodec::MulticodecEncoder;
pub use randomness::Randomness;
pub use signer::Signer;
pub use verifier::Verifier;
