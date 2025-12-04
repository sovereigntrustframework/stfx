//! Trust Spanning Protocol (TSP) implementation for STFx.
//!
//! This crate provides a modular implementation of the Trust Spanning Protocol,
//! built on top of STFx primitives (crypto, VIDs, storage, transport).
//!
//! # Architecture
//!
//! The implementation is organized into independent modules:
//!
//! - **`error`**: Error types and conversions
//! - **`types`**: Core message and relationship types
//! - **`wallet`**: In-memory wallet for managing VIDs and relationships
//! - **`message`**: Message sealing/opening operations (sealed envelope)
//! - **`relationship`**: Relationship state machine
//! - **`handler`**: Main message dispatch and handling
//!
//! # Design Principles (STFx)
//!
//! - **Rust-first**: Core logic in this crate; bindings are thin wrappers
//! - **Modular**: Each concern in its own module with clear interfaces
//! - **TSP SDK alignment**: Follows patterns from TSP reference implementation
//! - **Async**: Built on Tokio for production-grade async I/O
//! - **Trait-based**: Uses trait abstractions for flexibility and testing
//!
//! # Example
//!
//! ```rust,ignore
//! use stfx_tsp::{TspWallet, TspHandler};
//! use stfx_vid::OwnedVid;
//! use url::Url;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create wallet
//!     let wallet = TspWallet::new();
//!
//!     // Create and add a VID
//!     let endpoint = Url::parse("tcp://127.0.0.1:8080")?;
//!     let owned_vid = OwnedVid::new_did_peer(endpoint)?;
//!     wallet.add_private_vid(
//!         owned_vid.identifier().to_string(),
//!         Some(owned_vid.signing_key().into()),
//!         None,
//!     ).await?;
//!
//!     // Create handler
//!     let handler = TspHandler::new(wallet);
//!
//!     // Make relationship request
//!     let (url, message) = handler
//!         .propose_relationship(owned_vid.identifier(), "did:peer:...").await?;
//!
//!     Ok(())
//! }
//! ```

// Module declarations
pub mod cesr_utils;
pub mod crypto;
pub mod error;
pub mod handler;
pub mod message;
pub mod relationship;
pub mod routing;
pub mod signatures;
pub mod storage;
pub mod types;
pub mod wallet;

// Re-exports for convenience
pub use cesr_utils::{decode_digest, decode_nonce, decode_public_key, decode_signature, encode_digest, encode_nonce, encode_public_key, encode_signature};
pub use crypto::{open_payload, seal_payload, EncryptedMessage};
pub use error::{Result, TspError};
pub use handler::TspHandler;
pub use message::TspMessage;
pub use routing::{forward_message, process_routed_message, RouteTable};
pub use signatures::{sign_message, verify_signature, SignedMessage};
pub use storage::WalletSnapshot;
pub use types::{MessageType, ReceivedTspMessage, RelationshipStatus, TspPayload};
pub use wallet::TspWallet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_creation() {
        let _wallet = TspWallet::new();
        assert!(true);
    }
}
