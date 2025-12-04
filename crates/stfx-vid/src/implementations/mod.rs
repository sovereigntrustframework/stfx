//! Implementations of VID traits.
//!
//! This module contains concrete VID implementations following the trait patterns
//! defined in the traits module.
//!
//! # Available Implementations
//!
//! - [`PeerVid`]: A peer endpoint in the TSP network with public/optional secret keys.
//!   Supports both evaluator-side and controller-side operations.
//!
//! # Future Implementations
//!
//! Planned implementations:
//! - `UrlVid`: URL-based VID for HTTP endpoints
//! - `SocketVid`: Socket address-based VID for network endpoints
//! - `DIDVid`: DID (Decentralized Identifier) based VID

pub mod peer;

pub use peer::PeerVid;
