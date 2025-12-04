//! TSP message types and definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type alias for thread IDs (digests).
pub type ThreadId = Vec<u8>;

/// Type alias for routes (lists of VID strings).
pub type Route = Vec<String>;

/// Relationship status between two VIDs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationshipStatus {
    /// No relationship established.
    Unrelated,
    /// One-way relationship (initiator -> recipient).
    Unidirectional { thread_id: ThreadId },
    /// One-way relationship (recipient -> initiator).
    ReverseUnidirectional { thread_id: ThreadId },
    /// Two-way relationship established.
    Bidirectional {
        thread_id: ThreadId,
        outstanding_nested_thread_ids: Vec<ThreadId>,
    },
}

impl RelationshipStatus {
    /// Create a default bidirectional relationship.
    pub fn bi_default() -> Self {
        Self::Bidirectional {
            thread_id: Vec::new(),
            outstanding_nested_thread_ids: Vec::new(),
        }
    }

    /// Create a bidirectional relationship with a specific thread ID.
    pub fn bi(thread_id: ThreadId) -> Self {
        Self::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: Vec::new(),
        }
    }
}

/// TSP control message payloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TspPayload {
    /// Plain content message.
    Content(Vec<u8>),

    /// Relationship request.
    RequestRelationship {
        route: Option<Route>,
        thread_id: ThreadId,
    },

    /// Relationship acceptance.
    AcceptRelationship { thread_id: ThreadId },

    /// Relationship cancellation.
    CancelRelationship { thread_id: ThreadId },

    /// Nested relationship request (with inner signed message).
    RequestNestedRelationship { inner: Vec<u8>, thread_id: ThreadId },

    /// Nested relationship acceptance (with inner signed message).
    AcceptNestedRelationship { inner: Vec<u8>, thread_id: ThreadId },

    /// New identifier notification.
    NewIdentifier {
        thread_id: ThreadId,
        new_vid: String,
    },

    /// Third-party introduction (referral).
    Referral { referred_vid: String },

    /// Routed message (intermediate hop).
    RoutedMessage { hops: Route, payload: Vec<u8> },

    /// Nested message (parent relay).
    NestedMessage { payload: Vec<u8> },
}

/// Received TSP message variants.
#[derive(Clone, Debug)]
pub enum ReceivedTspMessage {
    /// Generic content message.
    GenericMessage {
        sender: String,
        receiver: Option<String>,
        message: Vec<u8>,
        message_type: MessageType,
    },

    /// Relationship request received.
    RequestRelationship {
        sender: String,
        receiver: String,
        route: Option<Route>,
        thread_id: ThreadId,
        nested_vid: Option<String>,
    },

    /// Relationship acceptance received.
    AcceptRelationship {
        sender: String,
        receiver: String,
        nested_vid: Option<String>,
    },

    /// Relationship cancellation received.
    CancelRelationship { sender: String, receiver: String },

    /// New identifier notification received.
    NewIdentifier {
        sender: String,
        receiver: String,
        new_vid: String,
    },

    /// Third-party introduction received.
    Referral {
        sender: String,
        receiver: String,
        referred_vid: String,
    },

    /// Routed message to forward.
    ForwardRequest {
        sender: String,
        receiver: String,
        next_hop: String,
        route: Vec<Vec<u8>>,
        opaque_payload: Vec<u8>,
    },
}

/// Message type metadata.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct MessageType {
    pub crypto_type: CryptoType,
    pub signature_type: SignatureType,
}

/// Cryptographic treatment of message.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum CryptoType {
    /// Encrypted and authenticated.
    Encrypted,
    /// Signed but not encrypted.
    Plaintext,
}

/// Signature type on message.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum SignatureType {
    /// No signature present.
    NoSignature,
    /// Single signature present.
    Signature,
}

/// VID context metadata stored in wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VidContext {
    /// The verified VID.
    pub vid: String,

    /// Optional private key material for this VID.
    pub private: Option<Vec<u8>>,

    /// Relationship status with this VID.
    pub relation_status: RelationshipStatus,

    /// If in a relationship, the counterparty VID.
    pub relation_vid: Option<String>,

    /// Parent VID (for nested identities).
    pub parent_vid: Option<String>,

    /// Route for reaching this VID.
    pub tunnel: Option<Route>,

    /// Application metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Aliases mapping (friendly name -> DID).
pub type Aliases = HashMap<String, String>;

/// WebVH update keys.
pub type WebvhUpdateKeys = HashMap<String, Vec<u8>>;
