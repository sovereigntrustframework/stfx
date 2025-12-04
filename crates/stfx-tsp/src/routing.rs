//! Message routing and forwarding for TSP.
//!
//! Implements relay and routing capabilities for TSP messages, enabling
//! communication through intermediaries and nested relationships.

use crate::error::Result;
use crate::types::{ReceivedTspMessage, Route, TspPayload};
use std::collections::HashMap;

/// Route entry for a VID (sequence of hops to reach it).
#[derive(Clone, Debug)]
pub struct RouteEntry {
    /// The destination VID.
    pub vid: String,

    /// Sequence of VIDs to traverse (hops).
    pub hops: Route,

    /// When this route was learned (timestamp).
    pub learned_at: std::time::SystemTime,
}

impl RouteEntry {
    /// Create a new route entry.
    pub fn new(vid: String, hops: Route) -> Self {
        Self {
            vid,
            hops,
            learned_at: std::time::SystemTime::now(),
        }
    }

    /// Check if route is valid (not stale).
    pub fn is_valid(&self, ttl_secs: u64) -> bool {
        match self.learned_at.elapsed() {
            Ok(elapsed) => elapsed.as_secs() < ttl_secs,
            Err(_) => false,
        }
    }
}

/// Route table for managing known paths to VIDs.
#[derive(Clone, Debug)]
pub struct RouteTable {
    /// Mapping from VID to route entry.
    routes: HashMap<String, RouteEntry>,

    /// TTL for routes in seconds (default: 3600 = 1 hour).
    ttl_secs: u64,
}

impl RouteTable {
    /// Create a new route table with default TTL.
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            ttl_secs: 3600,
        }
    }

    /// Create a new route table with custom TTL.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            routes: HashMap::new(),
            ttl_secs,
        }
    }

    /// Add or update a route.
    pub fn add_route(&mut self, vid: String, hops: Route) {
        let entry = RouteEntry::new(vid.clone(), hops);
        self.routes.insert(vid, entry);
    }

    /// Get a route to a VID if it exists and is valid.
    pub fn get_route(&self, vid: &str) -> Option<Route> {
        self.routes.get(vid).and_then(|entry| {
            if entry.is_valid(self.ttl_secs) {
                Some(entry.hops.clone())
            } else {
                None
            }
        })
    }

    /// Remove expired routes.
    pub fn cleanup_stale_routes(&mut self) {
        self.routes
            .retain(|_, entry| entry.is_valid(self.ttl_secs));
    }

    /// List all valid routes.
    pub fn list_routes(&self) -> Vec<(String, Route)> {
        self.routes
            .iter()
            .filter(|(_, entry)| entry.is_valid(self.ttl_secs))
            .map(|(vid, entry)| (vid.clone(), entry.hops.clone()))
            .collect()
    }
}

/// Forward a message along a route.
pub fn forward_message(
    _sender: &str,
    _receiver: &str,
    route: &Route,
    payload: &TspPayload,
) -> Result<(String, Vec<u8>)> {
    if route.is_empty() {
        return Err(crate::error::TspError::InvalidRoute(
            "Route is empty".to_string(),
        ));
    }

    // First hop is the next relay
    let next_hop = route[0].clone();

    // Serialize payload
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))?;

    // Create routed message with remaining hops
    let remaining_hops = route[1..].to_vec();
    let routed_payload = TspPayload::RoutedMessage {
        hops: remaining_hops,
        payload: payload_bytes,
    };

    let message = serde_json::to_vec(&routed_payload)
        .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))?;

    Ok((next_hop, message))
}

/// Process a received routed message.
pub fn process_routed_message(
    sender: &str,
    hops: &Route,
    payload: &[u8],
) -> Result<ReceivedTspMessage> {
    if hops.is_empty() {
        // Final destination - unwrap payload
        let inner_payload: TspPayload = serde_json::from_slice(payload)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))?;

        match inner_payload {
            TspPayload::Content(data) => Ok(ReceivedTspMessage::GenericMessage {
                sender: sender.to_string(),
                receiver: None,
                message: data,
                message_type: crate::types::MessageType {
                    crypto_type: crate::types::CryptoType::Plaintext,
                    signature_type: crate::types::SignatureType::NoSignature,
                },
            }),
            _ => Ok(ReceivedTspMessage::GenericMessage {
                sender: sender.to_string(),
                receiver: None,
                message: payload.to_vec(),
                message_type: crate::types::MessageType {
                    crypto_type: crate::types::CryptoType::Plaintext,
                    signature_type: crate::types::SignatureType::NoSignature,
                },
            }),
        }
    } else {
        // Intermediate hop - needs to be forwarded
        Err(crate::error::TspError::InvalidRoute(
            "Intermediate relay needs forwarding logic".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_table_add_get() {
        let mut table = RouteTable::new();

        let route = vec!["relay1".to_string(), "relay2".to_string()];
        table.add_route("did:peer:bob".to_string(), route.clone());

        let retrieved = table.get_route("did:peer:bob").unwrap();
        assert_eq!(retrieved, route);
    }

    #[test]
    fn test_route_validity() {
        let mut table = RouteTable::with_ttl(1); // 1 second TTL
        let route = vec!["relay".to_string()];
        table.add_route("did:peer:bob".to_string(), route);

        // Should exist immediately
        assert!(table.get_route("did:peer:bob").is_some());

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should be expired
        assert!(table.get_route("did:peer:bob").is_none());
    }

    #[test]
    fn test_forward_message() {
        let route = vec![
            "relay1".to_string(),
            "relay2".to_string(),
            "did:peer:bob".to_string(),
        ];

        let payload = TspPayload::Content(b"hello".to_vec());

        let (next_hop, _msg) =
            forward_message("did:peer:alice", "did:peer:bob", &route, &payload).unwrap();

        assert_eq!(next_hop, "relay1");
    }

    #[test]
    fn test_process_routed_message_final_hop() {
        let payload = TspPayload::Content(b"test content".to_vec());
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        let result = process_routed_message("did:peer:alice", &vec![], &payload_bytes).unwrap();

        match result {
            ReceivedTspMessage::GenericMessage { message, .. } => {
                assert_eq!(message, b"test content".to_vec());
            }
            _ => panic!("Expected GenericMessage"),
        }
    }

    #[test]
    fn test_cleanup_stale_routes() {
        let mut table = RouteTable::with_ttl(1);

        table.add_route("vid1".to_string(), vec!["relay".to_string()]);
        assert_eq!(table.list_routes().len(), 1);

        std::thread::sleep(std::time::Duration::from_secs(2));
        table.cleanup_stale_routes();

        assert_eq!(table.list_routes().len(), 0);
    }
}
