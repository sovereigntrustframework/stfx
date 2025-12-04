//! TSP message sealing and opening.

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// A sealed TSP message (encrypted envelope).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TspMessage {
    /// Sender VID.
    pub sender: String,

    /// Receiver VID (None for broadcasts).
    pub receiver: Option<String>,

    /// Sealed payload (encrypted + authenticated).
    pub payload: Vec<u8>,

    /// Nonconfidential data (unencrypted header).
    pub nonconfidential_data: Option<Vec<u8>>,
}

impl TspMessage {
    /// Create a new sealed TSP message.
    pub fn new(
        sender: String,
        receiver: Option<String>,
        payload: Vec<u8>,
        nonconfidential_data: Option<Vec<u8>>,
    ) -> Self {
        Self {
            sender,
            receiver,
            payload,
            nonconfidential_data,
        }
    }

    /// Serialize message to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
    }

    /// Deserialize message from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = TspMessage::new(
            "did:peer:alice".to_string(),
            Some("did:peer:bob".to_string()),
            b"hello".to_vec(),
            None,
        );

        let bytes = msg.to_bytes().unwrap();
        let restored = TspMessage::from_bytes(&bytes).unwrap();

        assert_eq!(restored.sender, "did:peer:alice");
        assert_eq!(restored.receiver, Some("did:peer:bob".to_string()));
    }
}
