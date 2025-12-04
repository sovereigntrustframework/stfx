//! TSP message handler and coordination.

use crate::error::Result;
use crate::message::TspMessage;
use crate::relationship::RelationshipManager;
use crate::routing::RouteTable;
use crate::types::{ReceivedTspMessage, RelationshipStatus, Route, ThreadId, TspPayload};
use crate::wallet::TspWallet;
use stfx_crypto::Hasher;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/// Main TSP handler coordinating wallet operations and message handling.
pub struct TspHandler {
    wallet: TspWallet,

    /// Route table for message forwarding.
    routes: Arc<RwLock<RouteTable>>,
}

impl TspHandler {
    /// Create a new TSP handler with a wallet.
    pub fn new(wallet: TspWallet) -> Self {
        Self {
            wallet,
            routes: Arc::new(RwLock::new(RouteTable::new())),
        }
    }

    /// Create a TSP handler with a custom route table.
    pub fn with_routes(wallet: TspWallet, routes: RouteTable) -> Self {
        Self {
            wallet,
            routes: Arc::new(RwLock::new(routes)),
        }
    }

    /// Add or update a route to a VID.
    pub async fn add_route(&self, vid: String, hops: Route) {
        let mut routes = self.routes.write().await;
        routes.add_route(vid, hops);
    }

    /// Get a route to a VID if known.
    pub async fn get_route(&self, vid: &str) -> Option<Route> {
        let routes = self.routes.read().await;
        routes.get_route(vid)
    }

    /// List all known routes.
    pub async fn list_routes(&self) -> Vec<(String, Route)> {
        let routes = self.routes.read().await;
        routes.list_routes()
    }

    /// Propose a relationship to a remote VID.
    pub async fn propose_relationship(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(Url, Vec<u8>)> {
        // Verify sender is a private VID
        if !self.wallet.has_private_vid(sender).await? {
            return Err(crate::error::TspError::MissingPrivateVid(
                sender.to_string(),
            ));
        }

        // Verify receiver is a verified VID
        if !self.wallet.has_verified_vid(receiver).await? {
            return Err(crate::error::TspError::UnverifiedVid(receiver.to_string()));
        }

        // Generate thread ID using hash of sender || receiver
        let hasher = stfx_crypto::hash::Blake2b256Hasher;
        let mut data = sender.as_bytes().to_vec();
        data.extend_from_slice(receiver.as_bytes());
        let thread_id = Hasher::hash(&hasher, &data);

        // Update relationship status
        self.wallet
            .set_relationship(
                receiver,
                RelationshipManager::initiate(thread_id.clone())?,
                Some(sender.to_string()),
            )
            .await?;

        // Create payload for relationship proposal
        let payload = TspPayload::RequestRelationship {
            route: None,
            thread_id: thread_id.clone(),
        };

        // Serialize payload to bytes
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))?;

        // Wrap in TSP message
        let msg = TspMessage::new(
            sender.to_string(),
            Some(receiver.to_string()),
            payload_bytes,
            None,
        );

        let sealed = msg.to_bytes()?;

        // Would return actual transport URL from VID metadata
        let url = Url::parse("tcp://127.0.0.1:8080")?;

        Ok((url, sealed))
    }

    /// Accept a relationship proposal.
    pub async fn accept_relationship(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: &ThreadId,
    ) -> Result<(Url, Vec<u8>)> {
        // Verify both are valid VIDs
        if !self.wallet.has_private_vid(receiver).await? {
            return Err(crate::error::TspError::MissingPrivateVid(
                receiver.to_string(),
            ));
        }

        if !self.wallet.has_verified_vid(sender).await? {
            return Err(crate::error::TspError::UnverifiedVid(sender.to_string()));
        }

        // Get current relationship status
        let current_status = self
            .wallet
            .get_relationship(sender, receiver)
            .await
            .unwrap_or(RelationshipStatus::Unrelated);

        // Transition to bidirectional
        let new_status = RelationshipManager::accept(&current_status, thread_id)?;

        self.wallet
            .set_relationship(sender, new_status, Some(receiver.to_string()))
            .await?;

        // Create and seal acceptance message
        let msg = TspMessage::new(
            receiver.to_string(),
            Some(sender.to_string()),
            Default::default(),
            None,
        );

        let payload = msg.to_bytes()?;
        let url = Url::parse("tcp://127.0.0.1:8080")?;

        Ok((url, payload))
    }

    /// Cancel a relationship.
    pub async fn cancel_relationship(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(Url, Vec<u8>)> {
        // Get current status
        let current_status = self
            .wallet
            .get_relationship(receiver, sender)
            .await
            .unwrap_or(RelationshipStatus::Unrelated);

        // Transition to unrelated
        let new_status = RelationshipManager::cancel(&current_status)?;

        self.wallet
            .set_relationship(sender, new_status, None)
            .await?;

        // Create cancellation message
        let msg = TspMessage::new(
            sender.to_string(),
            Some(receiver.to_string()),
            Default::default(),
            None,
        );

        let payload = msg.to_bytes()?;
        let url = Url::parse("tcp://127.0.0.1:8080")?;

        Ok((url, payload))
    }

    /// Handle a received message.
    pub async fn handle_message(&self, message: Vec<u8>) -> Result<ReceivedTspMessage> {
        let tsp_msg = TspMessage::from_bytes(&message)?;

        // Deserialize the payload to determine message type
        let payload: TspPayload = serde_json::from_slice(&tsp_msg.payload)
            .map_err(|e| crate::error::TspError::MessageFormat(e.to_string()))?;

        match payload {
            TspPayload::Content(data) => Ok(ReceivedTspMessage::GenericMessage {
                sender: tsp_msg.sender,
                receiver: tsp_msg.receiver,
                message: data,
                message_type: crate::types::MessageType {
                    crypto_type: crate::types::CryptoType::Encrypted,
                    signature_type: crate::types::SignatureType::Signature,
                },
            }),

            TspPayload::RequestRelationship {
                route,
                thread_id,
            } => {
                // Store route if provided
                if let Some(hops) = route {
                    self.add_route(tsp_msg.sender.clone(), hops).await;
                }

                Ok(ReceivedTspMessage::RequestRelationship {
                    sender: tsp_msg.sender,
                    receiver: tsp_msg.receiver.unwrap_or_default(),
                    route: None,
                    thread_id,
                    nested_vid: None,
                })
            }

            TspPayload::AcceptRelationship { thread_id: _ } => {
                Ok(ReceivedTspMessage::AcceptRelationship {
                    sender: tsp_msg.sender,
                    receiver: tsp_msg.receiver.unwrap_or_default(),
                    nested_vid: None,
                })
            }

            TspPayload::CancelRelationship { thread_id: _ } => {
                Ok(ReceivedTspMessage::CancelRelationship {
                    sender: tsp_msg.sender,
                    receiver: tsp_msg.receiver.unwrap_or_default(),
                })
            }

            TspPayload::RoutedMessage { hops, payload } => {
                use crate::routing::process_routed_message;

                if hops.is_empty() {
                    // Final destination
                    process_routed_message(&tsp_msg.sender, &hops, &payload)
                } else {
                    // Intermediate hop - need to forward
                    Err(crate::error::TspError::InvalidRoute(
                        "Relay not implemented for intermediate hops".to_string(),
                    ))
                }
            }

            // Other payload types not fully implemented yet
            _ => Ok(ReceivedTspMessage::GenericMessage {
                sender: tsp_msg.sender,
                receiver: tsp_msg.receiver,
                message: tsp_msg.payload,
                message_type: crate::types::MessageType {
                    crypto_type: crate::types::CryptoType::Encrypted,
                    signature_type: crate::types::SignatureType::Signature,
                },
            }),
        }
    }

    /// Get reference to the wallet.
    pub fn wallet(&self) -> &TspWallet {
        &self.wallet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handler_creation() {
        let wallet = TspWallet::new();
        let handler = TspHandler::new(wallet);
        assert!(handler.wallet().list_vids().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_propose_relationship() {
        let wallet = TspWallet::new();
        wallet
            .add_private_vid("alice".to_string(), Some(b"dummy-key".to_vec()), None)
            .await
            .unwrap();
        wallet
            .add_verified_vid("bob".to_string(), None)
            .await
            .unwrap();

        let handler = TspHandler::new(wallet.clone());
        let result = handler.propose_relationship("alice", "bob").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_propose_nonexistent_sender() {
        let wallet = TspWallet::new();
        wallet
            .add_verified_vid("bob".to_string(), None)
            .await
            .unwrap();

        let handler = TspHandler::new(wallet);
        let result = handler.propose_relationship("alice", "bob").await;
        assert!(result.is_err());
    }
}
