//! Integration tests for complete TSP workflows.

#[cfg(test)]
mod integration_tests {
    use stfx_tsp::*;

    #[tokio::test]
    async fn test_complete_relationship_workflow() {
        // Setup
        let alice_wallet = TspWallet::new();
        let bob_wallet = TspWallet::new();

        // Add VIDs
        alice_wallet
            .add_private_vid(
                "did:peer:alice".to_string(),
                Some(b"alice-key".to_vec()),
                None,
            )
            .await
            .unwrap();

        bob_wallet
            .add_private_vid(
                "did:peer:bob".to_string(),
                Some(b"bob-key".to_vec()),
                None,
            )
            .await
            .unwrap();

        alice_wallet
            .add_verified_vid("did:peer:bob".to_string(), None)
            .await
            .unwrap();

        bob_wallet
            .add_verified_vid("did:peer:alice".to_string(), None)
            .await
            .unwrap();

        // Create handlers
        let alice_handler = TspHandler::new(alice_wallet.clone());
        let bob_handler = TspHandler::new(bob_wallet.clone());

        // Alice proposes
        let (_, propose_msg) = alice_handler
            .propose_relationship("did:peer:alice", "did:peer:bob")
            .await
            .unwrap();

        // Bob receives and processes
        let received = bob_handler.handle_message(propose_msg).await.unwrap();

        match received {
            ReceivedTspMessage::RequestRelationship { sender, .. } => {
                assert_eq!(sender, "did:peer:alice");
            }
            _ => panic!("Expected RequestRelationship"),
        }
    }

    #[tokio::test]
    async fn test_routing_workflow() {
        // Three-party setup: Alice -> Relay -> Bob
        let alice_wallet = TspWallet::new();
        let relay_wallet = TspWallet::new();
        let bob_wallet = TspWallet::new();

        // Add VIDs
        alice_wallet
            .add_private_vid(
                "did:peer:alice".to_string(),
                Some(b"alice-key".to_vec()),
                None,
            )
            .await
            .unwrap();

        relay_wallet
            .add_private_vid(
                "did:peer:relay".to_string(),
                Some(b"relay-key".to_vec()),
                None,
            )
            .await
            .unwrap();

        bob_wallet
            .add_private_vid(
                "did:peer:bob".to_string(),
                Some(b"bob-key".to_vec()),
                None,
            )
            .await
            .unwrap();

        alice_wallet
            .add_verified_vid("did:peer:bob".to_string(), None)
            .await
            .unwrap();

        // Create handlers with routing
        let alice_handler = TspHandler::new(alice_wallet);
        let bob_handler = TspHandler::new(bob_wallet);

        // Set up route
        alice_handler
            .add_route(
                "did:peer:bob".to_string(),
                vec!["did:peer:relay".to_string()],
            )
            .await;

        // Verify route
        let routes = alice_handler.list_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0, "did:peer:bob");
        assert_eq!(routes[0].1, vec!["did:peer:relay".to_string()]);

        // Bob receives message
        let (_, msg) = alice_handler
            .propose_relationship("did:peer:alice", "did:peer:bob")
            .await
            .unwrap();

        let received = bob_handler.handle_message(msg).await.unwrap();

        match received {
            ReceivedTspMessage::RequestRelationship { sender, .. } => {
                assert_eq!(sender, "did:peer:alice");
            }
            _ => panic!("Expected RequestRelationship"),
        }
    }

    #[tokio::test]
    async fn test_wallet_snapshot_persistence() {
        // Create wallet with VIDs
        let wallet = TspWallet::new();

        wallet
            .add_private_vid(
                "alice".to_string(),
                Some(b"key1".to_vec()),
                None,
            )
            .await
            .unwrap();

        wallet
            .add_verified_vid("bob".to_string(), None)
            .await
            .unwrap();

        // Take snapshot
        let snapshot = WalletSnapshot::from_wallet(&wallet).await.unwrap();

        // Serialize
        let json = snapshot.to_json().unwrap();

        // Deserialize
        let restored = WalletSnapshot::from_json(&json).unwrap();

        // Restore to new wallet
        let new_wallet = TspWallet::new();
        restored.restore_to_wallet(&new_wallet).await.unwrap();

        // Verify
        assert!(new_wallet.has_private_vid("alice").await.unwrap());
        assert!(new_wallet.has_verified_vid("bob").await.unwrap());
    }

    #[tokio::test]
    async fn test_message_encryption_roundtrip() {
        let payload = TspPayload::Content(b"sensitive data".to_vec());
        let key = [42u8; 32];
        let aad = b"additional context";

        // Encrypt
        let encrypted = seal_payload(&payload, &key, aad).unwrap();

        // Serialize
        let bytes = encrypted.to_bytes().unwrap();

        // Deserialize
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

        // Decrypt
        let decrypted = open_payload(&restored, &key).unwrap();

        match decrypted {
            TspPayload::Content(data) => {
                assert_eq!(data, b"sensitive data".to_vec());
            }
            _ => panic!("Expected Content"),
        }
    }

    #[tokio::test]
    async fn test_multiple_vids_per_wallet() {
        let wallet = TspWallet::new();

        // Add multiple VIDs
        for i in 0..5 {
            wallet
                .add_private_vid(
                    format!("did:peer:id{}", i),
                    Some(format!("key{}", i).into_bytes()),
                    None,
                )
                .await
                .unwrap();
        }

        // List and verify
        let vids = wallet.list_vids().await.unwrap();
        assert_eq!(vids.len(), 5);

        // Each should be a private VID
        for i in 0..5 {
            let vid = format!("did:peer:id{}", i);
            assert!(wallet.has_private_vid(&vid).await.unwrap());
        }
    }

    #[tokio::test]
    async fn test_relationship_state_transitions() {
        let wallet = TspWallet::new();

        wallet
            .add_private_vid(
                "alice".to_string(),
                Some(b"key".to_vec()),
                None,
            )
            .await
            .unwrap();

        wallet
            .add_verified_vid("bob".to_string(), None)
            .await
            .unwrap();

        let handler = TspHandler::new(wallet);

        // Propose relationship - this generates the thread_id internally
        let (_, msg1) = handler
            .propose_relationship("alice", "bob")
            .await
            .unwrap();

        // Extract thread_id from the proposal message
        let proposal_msg = TspMessage::from_bytes(&msg1).unwrap();
        let payload: TspPayload = serde_json::from_slice(&proposal_msg.payload).unwrap();
        let thread_id = match payload {
            TspPayload::RequestRelationship { thread_id, .. } => thread_id,
            _ => panic!("Expected RequestRelationship payload"),
        };

        // Accept relationship with the extracted thread_id
        let (_, msg2) = handler
            .accept_relationship("bob", "alice", &thread_id)
            .await
            .unwrap();

        // Both messages should be valid
        assert!(!msg1.is_empty());
        assert!(!msg2.is_empty());
    }
}
