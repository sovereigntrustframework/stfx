//! Persistent storage integration for TSP wallets.
//!
//! Provides simple serialization/deserialization of wallet data.
//! For production use, integrate with stfx-store for encryption.

use crate::error::Result;
use crate::types::{Aliases, VidContext, WebvhUpdateKeys};
use crate::wallet::TspWallet;
use serde::{Deserialize, Serialize};

/// Wallet snapshot for serialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSnapshot {
    /// All VID contexts in the wallet.
    pub vids: Vec<VidContext>,

    /// Aliases mapping.
    pub aliases: Aliases,

    /// WebVH update keys.
    pub keys: WebvhUpdateKeys,
}

impl WalletSnapshot {
    /// Create a snapshot from a wallet.
    pub async fn from_wallet(wallet: &TspWallet) -> Result<Self> {
        let (vids, aliases, keys) = wallet.export().await?;
        Ok(Self { vids, aliases, keys })
    }

    /// Restore a wallet from a snapshot.
    pub async fn restore_to_wallet(&self, wallet: &TspWallet) -> Result<()> {
        wallet
            .import(self.vids.clone(), self.aliases.clone(), self.keys.clone())
            .await
    }

    /// Serialize snapshot to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::TspError::Custom(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize snapshot from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| crate::error::TspError::Custom(format!("Failed to deserialize: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_snapshot_roundtrip() {
        let wallet = TspWallet::new();
        wallet
            .add_private_vid("alice".to_string(), Some(b"key".to_vec()), None)
            .await
            .unwrap();

        // Create snapshot
        let snapshot = WalletSnapshot::from_wallet(&wallet).await.unwrap();

        // Serialize and deserialize
        let json = snapshot.to_json().unwrap();
        let restored = WalletSnapshot::from_json(&json).unwrap();

        // Create new wallet and restore
        let wallet2 = TspWallet::new();
        restored.restore_to_wallet(&wallet2).await.unwrap();

        // Verify
        assert!(wallet2.has_private_vid("alice").await.unwrap());
    }
}
