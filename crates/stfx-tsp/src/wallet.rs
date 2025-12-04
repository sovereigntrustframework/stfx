//! TSP wallet using stfx-store for persistence.

use crate::error::Result;
use crate::types::{Aliases, RelationshipStatus, VidContext, WebvhUpdateKeys};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// TSP wallet storing VIDs and relationships in memory with optional persistence.
#[derive(Clone)]
pub struct TspWallet {
    /// In-memory VID contexts.
    vids: Arc<RwLock<HashMap<String, VidContext>>>,

    /// Aliases mapping.
    aliases: Arc<RwLock<Aliases>>,

    /// WebVH update keys.
    keys: Arc<RwLock<WebvhUpdateKeys>>,
}

impl TspWallet {
    /// Create a new empty TSP wallet.
    pub fn new() -> Self {
        Self {
            vids: Arc::new(RwLock::new(HashMap::new())),
            aliases: Arc::new(RwLock::new(HashMap::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Export wallet data for persistence.
    pub async fn export(&self) -> Result<(Vec<VidContext>, Aliases, WebvhUpdateKeys)> {
        let vids = self.vids.read().await.values().cloned().collect();
        let aliases = self.aliases.read().await.clone();
        let keys = self.keys.read().await.clone();
        Ok((vids, aliases, keys))
    }

    /// Import wallet data from persistence.
    pub async fn import(
        &self,
        vids: Vec<VidContext>,
        aliases: Aliases,
        keys: WebvhUpdateKeys,
    ) -> Result<()> {
        {
            let mut vids_guard = self.vids.write().await;
            for vid in vids {
                vids_guard.insert(vid.vid.clone(), vid);
            }
        }

        {
            let mut aliases_guard = self.aliases.write().await;
            *aliases_guard = aliases;
        }

        {
            let mut keys_guard = self.keys.write().await;
            *keys_guard = keys;
        }

        Ok(())
    }

    /// Add a private VID (locally owned identity).
    pub async fn add_private_vid(
        &self,
        vid: String,
        private: Option<Vec<u8>>,
        metadata: Option<serde_json::Value>,
    ) -> Result<()> {
        let mut vids = self.vids.write().await;
        vids.insert(
            vid.clone(),
            VidContext {
                vid,
                private,
                relation_status: RelationshipStatus::Unrelated,
                relation_vid: None,
                parent_vid: None,
                tunnel: None,
                metadata,
            },
        );
        Ok(())
    }

    /// Add a verified (remote) VID.
    pub async fn add_verified_vid(
        &self,
        vid: String,
        metadata: Option<serde_json::Value>,
    ) -> Result<()> {
        let mut vids = self.vids.write().await;
        vids.entry(vid.clone())
            .and_modify(|ctx| {
                ctx.metadata = metadata.clone();
            })
            .or_insert_with(|| VidContext {
                vid,
                private: None,
                relation_status: RelationshipStatus::Unrelated,
                relation_vid: None,
                parent_vid: None,
                tunnel: None,
                metadata,
            });
        Ok(())
    }

    /// Check if a private VID exists.
    pub async fn has_private_vid(&self, vid: &str) -> Result<bool> {
        let vids = self.vids.read().await;
        Ok(vids
            .get(vid)
            .map(|ctx| ctx.private.is_some())
            .unwrap_or(false))
    }

    /// Check if a verified VID exists.
    pub async fn has_verified_vid(&self, vid: &str) -> Result<bool> {
        let vids = self.vids.read().await;
        Ok(vids.contains_key(vid))
    }

    /// Get a VID context if it exists.
    pub async fn get_vid(&self, vid: &str) -> Result<Option<VidContext>> {
        let vids = self.vids.read().await;
        Ok(vids.get(vid).cloned())
    }

    /// List all VID identifiers.
    pub async fn list_vids(&self) -> Result<Vec<String>> {
        let vids = self.vids.read().await;
        Ok(vids.keys().cloned().collect())
    }

    /// Resolve an alias to a VID, or return as-is if not an alias.
    pub async fn resolve_alias(&self, alias: &str) -> Result<String> {
        let aliases = self.aliases.read().await;
        Ok(aliases
            .get(alias)
            .cloned()
            .unwrap_or_else(|| alias.to_string()))
    }

    /// Set an alias for a VID.
    pub async fn set_alias(&self, alias: String, vid: String) -> Result<()> {
        let mut aliases = self.aliases.write().await;
        aliases.insert(alias, vid);
        Ok(())
    }

    /// Set relationship status for a VID pair.
    pub async fn set_relationship(
        &self,
        vid: &str,
        status: RelationshipStatus,
        relation_vid: Option<String>,
    ) -> Result<()> {
        let mut vids = self.vids.write().await;
        if let Some(ctx) = vids.get_mut(vid) {
            ctx.relation_status = status;
            ctx.relation_vid = relation_vid;
            Ok(())
        } else {
            Err(crate::error::TspError::UnverifiedVid(vid.to_string()))
        }
    }

    /// Get relationship status between two VIDs.
    pub async fn get_relationship(
        &self,
        local_vid: &str,
        remote_vid: &str,
    ) -> Result<RelationshipStatus> {
        let vids = self.vids.read().await;
        if let Some(ctx) = vids.get(local_vid) {
            if ctx.relation_vid.as_deref() == Some(remote_vid) {
                Ok(ctx.relation_status.clone())
            } else {
                Ok(RelationshipStatus::Unrelated)
            }
        } else {
            Err(crate::error::TspError::UnverifiedVid(local_vid.to_string()))
        }
    }

    /// Set parent VID for a nested identity.
    pub async fn set_parent_vid(&self, vid: &str, parent: Option<&str>) -> Result<()> {
        let mut vids = self.vids.write().await;
        if let Some(ctx) = vids.get_mut(vid) {
            ctx.parent_vid = parent.map(|s| s.to_string());
            Ok(())
        } else {
            Err(crate::error::TspError::UnverifiedVid(vid.to_string()))
        }
    }

    /// Set route (tunnel) for reaching a VID.
    pub async fn set_route(&self, vid: &str, route: Option<Vec<String>>) -> Result<()> {
        let mut vids = self.vids.write().await;
        if let Some(ctx) = vids.get_mut(vid) {
            ctx.tunnel = route;
            Ok(())
        } else {
            Err(crate::error::TspError::UnverifiedVid(vid.to_string()))
        }
    }

    /// Store a WebVH update key.
    pub async fn store_key(&self, kid: String, secret_key: Vec<u8>) -> Result<()> {
        let mut keys = self.keys.write().await;
        keys.insert(kid, secret_key);
        Ok(())
    }

    /// Get a WebVH update key.
    pub async fn get_key(&self, kid: &str) -> Result<Option<Vec<u8>>> {
        let keys = self.keys.read().await;
        Ok(keys.get(kid).cloned())
    }
}

impl Default for TspWallet {
    fn default() -> Self {
        Self::new()
    }
}
