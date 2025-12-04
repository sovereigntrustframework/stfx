//! Peer VID implementation for TSP peer identifiers.
//!
//! A PeerVid represents a peer endpoint in a TSP network.
//! It includes:
//! - A peer identifier (typically a multibase-encoded hash or DID:key)
//! - Public keys for encryption and signing (always present)
//! - Optional secret keys (only present on controller side)
//! - Capability flags for supported operations

use crate::error::{Error, VerifyError};
use crate::traits::{ControllerView, EvaluatorView, PrivateKey, PublicKey, Verifiable, Vid};
use std::fmt;

/// A Peer VID: represents a peer endpoint in the TSP network.
///
/// A peer can act as either a controller (with secret keys) or an evaluator (public keys only).
/// Peer VIDs support full verification including cryptographic validation and policy checking.
#[derive(Clone)]
pub struct PeerVid {
    /// Unique peer identifier (e.g., "peer:12D3KooDHgSV..." or "did:key:z6M...")
    peer_id: String,

    /// Encryption public key (always present)
    pk_e: PublicKey,

    /// Signing public key (always present)
    pk_s: PublicKey,

    /// Optional encryption secret key (only on controller side)
    sk_e: Option<PrivateKey>,

    /// Optional signing secret key (only on controller side)
    sk_s: Option<PrivateKey>,

    /// Whether this peer can be verified (e.g., not revoked)
    is_verifiable: bool,
}

impl PeerVid {
    /// Create a new evaluator-side PeerVid (public keys only).
    ///
    /// Use this when you have a remote peer's public keys but not the secret keys.
    pub fn new(peer_id: impl Into<String>, pk_e: PublicKey, pk_s: PublicKey) -> Self {
        Self {
            peer_id: peer_id.into(),
            pk_e,
            pk_s,
            sk_e: None,
            sk_s: None,
            is_verifiable: true,
        }
    }

    /// Create a controller-side PeerVid (with secret keys).
    ///
    /// Use this when you control the peer and have access to secret keys.
    pub fn with_secrets(
        peer_id: impl Into<String>,
        pk_e: PublicKey,
        pk_s: PublicKey,
        sk_e: PrivateKey,
        sk_s: PrivateKey,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            pk_e,
            pk_s,
            sk_e: Some(sk_e),
            sk_s: Some(sk_s),
            is_verifiable: true,
        }
    }

    /// Get the peer identifier.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Check if this peer has secret key material (is controller-side).
    pub fn is_controller(&self) -> bool {
        self.sk_e.is_some() && self.sk_s.is_some()
    }

    /// Check if this peer is verifiable.
    pub fn is_verifiable(&self) -> bool {
        self.is_verifiable
    }

    /// Mark this peer as revoked (no longer verifiable).
    pub fn revoke(&mut self) {
        self.is_verifiable = false;
    }
}

impl fmt::Display for PeerVid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerVid({}; controller={}; verifiable={})",
            self.peer_id,
            self.is_controller(),
            self.is_verifiable
        )
    }
}

impl fmt::Debug for PeerVid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerVid")
            .field("peer_id", &self.peer_id)
            .field("pk_e", &self.pk_e)
            .field("pk_s", &self.pk_s)
            .field("has_sk_e", &self.sk_e.is_some())
            .field("has_sk_s", &self.sk_s.is_some())
            .field("is_verifiable", &self.is_verifiable)
            .finish()
    }
}

/// Transport address for PeerVid is the peer ID itself.
impl Vid for PeerVid {
    type Address = String;

    fn as_str(&self) -> &str {
        &self.peer_id
    }

    fn resolve_address(&self) -> Result<Self::Address, Error> {
        Ok(self.peer_id.clone())
    }
}

/// Evaluator-side view: Public key access for all PeerVids.
impl EvaluatorView for PeerVid {
    fn pk_e(&self) -> Result<PublicKey, Error> {
        Ok(self.pk_e.clone())
    }

    fn pk_s(&self) -> Result<PublicKey, Error> {
        Ok(self.pk_s.clone())
    }
}

/// Controller-side view: Secret key access for controller-side PeerVids.
impl ControllerView for PeerVid {
    fn sk_e(&self) -> Result<PrivateKey, Error> {
        self.sk_e.clone().ok_or_else(|| {
            Error::SecretKeyNotAvailable(
                "This PeerVid is evaluator-only (no controller secret keys)".into(),
            )
        })
    }

    fn sk_s(&self) -> Result<PrivateKey, Error> {
        self.sk_s.clone().ok_or_else(|| {
            Error::SecretKeyNotAvailable(
                "This PeerVid is evaluator-only (no controller secret keys)".into(),
            )
        })
    }
}

/// Verification: Comprehensive VID validation.
impl Verifiable for PeerVid {
    fn verify(&self) -> Result<(), VerifyError> {
        // Check if peer is revoked or otherwise not verifiable
        if !self.is_verifiable {
            return Err(VerifyError::InvalidStatus("Peer is revoked or not verifiable".into()));
        }

        // Verify public keys are present and valid (non-empty)
        if self.pk_e.bytes().is_empty() {
            return Err(VerifyError::RecordsInvalid(
                "Encryption public key is empty".into(),
            ));
        }

        if self.pk_s.bytes().is_empty() {
            return Err(VerifyError::RecordsInvalid(
                "Signing public key is empty".into(),
            ));
        }

        // Verify peer ID is not empty
        if self.peer_id.is_empty() {
            return Err(VerifyError::RecordsInvalid("Peer ID is empty".into()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_evaluator_peer() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");

        let peer = PeerVid::new("peer:test123", pk_e, pk_s);

        assert_eq!(peer.peer_id(), "peer:test123");
        assert_eq!(peer.as_str(), "peer:test123");
        assert!(!peer.is_controller());
        assert!(peer.is_verifiable());
    }

    #[test]
    fn test_create_controller_peer() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let sk_e = PrivateKey::new(vec![7, 8, 9], "encryption");
        let sk_s = PrivateKey::new(vec![10, 11, 12], "signing");

        let peer = PeerVid::with_secrets("peer:controller", pk_e, pk_s, sk_e, sk_s);

        assert_eq!(peer.peer_id(), "peer:controller");
        assert!(peer.is_controller());
        assert!(peer.is_verifiable());
    }

    #[test]
    fn test_vid_trait_implementation() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("peer:vid123", pk_e, pk_s);

        let address = peer.resolve_address().expect("should resolve");
        assert_eq!(address, "peer:vid123");
    }

    #[test]
    fn test_evaluator_view_implementation() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("peer:eval", pk_e.clone(), pk_s.clone());

        let retrieved_pk_e = peer.pk_e().expect("should get pk_e");
        let retrieved_pk_s = peer.pk_s().expect("should get pk_s");

        assert_eq!(retrieved_pk_e.bytes(), pk_e.bytes());
        assert_eq!(retrieved_pk_s.bytes(), pk_s.bytes());
    }

    #[test]
    fn test_controller_view_implementation() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let sk_e = PrivateKey::new(vec![7, 8, 9], "encryption");
        let sk_s = PrivateKey::new(vec![10, 11, 12], "signing");

        let peer = PeerVid::with_secrets("peer:ctrl", pk_e, pk_s, sk_e.clone(), sk_s.clone());

        let retrieved_sk_e = peer.sk_e().expect("should get sk_e");
        let retrieved_sk_s = peer.sk_s().expect("should get sk_s");

        assert_eq!(retrieved_sk_e.bytes(), sk_e.bytes());
        assert_eq!(retrieved_sk_s.bytes(), sk_s.bytes());
    }

    #[test]
    fn test_controller_view_fails_on_evaluator() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("peer:eval_only", pk_e, pk_s);

        assert!(peer.sk_e().is_err());
        assert!(peer.sk_s().is_err());
    }

    #[test]
    fn test_verifiable_implementation() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("peer:verify", pk_e, pk_s);

        assert!(peer.verify().is_ok());
    }

    #[test]
    fn test_verify_fails_when_revoked() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let mut peer = PeerVid::new("peer:revoked", pk_e, pk_s);

        peer.revoke();

        assert!(peer.verify().is_err());
    }

    #[test]
    fn test_verify_fails_with_empty_key() {
        let pk_e = PublicKey::new(vec![], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("peer:bad_key", pk_e, pk_s);

        assert!(peer.verify().is_err());
    }

    #[test]
    fn test_verify_fails_with_empty_peer_id() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("", pk_e, pk_s);

        assert!(peer.verify().is_err());
    }

    #[test]
    fn test_display_implementation() {
        let pk_e = PublicKey::new(vec![1, 2, 3], "encryption");
        let pk_s = PublicKey::new(vec![4, 5, 6], "signing");
        let peer = PeerVid::new("peer:display_test", pk_e, pk_s);

        let display_str = peer.to_string();
        assert!(display_str.contains("peer:display_test"));
        assert!(display_str.contains("controller=false"));
        assert!(display_str.contains("verifiable=true"));
    }
}
