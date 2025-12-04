// ===== Core Traits =====

/// Trait for cryptographic signing operations
pub trait Signer {
    type Signature;
    type Error;

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
}

/// Trait for signature verification
pub trait Verifier {
    type Signature;
    type Error;

    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::Error>;
}

/// Trait for cryptographic hash functions (256-bit output)
pub trait Hasher {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// Trait for key agreement (Diffie-Hellman)
pub trait KeyAgreement {
    type PublicKey;

    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32];
}

/// Trait for authenticated encryption
pub trait Aead {
    type Error;

    fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;

    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;
}

// ===== Ed25519 Implementation =====

pub mod ed25519 {
    use super::{Signer, Verifier};
    use ed25519_dalek::{SigningKey, VerifyingKey, Signature, SecretKey};
    use ed25519_dalek::{Signer as DalekSigner, Verifier as DalekVerifier, SignatureError};
    use rand::rngs::OsRng;
    use rand::RngCore;

    pub struct Ed25519Keypair {
        secret: SigningKey,
        pub public: VerifyingKey,
    }

    impl Ed25519Keypair {
        pub fn generate() -> Self {
            let mut sk_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut sk_bytes);
            let sk = SecretKey::from(sk_bytes);
            let secret = SigningKey::from_bytes(&sk);
            let public = secret.verifying_key();
            Self { secret, public }
        }

        pub fn public_key(&self) -> &VerifyingKey {
            &self.public
        }
    }

    impl Signer for Ed25519Keypair {
        type Signature = Signature;
        type Error = SignatureError;

        fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
            Ok(self.secret.sign(msg))
        }
    }

    impl Verifier for VerifyingKey {
        type Signature = Signature;
        type Error = SignatureError;

        fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::Error> {
            DalekVerifier::verify(self, msg, signature)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{Signer, Verifier};

        #[test]
        fn sign_verify() {
            let kp = Ed25519Keypair::generate();
            let msg = b"hello world";
            let sig = Signer::sign(&kp, msg).unwrap();
            Verifier::verify(&kp.public, msg, &sig).unwrap();
        }
    }
}

// ===== Hash Implementations =====

pub mod hash {
    use super::Hasher;
    use sha2::{Digest, Sha256};
    use blake2::{Blake2b, digest::consts::U32};

    pub struct Sha256Hasher;
    pub struct Blake2b256Hasher;

    impl Hasher for Sha256Hasher {
        fn hash(&self, data: &[u8]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().into()
        }
    }

    impl Hasher for Blake2b256Hasher {
        fn hash(&self, data: &[u8]) -> [u8; 32] {
            let mut hasher = Blake2b::<U32>::new();
            hasher.update(data);
            hasher.finalize().into()
        }
    }

    // Convenience functions for direct use
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256Hasher.hash(data)
    }

    pub fn blake2b256(data: &[u8]) -> [u8; 32] {
        Blake2b256Hasher.hash(data)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sha256_len() {
            assert_eq!(sha256(b"abc").len(), 32);
        }

        #[test]
        fn blake2b256_len() {
            assert_eq!(blake2b256(b"abc").len(), 32);
        }
    }
}

// ===== X25519 Implementation =====

pub mod x25519 {
    use super::KeyAgreement;
    use x25519_dalek::{StaticSecret, PublicKey};
    use rand::rngs::OsRng;

    pub struct X25519Keypair {
        secret: StaticSecret,
        pub public: PublicKey,
    }

    impl X25519Keypair {
        pub fn generate() -> Self {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            Self { secret, public }
        }

        pub fn public_key(&self) -> &PublicKey {
            &self.public
        }
    }

    impl KeyAgreement for X25519Keypair {
        type PublicKey = PublicKey;

        fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32] {
            self.secret.diffie_hellman(their_public).to_bytes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn shared_secret() {
            let alice = X25519Keypair::generate();
            let bob = X25519Keypair::generate();
            let shared_a = alice.diffie_hellman(&bob.public);
            let shared_b = bob.diffie_hellman(&alice.public);
            assert_eq!(shared_a, shared_b);
        }
    }
}

// ===== AEAD Implementation =====

pub mod aead {
    use super::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
    use chacha20poly1305::aead::Error as AeadError;

    pub struct ChaCha20Poly1305Cipher;

    impl Aead for ChaCha20Poly1305Cipher {
        type Error = AeadError;

        fn encrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            aad: &[u8],
            plaintext: &mut Vec<u8>,
        ) -> Result<(), Self::Error> {
            let cipher = ChaCha20Poly1305::new(key.into());
            let nonce = Nonce::from_slice(nonce);
            cipher.encrypt_in_place(nonce, aad, plaintext)?;
            Ok(())
        }

        fn decrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            aad: &[u8],
            ciphertext: &mut Vec<u8>,
        ) -> Result<(), Self::Error> {
            let cipher = ChaCha20Poly1305::new(key.into());
            let nonce = Nonce::from_slice(nonce);
            cipher.decrypt_in_place(nonce, aad, ciphertext)?;
            Ok(())
        }
    }

    // Convenience functions for direct use
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        ChaCha20Poly1305Cipher.encrypt(key, nonce, aad, plaintext)
    }

    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        ChaCha20Poly1305Cipher.decrypt(key, nonce, aad, ciphertext)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encrypt_decrypt() {
            let key = [1u8; 32];
            let nonce = [2u8; 12];
            let aad = b"additional data";
            let mut data = b"plaintext message".to_vec();
            let original = data.clone();
            encrypt(&key, &nonce, aad, &mut data).unwrap();
            assert_ne!(data, original);
            decrypt(&key, &nonce, aad, &mut data).unwrap();
            assert_eq!(data, original);
        }
    }
}

// ===== Utilities =====

pub mod rand {
    use rand::rngs::OsRng;
    use rand::RngCore;

    pub fn bytes(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}

pub mod encode {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    pub fn base64url_encode(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip() {
            let data = b"stfx";
            let enc = base64url_encode(data);
            let dec = base64url_decode(&enc).unwrap();
            assert_eq!(dec, data);
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_integration() {
        let kp = ed25519::Ed25519Keypair::generate();
        let msg = b"hello TSP";
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(&kp.public, msg, &sig).unwrap();
    }

    #[test]
    fn trait_based_signing() {
        let kp = ed25519::Ed25519Keypair::generate();
        let msg = b"test message";
        
        // Use through trait
        let sig = Signer::sign(&kp, msg).unwrap();
        Verifier::verify(&kp.public, msg, &sig).unwrap();
    }

    #[test]
    fn trait_based_hashing() {
        let sha = hash::Sha256Hasher;
        let blake = hash::Blake2b256Hasher;
        
        let data = b"test data";
        assert_eq!(Hasher::hash(&sha, data).len(), 32);
        assert_eq!(Hasher::hash(&blake, data).len(), 32);
    }

    #[test]
    fn trait_based_key_agreement() {
        let alice = x25519::X25519Keypair::generate();
        let bob = x25519::X25519Keypair::generate();
        
        let shared_a = KeyAgreement::diffie_hellman(&alice, &bob.public);
        let shared_b = KeyAgreement::diffie_hellman(&bob, &alice.public);
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn trait_based_aead() {
        let cipher = aead::ChaCha20Poly1305Cipher;
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = b"metadata";
        
        let mut data = b"secret".to_vec();
        let original = data.clone();
        
        Aead::encrypt(&cipher, &key, &nonce, aad, &mut data).unwrap();
        assert_ne!(data, original);
        
        Aead::decrypt(&cipher, &key, &nonce, aad, &mut data).unwrap();
        assert_eq!(data, original);
    }
}
