# stfx-crypto Public API

Layer 1 cryptographic primitives for the Sovereign Trust Framework (ToIP/TSP).

**Design**: Trait-based architecture for algorithm modularity and easy swapping in higher layers.

## Core Traits

```rust
/// Cryptographic signing
pub trait Signer {
    type Signature;
    type Error;
    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
}

/// Signature verification
pub trait Verifier {
    type Signature;
    type Error;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::Error>;
}

/// Hash functions (256-bit output)
pub trait Hasher {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// Key agreement (Diffie-Hellman)
pub trait KeyAgreement {
    type PublicKey;
    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32];
}

/// Authenticated encryption
pub trait Aead {
    type Error;
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), Self::Error>;
    fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), Self::Error>;
}
```

## ed25519

Ed25519 signing keypairs.

```rust
pub struct Ed25519Keypair { /* private fields */ }

impl Ed25519Keypair {
    pub fn generate() -> Self;
    pub fn public_key(&self) -> &VerifyingKey;
}

impl Signer for Ed25519Keypair {
    type Signature = Signature;
    type Error = SignatureError;
    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
}

impl Verifier for VerifyingKey {
    type Signature = Signature;
    type Error = SignatureError;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::Error>;
}
```

## hash

Cryptographic hash implementations.

```rust
pub struct Sha256Hasher;
pub struct Blake2b256Hasher;

impl Hasher for Sha256Hasher { /* ... */ }
impl Hasher for Blake2b256Hasher { /* ... */ }

// Convenience functions
pub fn sha256(data: &[u8]) -> [u8; 32];
pub fn blake2b256(data: &[u8]) -> [u8; 32];
```

## x25519

X25519 Diffie-Hellman key agreement.

```rust
pub struct X25519Keypair { /* private fields */ }

impl X25519Keypair {
    pub fn generate() -> Self;
    pub fn public_key(&self) -> &PublicKey;
}

impl KeyAgreement for X25519Keypair {
    type PublicKey = PublicKey;
    fn diffie_hellman(&self, their_public: &Self::PublicKey) -> [u8; 32];
}
```

## aead

ChaCha20-Poly1305 authenticated encryption.

```rust
pub struct ChaCha20Poly1305Cipher;

impl Aead for ChaCha20Poly1305Cipher {
    type Error = AeadError;
    fn encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), Self::Error>;
    fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), Self::Error>;
}

// Convenience functions
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), AeadError>;
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), AeadError>;
```

## rand

Cryptographically secure random number generation.

```rust
pub fn bytes(len: usize) -> Vec<u8>;
```

## encode

Base64url encoding (RFC 4648, no padding).

```rust
pub fn base64url_encode(data: &[u8]) -> String;
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError>;
```

---

## Usage Examples

### Direct (Convenience Functions)
```rust
use stfx_crypto::{ed25519, hash, x25519, aead, Signer, Verifier, KeyAgreement};

// Ed25519 signing
let kp = ed25519::Ed25519Keypair::generate();
let sig = kp.sign(b"message")?;
kp.public_key().verify(b"message", &sig)?;

// Hashing
let digest = hash::sha256(b"data");

// X25519 key agreement
let alice = x25519::X25519Keypair::generate();
let bob = x25519::X25519Keypair::generate();
let shared = alice.diffie_hellman(bob.public_key());

// AEAD
let mut data = b"plaintext".to_vec();
aead::encrypt(&key, &nonce, b"aad", &mut data)?;
aead::decrypt(&key, &nonce, b"aad", &mut data)?;
```

### Trait-based (Algorithm Agnostic)
```rust
use stfx_crypto::{Signer, Verifier, Hasher, KeyAgreement, Aead};
use stfx_crypto::{ed25519, hash, x25519, aead};

// Generic over signer
fn sign_message<S: Signer>(signer: &S, msg: &[u8]) -> Result<S::Signature, S::Error> {
    signer.sign(msg)
}

// Generic over hasher
fn hash_data<H: Hasher>(hasher: &H, data: &[u8]) -> [u8; 32] {
    hasher.hash(data)
}

// Use with concrete implementations
let kp = ed25519::Ed25519Keypair::generate();
let sig = sign_message(&kp, b"hello")?;

let sha = hash::Sha256Hasher;
let digest = hash_data(&sha, b"data");
```
