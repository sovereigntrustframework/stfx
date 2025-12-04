# stfx-crypto

**Layer 1 Cryptographic Primitives** for the Sovereign Trust Framework (STFx) — ToIP compatible, modular, and extensible.

## Features

- **Ed25519** signing and verification
- **X25519** Diffie-Hellman key agreement
- **SHA-256** and **BLAKE2b-256** hashing
- **ChaCha20Poly1305** AEAD encryption
- **Trait-based abstractions** for algorithm-agnostic code
- **Zero coupling** between Layer 1 modules

Project home: https://stfx.dev  
Repository: https://github.com/sovereigntrustframework/stfx

## Architecture

```
stfx-crypto/
├── src/
│   ├── lib.rs              # Public API & re-exports
│   ├── error.rs            # CryptoError (domain-specific)
│   ├── traits/             # Modular trait definitions
│   │   ├── mod.rs
│   │   ├── key_manager.rs  # KeyManager trait
│   │   ├── key_pair.rs     # KeyPair trait
│   │   ├── signer.rs       # Signer trait
│   │   ├── verifier.rs     # Verifier trait
│   │   ├── hasher.rs       # Hasher trait
│   │   ├── digest.rs       # Digest trait
│   │   ├── randomness.rs   # Randomness trait
│   │   ├── multibase.rs    # MultibaseEncoder trait
│   │   ├── multicodec.rs   # MulticodecEncoder trait
│   │   └── compat.rs       # Legacy KeyAgreement & Aead
│   ├── keys/
│   │   ├── mod.rs
│   │   ├── ed25519_impl.rs # Ed25519 signing
│   │   └── x25519_impl.rs  # X25519 key agreement
│   ├── hash/
│   │   └── mod.rs          # SHA-256, BLAKE2b-256
│   ├── encoding/
│   │   └── mod.rs          # Base64url encoding
│   ├── aead_impl.rs        # ChaCha20Poly1305 AEAD
│   └── random.rs           # Secure randomness
├── benches/
│   └── crypto_benchmarks.rs
└── tests/
    └── (colocated in modules)
```

## Usage

### Ed25519 Signing

```rust
use stfx_crypto::{
    ed25519::Ed25519Keypair,
    Signer, Verifier,
};

let keypair = Ed25519Keypair::generate();
let message = b"Hello, STFx!";

// Sign
let signature = keypair.sign(message).unwrap();

// Verify
keypair.public_key().verify(message, &signature).unwrap();
```

### X25519 Key Agreement

```rust
use stfx_crypto::{
    x25519::X25519Keypair,
    KeyAgreement,
};

let alice = X25519Keypair::generate();
let bob = X25519Keypair::generate();

let shared_secret = alice.diffie_hellman(bob.public_key());
```

### Hashing

```rust
use stfx_crypto::hash::{sha256, blake2b256};

let data = b"data to hash";
let sha_digest = sha256(data);      // [u8; 32]
let blake_digest = blake2b256(data); // [u8; 32]
```

### AEAD Encryption

```rust
use stfx_crypto::{
    aead::ChaCha20Poly1305Cipher,
    Aead,
};

let cipher = ChaCha20Poly1305Cipher;
let key = [0u8; 32];
let nonce = [0u8; 12];
let aad = b"metadata";

let mut data = b"secret message".to_vec();
cipher.encrypt(&key, &nonce, aad, &mut data).unwrap();
cipher.decrypt(&key, &nonce, aad, &mut data).unwrap();
```

## Benchmarks

Run performance benchmarks with [Criterion](https://github.com/bheisler/criterion.rs):

```bash
cargo bench --package stfx-crypto
```

Typical results (approximate):
- Ed25519 sign: ~35 µs
- Ed25519 verify: ~83 µs
- X25519 DH: ~72 µs
- BLAKE2b-256 (4KB): ~593 MiB/s
- ChaCha20Poly1305 (4KB): ~575 MiB/s

## Trait System

All primitives implement algorithm-agnostic traits for maximum composability:

- **`Signer`** / **`Verifier`** — signature operations
- **`Hasher`** — deterministic hashing
- **`KeyAgreement`** — Diffie-Hellman
- **`Aead`** — authenticated encryption
- **`KeyManager`** / **`KeyPair`** — key lifecycle (extensible)

## Future Extensions

- Additional curves: `secp256k1`, `BLS12-381`
- Post-quantum: `Dilithium`, `Kyber`
- Advanced hashing: `BLAKE3`
- Multibase/Multicodec implementations

## License

Apache-2.0. See the workspace `LICENSE` for details.
