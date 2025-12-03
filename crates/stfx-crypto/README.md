# stfx-crypto

Core cryptographic primitives for the Sovereign Trust Framework (STFx).

This crate provides foundational crypto utilities used across STFx:
- Key generation and basic operations (planned)
- Hashing/signing abstractions (planned)
- Future integrations with DID/VID and TSP layers

Project home: https://stfx.dev
Repository: https://github.com/sovereigntrustframework/stfx

## Usage

```rust
use stfx_crypto::add;

fn main() {
    assert_eq!(add(2, 2), 4);
}
```

## License

Apache-2.0. See the workspace `LICENSE` for details.
