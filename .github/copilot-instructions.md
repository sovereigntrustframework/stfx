# STFx Copilot Instructions

## Project Overview

**STFx** is a high-performance, modular Rust implementation of the Trust over IP (ToIP) Stack and Trust Spanning Protocol (TSP), with multi-language bindings. It's the reference implementation for ToIP Layers 1–3 with cryptographic primitives, verifiable identifiers, key management, and credential exchange.

## Architecture at a Glance

### Core Rust Crates (`crates/`)

**Foundation Layer** (cryptographic and identity primitives):
- `stfx-crypto` - Core cryptographic operations
- `stfx-vid` - Verifiable Identifiers (DIDs/equivalent)
- `stfx-keys` - Key management and rotation

**Protocol Layers** (ToIP Stack implementation):
- `stfx-layer2` - Utility Layer (infrastructure/governance)
- `stfx-layer3` - Credential & Exchange Layer (SSI workflows)
- `stfx-tsp` - Trust Spanning Protocol (cross-domain trust)
- `stfx-cred-exchange` - Credential issuance/verification workflows
- `stfx-cesr` - CESR codec support (cryptographic text encoding)

**Support Crates**:
- `stfx-server` - Reference HTTP server (authentication/API exposure)
- `stfx-test-utils` - Shared testing utilities

### Multi-Language Bindings (`bindings/`)

- `stfx-wasm` - WebAssembly bindings (Node.js, browser)
- `stfx-python` - Python FFI via PyO3
- `stfx-kotlin` - JVM/Kotlin bindings via JNIOA
- `stfx-js` - TypeScript/JavaScript bindings

All bindings wrap Rust core implementations; keep logic in Rust, not in binding layers.

## Build & Test Workflow

Uses **justfile** for task automation (run `just check` before commit):

```powershell
just test        # cargo test --workspace --all-features
just clippy      # cargo clippy --workspace --all-features -- -D warnings
just fmt         # cargo fmt --all
just check       # runs fmt, clippy, test in sequence
just publish-all # publishes all crates to crates.io (requires tokens)
```

Rust version: **1.75+** (stable channel, see `rust-toolchain.toml`).

## Key Development Patterns

### Workspace Dependencies
All crates use workspace-level package metadata (`Cargo.toml`):
- Shared version, edition (2021), license (Apache-2.0)
- Define common dependencies once at workspace level to avoid duplication

### Inter-Crate Dependencies
Organize dependencies by layer:
- Foundation crates (`stfx-crypto`, `stfx-vid`, `stfx-keys`) have minimal dependencies
- Higher layers (`stfx-tsp`, `stfx-cred-exchange`) depend on foundation crates
- Bindings depend on their respective core crates
- Example projects in `examples/` demonstrate typical usage patterns

### Cross-Language Data Flow
When extending bindings:
1. Define core logic in Rust (e.g., `stfx-tsp/src/lib.rs`)
2. Expose via binding crate using appropriate FFI (PyO3 for Python, wasm-bindgen for WASM)
3. Ensure serialization compatibility (JSON or CBOR for wire formats)

### Testing Convention
Tests live in `#[cfg(test)]` modules alongside implementation:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_name() { /* ... */ }
}
```

Run workspace tests: `just test` (includes all crates and bindings).

## When Adding Features

1. **Identify Layer**: Does it belong in foundation (`crypto`, `vid`, `keys`), protocol (`layer2`, `layer3`, `tsp`), or application (`server`, `cred-exchange`)?
2. **Add to Appropriate Crate**: Place implementation in `crates/stfx-{feature}` if new, or extend existing crate
3. **Update Workspace**: Add new crate to members array in root `Cargo.toml`
4. **Binding Coverage**: Evaluate if bindings need exposure (add to `bindings/stfx-{lang}`)
5. **Example & Docs**: Add example in `examples/` demonstrating new capability

## Key Files to Reference

- `README.md` - Quick start, language availability, feature overview
- `Cargo.toml` - Workspace structure, dependency coordination
- `rust-toolchain.toml` - Rust version and components (rustfmt, clippy)
- `justfile` - Build/test automation
- `LICENSE` - Apache 2.0 (modifications and commercial use allowed)

## Architecture Decision: Rust-First

This is a **Rust-native project** with bindings, not a multi-language project. All core logic lives in Rust crates; bindings are thin wrappers. This ensures:
- Single source of truth for cryptographic correctness
- Performance guarantees (zero-cost abstractions in Rust)
- Easier maintenance and security updates
- Consistent behavior across language bindings

---

*Last updated: December 2025 (refined from actual codebase structure)*
