# STFx Copilot Instructions

This doc equips AI coding agents to work productively in the STFx repo. Keep core logic in Rust crates; bindings are thin wrappers.

## Architecture
- Foundation crates (`crates/`):
    - `stfx-crypto`: cryptographic primitives.
    - `stfx-vid`: verifiable identifiers.
    - `stfx-keys`: key management/rotation.
- Protocol crates:
    - `stfx-layer2`, `stfx-layer3`: ToIP Layers 2–3 utilities and workflows.
    - `stfx-tsp`: Trust Spanning Protocol (cross-domain trust).
    - `stfx-cred-exchange`: issuance/verification workflows.
    - `stfx-cesr`: CESR codec support.
- Support:
    - `stfx-server`: reference HTTP server surface.
    - `stfx-test-utils`: shared test helpers.
- Bindings (`bindings/`): `stfx-wasm`, `stfx-python`, `stfx-kotlin`, `stfx-js` expose Rust APIs via FFI; avoid business logic here.
- Examples: `examples/tsp-hello-rust` shows minimal TSP usage; use as a pattern for examples.

## Build & Test
- Use `justfile` tasks (Rust 1.75+ per `rust-toolchain.toml`):
    - `just fmt` → format workspace.
    - `just clippy` → lint with `-D warnings`.
    - `just test` → `cargo test --workspace --all-features`.
    - `just check` → runs fmt, clippy, tests (preferred pre-commit).
- Workspace metadata and dependencies are coordinated in root `Cargo.toml`; add new crates to `members` and prefer workspace-level deps.

## Conventions & Patterns
- Rust-first: implement features in the appropriate `crates/stfx-*` crate, then expose via bindings if needed.
- Tests colocated: use `#[cfg(test)]` modules in each crate (`stfx-test-utils` for shared fixtures).
- Data formats: prefer JSON/CBOR for FFI/wire compatibility; CESR lives in `stfx-cesr`.
- Layering: higher-level crates depend on foundation crates; avoid reverse dependencies.
- Bindings: use PyO3 (Python), wasm-bindgen (WASM), JNI/FFI (Kotlin), and minimal TypeScript shims. Keep serialization stable across languages.
- Error handling: each crate defines its own error types (e.g., `CryptoError`, `VIDError`, `TSPError`) with domain-specific variants. This maintains maximum modularity and zero coupling between Layer 1 crates. Avoid shared error crates unless significant duplication emerges.

## Typical Workflows
- Add a feature:
    1) Implement in Rust crate (e.g., `stfx-tsp/src/lib.rs`).
    2) Add tests in the same crate.
    3) If cross-language needed, expose via binding crate (`bindings/stfx-*/src/lib.rs`).
    4) Add a runnable example under `examples/`.
    5) Run `just check` to validate.
- Example usage: see `examples/tsp-hello-rust/src/main.rs` for API patterns to mirror.

## Integration Points
- Server: `crates/stfx-server` exposes HTTP endpoints mapping to core APIs (keep auth and exposure logic here, not in core crates).
- CESR/codec: `crates/stfx-cesr` handles text encoding for cryptographic material.
- Credential exchange: `crates/stfx-cred-exchange` orchestrates issuance/verification using keys/VID.

## File References
- Root `Cargo.toml`: workspace members and shared deps.
- `justfile`: canonical dev commands.
- `README.md`: high-level overview and language availability.
- `rust-toolchain.toml`: toolchain and components.

## Notes for Agents
- Keep changes minimal and aligned with crate ownership boundaries.
- Do not place core logic in bindings; only expose Rust functions.
- When adding crates or bindings, update workspace members and run `just check`.
- Prefer adding examples over expanding binding-side tests.

Last updated: December 2025
