test:
    cargo test --workspace --all-features

clippy:
    cargo clippy --workspace --all-features -- -D warnings

fmt:
    cargo fmt --all

check: fmt clippy test

publish-all:   # run only after you set up tokens
    cargo publish --allow-dirty -p stfx-crypto || true
    # add others later
