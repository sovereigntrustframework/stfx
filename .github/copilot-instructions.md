# STFx Copilot Instructions

## Project Overview

**STFx** is a modular, multi-language foundation for Self-Sovereign Identity (SSI) built on the Trust over IP (ToIP) Stack. The project focuses on abstraction, portability, and interoperability across different technology stacks and programming languages.

## Key Architecture Principles

- **Multi-Language Support**: Core patterns should be language-agnostic where possible; implementations exist in multiple languages
- **Modular Design**: Components should be loosely coupled with clear interfaces for cross-language communication
- **ToIP Stack Alignment**: Follow Trust over IP Layer abstractions (governance, utility, credential, and exchange layers)
- **Portability**: Code should minimize platform-specific dependencies; use abstraction layers for I/O operations

## Directory Structure (Expected)

As the project develops, expect:
- `docs/` - Architecture and specification documents
- `{language}/` - Language-specific implementations (e.g., `go/`, `ts/`, `python/`, `rust/`)
- `.github/workflows/` - CI/CD pipelines for multi-language testing
- `specs/` - Protocol and interface specifications

## Development Conventions

### Code Organization
- Each language implementation should have clear separation between:
  - **Core interfaces** - Language-neutral abstractions
  - **Implementations** - Concrete realizations of those interfaces
  - **Utils/helpers** - Common utilities

### Naming Patterns
- Use clear, descriptive names that reflect ToIP concepts (Issuer, Holder, Verifier, Credential, etc.)
- Prefix internal/private utilities with underscore or language-specific convention

### Cross-Language Communication
- Use JSON or Protocol Buffers for data serialization across language boundaries
- Document wire formats in `specs/` directory
- Include examples in multiple languages

## Development Workflow

1. **Before Implementation**: Check `docs/` or specs for architecture decisions
2. **Language-Specific**: Each language may have its own build/test tools (see lang-specific README)
3. **Testing**: Write tests alongside implementations; multiplatform test integration in CI/CD
4. **Documentation**: Update relevant docs when changing interfaces or adding features

## Key Files to Reference

- `README.md` - Project overview and getting started
- `LICENSE` - Apache 2.0: modifications and commercial use allowed with attribution

## When Contributing

- Respect the multi-language philosophy: discuss breaking changes across language teams
- Consider how interface changes impact interoperability
- Add examples in multiple languages for significant features
- Update specifications before implementing breaking changes

---

*Last updated: December 2025*
