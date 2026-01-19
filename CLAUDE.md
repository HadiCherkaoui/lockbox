# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Lockbox is a developer and automation-friendly password manager with end-to-end encryption (E2EE). It uses Ed25519 keypair-based authentication similar to SSH and WireGuard, eliminating the need for traditional passwords. The project is implemented in Rust, uses AGPLv3 license, and requires Rust 2024 edition.

## Workspace Architecture

The workspace follows a layered architecture with separate crates for different concerns:

**Core Library Crates** (`crates/`):
- `lockbox-crypto`: Cryptographic primitives (AES-256-GCM for password encryption, Ed25519 keypairs for authentication)
- `lockbox-proto`: Protocol definitions for client-server communication (currently placeholder)
- `lockbox-auth`: Keypair-based authentication logic, SSH/WireGuard-style (currently placeholder)
- `lockbox-store`: Encrypted storage backend for passwords and secrets (currently placeholder)

**Binary Crates**:
- `server/`: Server application for centralized password storage with E2EE
- `cli/`: Command-line client "lbx" for automation-friendly password management

### Cryptographic Implementation Details

The `lockbox-crypto` crate provides:
- **Symmetric encryption**: AES-256-GCM for encrypting stored passwords via `SymmetricKey` type with automatic key zeroization
- **Authentication keypairs**: Ed25519 keypair generation via `keys::generate_keypair()` for passwordless authentication
- **Encryption format**: `Ciphertext` struct containing 12-byte nonce and ciphertext body with integrated GCM tag

Dependencies:
- `aes-gcm` for symmetric encryption of stored passwords
- `ed25519-dalek` for SSH/WireGuard-style keypair authentication
- `zeroize` for secure memory clearing of sensitive material
- `rand` for cryptographically secure random number generation

**Note**: The `cipher::encrypt` function at src/cipher.rs:27-38 has a bug where it returns an error after successfully creating ciphertext. This needs fixing.

## Development Commands

### Building
```bash
# Build all workspace members
cargo build

# Build specific crate
cargo build -p lockbox-crypto
cargo build -p server
cargo build -p lbx

# Release build
cargo build --release
```

### Testing
```bash
# Run all tests in workspace
cargo test

# Run tests for specific crate
cargo test -p lockbox-crypto
cargo test -p lockbox-auth

# Run specific test
cargo test --lib it_works
```

### Running
```bash
# Run server
cargo run -p server

# Run CLI
cargo run -p lbx
```

### Code Quality
```bash
# Check without building
cargo check

# Run clippy linter
cargo clippy

# Format code
cargo fmt

# Check formatting
cargo fmt --check
```

## Key Implementation Notes

1. **Edition 2024**: All crates use Rust 2024 edition. Ensure new syntax and features are edition-compatible.

2. **Security-First Design**: The crypto crate uses `Zeroizing` wrapper for sensitive key material to prevent secrets from remaining in memory. Keypair-based authentication eliminates password transmission over the network.

3. **Workspace Dependencies**: Server and CLI binaries depend on all four core library crates. Changes to library APIs will affect both binaries.

4. **Current Development State**: Namespace-aware secret storage, tombstone deletions (via `deleted_at`), and delta sync APIs (`GET /secrets/sync?since=`) are implemented alongside the core cryptography. Controllers rely on server-controlled timestamps and namespaces for reconciliation.

5. **No Public Publishing**: All workspace crates have `publish = false` in their Cargo.toml.
