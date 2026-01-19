# Lockbox

[![Quality Gate Status](https://sonarqube.cherkaoui.ch/api/project_badges/measure?project=HadiCherkaoui_lockbox_2707f8bc-c376-4a15-b07c-09f191044f3f&metric=alert_status&token=sqb_c0d7fae7bdc947705724191a683333e0700031a3)](https://sonarqube.cherkaoui.ch/dashboard?id=HadiCherkaoui_lockbox_2707f8bc-c376-4a15-b07c-09f191044f3f)

Dev and automation-friendly Password manager with E2EE written in Rust

## Overview

Lockbox is a developer and automation-friendly password manager with end-to-end encryption (E2EE). It uses Ed25519 keypair-based authentication similar to SSH and WireGuard, eliminating the need for traditional passwords. The project is implemented in Rust, uses AGPLv3 license, and requires Rust 2024 edition.

## Features

- **End-to-End Encryption**: All passwords are encrypted with AES-256-GCM encryption
- **Keypair Authentication**: Uses Ed25519 keypairs for passwordless authentication (SSH/WireGuard-style)
- **Developer Friendly**: Designed for automation and scripting
- **Secure Memory Handling**: Automatic zeroization of sensitive key material
- **Cross-platform**: Built with Rust for maximum portability
- **CLI Interface**: Command-line client for easy automation
- **Kubernetes-ready**: Namespaced secrets, soft deletions (tombstones), and delta-sync API for controllers

## Architecture

The workspace follows a layered architecture with separate crates for different concerns:

**Core Library Crates** (`crates/`):
- `lockbox-crypto`: Cryptographic primitives (AES-256-GCM for password encryption, Ed25519 keypairs for authentication)
- `lockbox-proto`: Protocol definitions for client-server communication
- `lockbox-auth`: Keypair-based authentication logic, SSH/WireGuard-style
- `lockbox-store`: Encrypted storage backend for passwords and secrets

**Binary Crates**:
- `server/`: Server application for centralized password storage with E2EE
- `cli/`: Command-line client "lbx" for automation-friendly password management

## Cryptographic Implementation

The `lockbox-crypto` crate provides:
- **Symmetric encryption**: AES-256-GCM for encrypting stored passwords via `SymmetricKey` type with automatic key zeroization
- **Authentication keypairs**: Ed25519 keypair generation via `keys::generate_keypair()` for passwordless authentication
- **Encryption format**: `Ciphertext` struct containing 12-byte nonce and ciphertext body with integrated GCM tag

Dependencies:
- `aes-gcm` for symmetric encryption of stored passwords
- `ed25519-dalek` for SSH/WireGuard-style keypair authentication
- `zeroize` for secure memory clearing of sensitive material
- `rand` for cryptographically secure random number generation

## Installation

### Prerequisites
- Rust 2024 edition
- Cargo package manager

### Building from Source

```bash
# Clone the repository
git clone https://gitlab.cherkaoui.ch/HadiCherkaoui/lockbox.git
cd lockbox

# Build all workspace members
cargo build

# Build release version
cargo build --release
```

## Usage

### Running the Server
```bash
# Run the server application
cargo run -p server
```

### Using the CLI Client
```bash
# Run the command-line client
cargo run -p lbx
```

The `set` command accepts an optional namespace flag (defaults to `default`):

```bash
cargo run -p lbx -- set -n prod db-creds USERNAME=admin PASSWORD=s3cr3t
```

Secret names are unique per namespace and persisted server-side with server-controlled `created_at`, `updated_at`, and `deleted_at` timestamps (tombstones).

### API Documentation
For detailed API documentation, see [docs/api.md](docs/api.md). The API includes a `GET /secrets/sync?since=<timestamp>` endpoint for delta synchronization across namespaces.

## Development

### Building Specific Components
```bash
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

## Security

Lockbox implements security-first design principles:
- Zeroization of sensitive key material to prevent secrets from remaining in memory
- Keypair-based authentication eliminates password transmission over the network
- AES-256-GCM encryption for all stored passwords
- Ed25519 signatures for authentication

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Current Development State
Namespace-aware storage, tombstone deletions, and delta-sync APIs are implemented alongside the cryptographic primitives. Remaining work focuses on the Kubernetes controller integration.

## License

This project is licensed under the AGPLv3 License - see the LICENSE file for details.

## Project Status

Active development. The project is currently in early stages with core cryptographic functionality implemented and server/client applications under development.