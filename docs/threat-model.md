# Threat Model

_Last updated: 2026-01-23_

Lockbox is an end-to-end encrypted (E2EE) password manager built in Rust. It is a personal side project originally created to learn Rust and is currently used in my homelab Kubernetes cluster (gitlab.cherkaoui.ch/hadicherkoaui/homelab-k8s-fluxcd), so it should not be considered production-ready. The system consists of:

- **CLI (`cli/`)**: Generates and stores an Ed25519 keypair, encrypts secret payloads client-side using AES-256-GCM, and talks to the server via REST helpers.
- **Server (`server/src/main.rs`)**: Provides key registration and challenge/response authentication, issues HS256 JWTs, and enforces namespace scoping, rate limits, and tombstones.
- **Storage (`crates/lockbox-store`)**: Persists ciphertext blobs, metadata, and authentication challenges in SQLite via `sqlx` migrations.
- **Crypto (`crates/lockbox-crypto`)**: Defines the AES-GCM cipher wrapper (`SymmetricKey`, `Ciphertext`) and Ed25519 key utilities.

This document captures the current threat model with a deeper analysis tied to the codebase to guide reviews, implementation, and operational posture.

## System Context & Data Flows

1. **Key registration**: `cli::handle_init` (`cli/src/commands.rs`) generates a signing key, stores it locally, then calls `/auth/register` with an API key and the public key. The server stores the public key + label in `users` (`migrations/20250101000000_initial_schema.sql`).
2. **Authentication**: A client calls `/auth/challenge`, receives a 32-byte nonce from `lockbox-store::Database::store_challenge`, signs it with its private key, and submits to `/auth/verify`. On success the server issues a short-lived HS256 JWT using `JWT_SECRET`.
3. **Secret write**: The CLI derives a 32-byte AES key directly from the Ed25519 signing key (`SymmetricKey::from_ed25519`) and encrypts each field before calling `/secrets`. The server stores ciphertext, the associated Kubernetes namespace, and timestamps.
4. **Secret read**: The server returns ciphertext blobs; the client decrypts locally. Metadata (Kubernetes namespaces, tombstones, timestamps) remain in the clear.
5. **Delta sync**: `/secrets/sync?since=<ts>` streams secrets whose `updated_at` exceeds the provided timestamp, enabling controllers to reconcile state per Kubernetes namespace.

### Kubernetes Namespace Model

Namespaces in Lockbox align with Kubernetes namespaces: every stored secret is scoped to a Kubernetes namespace string (defaulting to `default`) so that controllers can mirror Lockbox state into cluster namespaces. Today, namespace names are stored as plaintext metadata in the `secrets` table and enforced at the application layer.

All flows require an authenticated HTTPS (or better) channel; otherwise replay and manipulation remain possible.

## Security Goals

1. Protect secret payloads even if the server, database, or storage medium is compromised.
2. Prevent unauthorized actors from issuing API mutations outside their namespace.
3. Provide integrity for sync/update operations despite untrusted networks.
4. Maintain availability against malformed or malicious client traffic.
5. Enable operators to reason about leakage (metadata, timing) and residual risk.

## Assumptions & Non-Goals

- Client devices manage their own hardening (disk encryption, malware protection, secure input). Lockbox does not enforce attestation or remote wipe.
- Users are responsible for backing up and protecting Ed25519 private keys. There is no recovery flow if the key and backups are lost or stolen.
- Transport security (TLS, WireGuard, mTLS) is assumed, but Lockbox does not ship certificate pinning today.
- Hardware-backed key storage, multi-party authorization, server-side HSMs, and audit logging beyond stdout are out of scope for the current release.
- The system trusts its dependency graph (`Cargo.lock`) and supply chain unless otherwise noted.

## Assets to Protect

| Asset | Where it lives | Security Properties |
| --- | --- | --- |
| Client Ed25519 signing key | `~/.lockbox/keypair.bin` | Confidentiality, integrity |
| Derived AES key / plaintext secrets | Client memory during CLI ops | Confidentiality, zeroization |
| Stored ciphertext | `secrets.data` table | Integrity, authenticity |
| Namespace metadata + tombstones | `secrets.namespace`, `deleted_at` (Kubernetes namespace identifiers) | Integrity, limited confidentiality |
| Challenge nonces | `challenges` table | Integrity, anti-reuse |
| API key, `JWT_SECRET`, database URL | Server env | Confidentiality |
| Build artifacts (CLI/server) | Release tarballs, containers | Integrity, authenticity |
| CI credentials & signing keys | GitLab pipelines | Confidentiality |

## Trust Boundaries

1. **Client ↔ Server API**: Authenticated over HTTPS; attacker may observe or tamper with traffic absent TLS.
2. **Server ↔ Database**: SQLite backend; compromise exposes ciphertext + metadata but not plaintext.
3. **Server runtime vs. operator**: Environment variables (`API_KEY`, `JWT_SECRET`) must be protected by ops.
4. **Automation controllers**: Namespace-specific automation uses the same API surface; compromise yields bulk operations.
5. **Build / CI boundary**: Source, dependencies, and CI configuration must resist tampering to avoid supply-chain attacks.

## Adversaries & Capabilities

- **Network attacker**: Can intercept, delay, or replay requests if TLS is misconfigured.
- **Malicious tenant**: Authenticated client in a separate namespace attempting privilege escalation or resource exhaustion.
- **Compromised operator/database**: Gains storage snapshots or shell access but not client private keys.
- **Endpoint malware**: Steals user key material or tampers with CLI operations.
- **Insider developer / build attacker**: Injects malicious dependency, modifies CI secrets, or tampers with releases.
- **Supply-chain adversary**: Targets crates.io dependencies or Git submodules to introduce backdoors.

## Threat Analysis (STRIDE)

### Spoofing

- **Key registration abuse**: Anyone with `API_KEY` can register arbitrary public keys, potentially exhausting storage or enabling rogue devices. Mitigations: strong API key management, audit logs, optional approval workflow.
- **Challenge replay**: Nonces are 32 random bytes stored server-side; if an attacker replays a previously signed challenge before expiry they may get a JWT. Mitigation: `consume_challenge` deletes the challenge after use and enforces expirations (`CHALLENGE_EXPIRY_SECS = 300`). Residual risk: short JWT validity (60s) limits window but clients must refresh often.
- **JWT forgery**: HS256 tokens rely on `JWT_SECRET`. Compromise of the secret or weak entropy would enable spoofing. Mitigation: load from env, require non-empty value; consider rotation and stronger algorithms (EdDSA) in future.

### Tampering

- **Ciphertext modification**: Attacker altering `secrets.data` causes decrypt failures thanks to AES-GCM tags validated client-side. No rollback protection exists; metadata could be rewound. Consider version numbers or signatures per entry.
- **Namespace drift**: `set_secret` overwrites namespace on conflict. Without server-side authorization checks per namespace, a compromised client could move secrets. Ensure middleware attaches namespace claims and enforces them (work to verify tests cover this).
- **Sync poisoning**: MITM could reorder or strip responses. Mitigation: rely on TLS; consider signing sync payloads with server-held Ed25519 key to provide integrity when TLS terminates elsewhere.

### Repudiation

- Server does not persist structured audit logs; only stdout statements. Malicious actors can deny having performed actions. Mitigation: add authenticated logging (e.g., tamper-evident append-only log) tied to public keys.

### Information Disclosure

- **Metadata leakage**: Namespace names, secret identifiers, and timestamps are plaintext in the DB and API responses. Attackers with DB access learn namespace topology and update cadence. Mitigation: document leakage, provide namespace ACLs, and consider deterministic naming or padding.
- **Key derivation weakness**: AES keys are raw Ed25519 private bytes (no KDF). Compromise of the signing key instantly reveals symmetric key; no key separation exists. Mitigation: derive AES keys via HKDF with domain separation and random salt.
- **Logging secrets**: CLI prints decrypted secrets to stdout (`handle_get`), so terminal history or process inspection can leak. Document this risk and encourage piping to secure destinations.

### Denial of Service

- **Authentication storms**: Challenge storage and cleanup loops could be overwhelmed. Implement rate limiting per IP / public key and bounded challenge table size.
- **Secret namespace abuse**: Names are unique globally (not namespace + name), so malicious tenant can squat names and force other namespaces to rename. Consider composite unique index over (namespace, name).
- **Sync amplification**: Attacker could request large `since` ranges repeatedly. Mitigation: enforce pagination limits (`limit` parameter) and monitor per-client quotas.

### Elevation of Privilege

- **Namespace isolation**: Authorization middleware (`auth_middleware`) only validates JWT signature; it does not yet attach namespace claims. All secrets appear globally addressable by name, making cross-namespace privilege escalation possible. Mitigation: embed namespace claims in JWTs and enforce them server-side.
- **Automation tokens**: Controllers reuse standard client flow; compromise of controller host equates to full namespace control. Use dedicated scoped keys and rotate them frequently.

## Residual Risks & Open Issues

1. **No transport binding**: Authentication relies on TLS termination. If TLS terminates outside trusted infrastructure (e.g., ingress), an internal attacker could replay requests. Consider channel binding or signing request bodies.
2. **Key derivation**: Lack of HKDF or salt means deterministic AES keys per device. Introduce `SymmetricKey::from_ed25519_with_salt` using HKDF-SHA256 and stored salt to allow rotation without regenerating signing keys.
3. **Unique secret names**: Because `name` is globally unique in the DB, namespaces are effectively advisory. Schema change needed for composite PK.
4. **No end-to-end integrity for metadata**: Clients trust server-provided timestamps and tombstones. A compromised server can reorder or inject items. Consider Merkle proofs or server-signed manifests for high-assurance environments.
5. **Operational logging**: Lack of tamper-resistant audit logs hinders incident response.

---

For updates, open a documentation issue referencing this file and the impacted components.
