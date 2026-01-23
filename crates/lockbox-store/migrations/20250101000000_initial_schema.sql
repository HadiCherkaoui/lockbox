-- Initial schema for lockbox storage
-- Users table stores registered public keys
CREATE TABLE IF NOT EXISTS users (
    public_key BLOB PRIMARY KEY NOT NULL,  -- Ed25519 public key (32 bytes)
    label TEXT NOT NULL,                   -- Human-readable label for the key
    created_at INTEGER NOT NULL            -- Unix timestamp
);

-- Secrets table stores encrypted password entries
-- Note: The data is already encrypted client-side with AES-256-GCM
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL DEFAULT 'default',  -- Target K8s namespace
    name TEXT NOT NULL UNIQUE,                  -- Secret name/identifier
    data TEXT NOT NULL,                         -- JSON blob of encrypted key-value pairs
    created_at INTEGER NOT NULL,                -- Unix timestamp
    updated_at INTEGER NOT NULL,                -- Unix timestamp (version for delta sync)
    deleted_at INTEGER DEFAULT NULL             -- Unix timestamp when soft-deleted (tombstone)
);

-- Index for faster lookups by secret name
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
CREATE INDEX IF NOT EXISTS idx_secrets_updated_at ON secrets(updated_at);
CREATE INDEX IF NOT EXISTS idx_secrets_namespace ON secrets(namespace);

-- Challenges table stores authentication challenges
CREATE TABLE IF NOT EXISTS challenges (
    public_key BLOB PRIMARY KEY NOT NULL,  -- Raw public key bytes (32 bytes)
    challenge BLOB NOT NULL,               -- Raw challenge nonce (32 bytes)
    expires_at INTEGER NOT NULL            -- Unix timestamp when challenge expires
);

-- Index for challenge expiry cleanup
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);
