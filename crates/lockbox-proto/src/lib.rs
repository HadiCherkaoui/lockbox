use ed25519_dalek::{Signature, VerifyingKey, ed25519::SignatureBytes};
use lockbox_crypto::cipher::Ciphertext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Secret {
    pub data: HashMap<String, Ciphertext>,
}

/// Request to set/create a secret
#[derive(Serialize, Deserialize, Debug)]
pub struct SetSecretRequest {
    pub name: String,
    pub secret: Secret,
}

/// Response after setting a secret
#[derive(Serialize, Deserialize, Debug)]
pub struct SetSecretResponse {
    pub success: bool,
}

/// Request to get a secret
#[derive(Serialize, Deserialize, Debug)]
pub struct GetSecretRequest {
    pub name: String,
}

/// Response with encrypted secret
#[derive(Serialize, Deserialize, Debug)]
pub struct GetSecretResponse {
    pub name: String,
    pub secret: Secret, // Encrypted - client will decrypt
}

/// Request to delete a secret
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteSecretRequest {
    pub name: String,
}

/// Response after deleting
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteSecretResponse {
    pub success: bool,
}

/// Request to list all secret names (no data returned)
#[derive(Serialize, Deserialize, Debug)]
pub struct ListSecretsRequest {}

/// Response with list of secret names
#[derive(Serialize, Deserialize, Debug)]
pub struct ListSecretsResponse {
    pub names: Vec<String>,
}

/// Register a new public key with the server
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterKeyRequest {
    pub public_key: VerifyingKey, // Ed25519 public key
    pub label: String,            // label like "my-laptop"
}

/// Response after registering
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterKeyResponse {
    pub success: bool,
    pub message: String,
}

/// Authenticate using Ed25519 signature
/// The server sends a challenge, client signs it with private key
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub public_key: VerifyingKey, // Your public key
    pub challenge: String,        // Server's challenge (nonce)
    pub signature: Signature,     // Signature of challenge with private key
}

/// Response with auth token or session
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<String>, // JWT or session token
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
}

/// Request for challenge nonce
#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeRequest {
    pub public_key: VerifyingKey, // Your public key
}

#[derive(serde::Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String, // Nonce to be signed
}
