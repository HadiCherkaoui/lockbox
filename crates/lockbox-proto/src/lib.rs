use ed25519_dalek::{Signature, VerifyingKey};
use lockbox_store::secrets::Secret;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SetSecretRequest {
    pub name: String,
    pub secret: Secret,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetSecretResponse {
    pub success: bool,
}

#[derive(Serialize, Deserialize)]
pub struct GetSecretResponse {
    pub secret: Secret,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteSecretResponse {
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListSecretsResponse {
    pub names: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterKeyRequest {
    pub public_key: VerifyingKey,
    pub label: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterKeyResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub public_key: VerifyingKey,
    pub challenge: String,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub success: bool,
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeRequest {
    pub public_key: VerifyingKey,
}

#[derive(serde::Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub pub_key: VerifyingKey,
    pub exp: usize,
}
