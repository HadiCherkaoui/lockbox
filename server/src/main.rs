use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode, header::HeaderName},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose;
use lockbox_proto::*;
use lockbox_store::keys::KeyStore;
use once_cell::sync::Lazy;
use rand::RngCore;
use serde_json::json;
use std::env;
use tokio::net::TcpListener;

static API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");
static API_KEY: Lazy<String> = Lazy::new(|| {
    let key = env::var("API_KEY").expect("API_KEY environment variable must be set");
    if key.trim().is_empty() {
        panic!("API_KEY cannot be empty");
    }
    key
});

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/challenge", post(challenge))
        .route("/auth/verify", post(verify))
        .route("/api/health", get(health));

    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Starting server on port 8080");
    axum::serve(listener, app).await.unwrap();
}

async fn register(
    headers: HeaderMap,
    Json(payload): Json<RegisterKeyRequest>,
) -> impl IntoResponse {
    let api_key = headers
        .get(&API_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if api_key != *API_KEY {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Invalid API key"
            }))
            .into_response(),
        );
    }
    if payload.public_key.as_bytes().is_empty() || payload.label.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Label and public key are required"
            }))
            .into_response(),
        );
    }
    let mut keystore = KeyStore::new();
    if let Err(e) = keystore.register_key(payload.public_key, &payload.label) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Keystore error: {}", e)
            }))
            .into_response(),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Key registered successfully"
        }))
        .into_response(),
    )
}

async fn challenge(Json(payload): Json<ChallengeRequest>) -> impl IntoResponse {
    if payload.public_key.as_bytes().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Public key is required"
            })),
        )
            .into_response();
    }
    let mut keystore = KeyStore::new();
    if let Err(e) = keystore.load("keystore.json") {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to load keystore: {}", e)
            })),
        )
            .into_response();
    }
    if !keystore.key_allowed(&payload.public_key) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Public key not registered"
            })),
        )
            .into_response();
    }
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);

    // Base64 encode for safe transmission
    let challenge = general_purpose::STANDARD.encode(&nonce);

    (StatusCode::OK, Json(ChallengeResponse { challenge })).into_response()
}

async fn verify(Json(payload): Json<AuthRequest>) -> impl IntoResponse {
    let challenge = general_purpose::STANDARD.decode(payload.challenge);
    if challenge.is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid challenge encoding"
            })),
        )
            .into_response();
    }
    let challenge = challenge.unwrap();
    if challenge.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid challenge length"
            })),
        )
            .into_response();
    }
    if let Err(e) = payload
        .public_key
        .verify_strict(&challenge, &payload.signature)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": format!("Signature verification failed: {}", e)
            })),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Verification endpoint not yet implemented"
        })),
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "healthy"}))
}
