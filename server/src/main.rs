use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use base64::{Engine, engine::general_purpose};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lockbox_proto::*;
use lockbox_store::secrets::Secret;
use lockbox_store::{keys::KeyStore, secrets::SecretStore};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

static API_KEY: Lazy<String> = Lazy::new(|| {
    let key = env::var("API_KEY").expect("API_KEY environment variable must be set");
    if key.trim().is_empty() {
        panic!("API_KEY cannot be empty");
    }
    key
});

static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    let key = env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set");
    if key.trim().is_empty() {
        panic!("JWT_SECRET cannot be empty");
    }
    key
});

const CHALLENGE_EXPIRY_SECS: u64 = 300;
const JWT_EXPIRY_SECS: usize = 60;
const CHALLENGE_CLEANUP_INTERVAL_SECS: u64 = 60;
const MAX_SECRET_NAME_LENGTH: usize = 256;

#[derive(Clone)]
struct AppState {
    keystore: Arc<RwLock<KeyStore>>,
    challenges: Arc<RwLock<HashMap<String, (String, SystemTime)>>>,
    secret_store: Arc<RwLock<SecretStore>>,
}

#[tokio::main]
async fn main() {
    let mut keystore = KeyStore::new();
    if let Err(e) = keystore.load("keystore.json") {
        println!("No existing keystore found, creating new one: {}", e);
    } else {
        println!("Loaded existing keystore");
    }
    let mut secret_store = SecretStore::new();
    if let Err(e) = secret_store.load("secrets.json") {
        println!("No existing secret store found, creating new one: {}", e);
    } else {
        println!("Loaded existing secret store");
    }

    let state = AppState {
        keystore: Arc::new(RwLock::new(keystore)),
        challenges: Arc::new(RwLock::new(HashMap::new())),
        secret_store: Arc::new(RwLock::new(secret_store)),
    };

    let _ = &*API_KEY;
    let _ = &*JWT_SECRET;

    // Spawn background task to clean up expired challenges (prevents memory leak)
    let challenges_cleanup = state.challenges.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(CHALLENGE_CLEANUP_INTERVAL_SECS)).await;
            if let Ok(mut challenges) = challenges_cleanup.write() {
                let now = SystemTime::now();
                let before = challenges.len();
                challenges.retain(|_, (_, expiry)| *expiry > now);
                let removed = before - challenges.len();
                if removed > 0 {
                    println!("Cleaned up {} expired challenges", removed);
                }
            }
        }
    });

    let public_routes = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/challenge", post(challenge))
        .route("/auth/verify", post(verify))
        .route("/health", get(health));

    let protected_routes = Router::new()
        .route("/secrets", post(set_secret))
        .route("/secrets/{name}", get(get_secret))
        .route("/secrets/{name}", delete(delete_secret))
        .route("/secrets/{name}", patch(update_secret))
        .route("/secrets", get(list_secrets))
        .layer(middleware::from_fn(auth_middleware));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Starting server on port 8080");
    axum::serve(listener, app).await.unwrap();
}

async fn auth_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let _token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &validation,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(next.run(req).await)
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterKeyRequest>,
) -> impl IntoResponse {
    // Verify API key
    let Some(api_key) = headers.get("X-API-KEY").and_then(|v| v.to_str().ok()) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Missing API key"})),
        )
            .into_response();
    };

    if api_key != *API_KEY {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid API key"})),
        )
            .into_response();
    }

    if payload.label.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Label cannot be empty"})),
        )
            .into_response();
    }

    let Ok(mut keystore) = state.keystore.write() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire keystore lock"})),
        )
            .into_response();
    };

    if let Err(e) = keystore.register_key(payload.public_key, &payload.label) {
        eprintln!("Failed to register key: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Failed to register key"})),
        )
            .into_response();
    }

    // Persist to disk
    if let Err(e) = keystore.save("keystore.json") {
        eprintln!("Failed to save keystore: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to save keystore"})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(json!({"message": "Key registered successfully"})),
    )
        .into_response()
}

async fn challenge(
    State(state): State<AppState>,
    Json(payload): Json<ChallengeRequest>,
) -> impl IntoResponse {
    // Check if public key is registered
       let Ok(keystore) = state.keystore.read() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire keystore lock"})),
        )
            .into_response();
    };

    if !keystore.key_allowed(&payload.public_key) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Public key not registered"})),
        )
            .into_response();
    }
    drop(keystore); // Release read lock

    // Generate random challenge
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let challenge_b64 = general_purpose::STANDARD.encode(&nonce);

    // Store challenge with expiry
    let expiry = SystemTime::now() + Duration::from_secs(CHALLENGE_EXPIRY_SECS);
    let pub_key_b64 = general_purpose::STANDARD.encode(payload.public_key.as_bytes());

    let Ok(mut challenges) = state.challenges.write() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire challenges lock"})),
        )
            .into_response();
    };
    challenges.insert(pub_key_b64, (challenge_b64.clone(), expiry));

    (
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge: challenge_b64,
        }),
    )
        .into_response()
}

async fn verify(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    let pub_key_b64 = general_purpose::STANDARD.encode(payload.public_key.as_bytes());

    let Ok(mut challenges) = state.challenges.write() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire challenges lock"})),
        )
            .into_response();
    };

    let Some((stored_challenge, expiry)) = challenges.remove(&pub_key_b64) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "No challenge found for this key"})),
        )
            .into_response();
    };

    if SystemTime::now() > expiry {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Challenge expired"})),
        )
            .into_response();
    }
    drop(challenges);

    if payload.challenge != stored_challenge {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Challenge mismatch"})),
        )
            .into_response();
    }

    let Ok(challenge_bytes) = general_purpose::STANDARD.decode(&payload.challenge) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid challenge encoding"})),
        )
            .into_response();
    };

    if let Err(e) = payload
        .public_key
        .verify_strict(&challenge_bytes, &payload.signature)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": format!("Signature verification failed: {}", e)})),
        )
            .into_response();
    }

    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                token: String::new(),
            }),
        )
            .into_response();
    };
    let now = duration.as_secs() as usize;

    let claims = Claims {
        pub_key: payload.public_key,
        exp: now + JWT_EXPIRY_SECS,
    };

    let Ok(token) = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthResponse {
                success: false,
                token: String::new(),
            }),
        )
            .into_response();
    };

    (
        StatusCode::OK,
        Json(AuthResponse {
            success: true,
            token,
        }),
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "healthy"}))
}

async fn set_secret(
    State(state): State<AppState>,
    Json(payload): Json<SetSecretRequest>,
) -> impl IntoResponse {
    // Validate secret name
    if payload.name.is_empty() || payload.name.len() > MAX_SECRET_NAME_LENGTH {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Secret name must be between 1 and 256 characters"})),
        )
            .into_response();
    }
    if payload.name.contains("..") || payload.name.contains('/') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Secret name cannot contain '..' or '/'"})),
        )
            .into_response();
    }

    let Ok(mut secret_store) = state.secret_store.write() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire secret lock"})),
        )
            .into_response();
    };

    if let Err(e) = secret_store.set(&payload.name, payload.secret) {
        eprintln!("Failed to set secret: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Failed to set secret"})),
        )
            .into_response();
    }

    if let Err(e) = secret_store.save("secrets.json") {
        eprintln!("Failed to save secrets: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to save changes"})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(SetSecretResponse { success: true })).into_response()
}

async fn get_secret(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Ok(secret_store) = state.secret_store.read() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire read lock"})),
        )
            .into_response();
    };

    match secret_store.get(&name) {
        Ok(secret) => (StatusCode::OK, Json(GetSecretResponse { secret })).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Secret not found"})),
        )
            .into_response(),
    }
}

async fn delete_secret(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Ok(mut secret_store) = state.secret_store.write() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire secret lock"})),
        )
            .into_response();
    };

    // Use the proper remove method instead of direct field access
    match secret_store.remove(&name) {
        Ok(_) => {
            if let Err(e) = secret_store.save("secrets.json") {
                eprintln!("Failed to save secrets after delete: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to save changes"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(DeleteSecretResponse { success: true })).into_response()
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Secret not found"})),
        )
            .into_response(),
    }
}

async fn list_secrets(State(state): State<AppState>) -> impl IntoResponse {
    let Ok(secret_store) = state.secret_store.read() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire read lock"})),
        )
            .into_response();
    };

    // Use the proper list method instead of direct field access
    let names = secret_store.list();

    (StatusCode::OK, Json(ListSecretsResponse { names })).into_response()
}

async fn update_secret(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(payload): Json<Secret>,
) -> impl IntoResponse {
    if name.is_empty() || name.len() > MAX_SECRET_NAME_LENGTH {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Secret name must be between 1 and 256 characters"})),
        )
            .into_response();
    }

    let Ok(mut secret_store) = state.secret_store.write() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to acquire secret lock"})),
        )
            .into_response();
    };

    if let Err(_) = secret_store.update(&name, payload.data) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Secret not found"})),
        )
            .into_response();
    }

    if let Err(e) = secret_store.save("secrets.json") {
        eprintln!("Failed to save secrets after update: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to save changes"})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(SetSecretResponse { success: true })).into_response()
}
