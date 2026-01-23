use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lockbox_proto::*;
use lockbox_store::db::Database;
use once_cell::sync::Lazy;
use rand::RngCore;
use serde_json::json;
use std::{
    env,
    sync::Arc,
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

static DATABASE_URL: Lazy<String> =
    Lazy::new(|| env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://lockbox.db".to_string()));

const CHALLENGE_EXPIRY_SECS: u64 = 300;
const JWT_EXPIRY_SECS: usize = 60;
const CHALLENGE_CLEANUP_INTERVAL_SECS: u64 = 60;
const MAX_SECRET_NAME_LENGTH: usize = 256;
const TOMBSTONE_RETENTION_SECS: i64 = 86400;
const TOMBSTONE_PURGE_INTERVAL_SECS: u64 = 3600;

fn current_timestamp() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| format!("Failed to get current time: {}", e))
}

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
}

#[tokio::main]
async fn main() {
    let db = Database::new(&DATABASE_URL)
        .await
        .expect("Failed to initialize database");
    println!("Database initialized successfully");

    let state = AppState { db: Arc::new(db) };

    let _ = &*API_KEY;
    let _ = &*JWT_SECRET;
    let cleanup_db = state.db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(CHALLENGE_CLEANUP_INTERVAL_SECS)).await;
            let now = match current_timestamp() {
                Ok(ts) => ts,
                Err(e) => {
                    eprintln!("{}", e);
                    continue;
                }
            };

            match cleanup_db.cleanup_expired_challenges(now).await {
                Ok(removed) if removed > 0 => {
                    println!("Cleaned up {} expired challenges", removed);
                }
                Err(e) => {
                    eprintln!("Failed to cleanup challenges: {}", e);
                }
                _ => {}
            }
        }
    });

    let purge_db = state.db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(TOMBSTONE_PURGE_INTERVAL_SECS)).await;
            match purge_db
                .purge_deleted_secrets(TOMBSTONE_RETENTION_SECS)
                .await
            {
                Ok(removed) if removed > 0 => {
                    println!("Purged {} tombstoned secrets", removed);
                }
                Err(e) => {
                    eprintln!("Failed to purge tombstoned secrets: {}", e);
                }
                _ => {}
            }
        }
    });

    let public_routes = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/challenge", post(challenge))
        .route("/auth/verify", post(verify))
        .route("/health", get(health));

    let protected_routes = Router::new()
        .route("/secrets", post(set_secret).get(list_secrets))
        .route("/secrets/sync", get(delta_sync))
        .route(
            "/secrets/{*name}",
            get(get_secret).delete(delete_secret).patch(update_secret),
        )
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

    if let Err(e) = state
        .db
        .register_key(&payload.public_key, &payload.label)
        .await
    {
        eprintln!("Failed to register key: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Failed to register key"})),
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
    match state.db.key_allowed(&payload.public_key).await {
        Ok(allowed) if !allowed => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Public key not registered"})),
            )
                .into_response();
        }
        Err(e) => {
            eprintln!("Failed to check key: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify key"})),
            )
                .into_response();
        }
        _ => {}
    }
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);

    let expires_at = match current_timestamp() {
        Ok(ts) => ts + CHALLENGE_EXPIRY_SECS as i64,
        Err(e) => {
            eprintln!("{}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to generate challenge"})),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .db
        .store_challenge(payload.public_key.as_bytes(), &nonce, expires_at)
        .await
    {
        eprintln!("Failed to store challenge: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to store challenge"})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge: nonce.to_vec(),
        }),
    )
        .into_response()
}

async fn verify(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    let (stored_challenge, expires_at) = match state.db.consume_challenge(payload.public_key.as_bytes()).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "No challenge found for this key"})),
            )
                .into_response();
        }
        Err(e) => {
            eprintln!("Failed to retrieve challenge: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify challenge"})),
            )
                .into_response();
        }
    };
    let now = match current_timestamp() {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("{}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify challenge"})),
            )
                .into_response();
        }
    };

    if now > expires_at {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Challenge expired"})),
        )
            .into_response();
    }
    if payload.challenge != stored_challenge {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Challenge mismatch"})),
        )
            .into_response();
    }
    if let Err(e) = payload
        .public_key
        .verify_strict(&payload.challenge, &payload.signature)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": format!("Signature verification failed: {}", e)})),
        )
            .into_response();
    }
    let exp = match current_timestamp() {
        Ok(ts) => (ts as usize) + JWT_EXPIRY_SECS,
        Err(e) => {
            eprintln!("{}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    token: String::new(),
                }),
            )
                .into_response();
        }
    };

    let claims = Claims {
        pub_key: payload.public_key,
        exp,
    };

    let token = match encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to encode JWT: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthResponse {
                    success: false,
                    token: String::new(),
                }),
            )
                .into_response();
        }
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

    // Only prevent path traversal attempts - slashes are allowed for namespace/secret patterns
    if payload.name.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Secret name cannot contain '..'"})),
        )
            .into_response();
    }

    if payload.namespace.is_empty() || payload.namespace.len() > MAX_SECRET_NAME_LENGTH {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Namespace must be between 1 and 256 characters"})),
        )
            .into_response();
    }

    if let Err(e) = state
        .db
        .set_secret(&payload.namespace, &payload.name, &payload.secret.data)
        .await
    {
        eprintln!("Failed to set secret: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Failed to set secret"})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(SetSecretResponse { success: true })).into_response()
}

async fn get_secret(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Strip leading slash from catch-all parameter
    let name = name.strip_prefix('/').unwrap_or(&name);

    match state.db.get_secret(name).await {
        Ok(data) => {
            let secret = lockbox_store::Secret { data };
            (StatusCode::OK, Json(GetSecretResponse { secret })).into_response()
        }
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
    // Strip leading slash from catch-all parameter
    let name = name.strip_prefix('/').unwrap_or(&name);

    match state.db.remove_secret(name).await {
        Ok(_) => (StatusCode::OK, Json(DeleteSecretResponse { success: true })).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Secret not found"})),
        )
            .into_response(),
    }
}

async fn list_secrets(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.list_secrets().await {
        Ok(names) => (StatusCode::OK, Json(ListSecretsResponse { names })).into_response(),
        Err(e) => {
            eprintln!("Failed to list secrets: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list secrets"})),
            )
                .into_response()
        }
    }
}

async fn update_secret(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(payload): Json<lockbox_store::Secret>,
) -> impl IntoResponse {
    // Strip leading slash from catch-all parameter
    let name = name.strip_prefix('/').unwrap_or(&name);

    if name.is_empty() || name.len() > MAX_SECRET_NAME_LENGTH {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Secret name must be between 1 and 256 characters"})),
        )
            .into_response();
    }

    if state.db.update_secret(name, payload.data).await.is_err() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Secret not found"})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(SetSecretResponse { success: true })).into_response()
}

async fn delta_sync(
    State(state): State<AppState>,
    Query(params): Query<DeltaSyncQuery>,
) -> impl IntoResponse {
    let server_time = match current_timestamp() {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("{}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get server time"})),
            )
                .into_response();
        }
    };

    let secrets = match params.since {
        Some(since) => match state.db.get_secrets_since(since, params.limit).await {
            Ok(records) => records
                .into_iter()
                .map(lockbox_store::SecretWithMetadata::from)
                .collect(),
            Err(e) => {
                eprintln!("Failed to get secrets since timestamp: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to fetch secrets"})),
                )
                    .into_response();
            }
        },
        None => match state.db.get_all_secret_records().await {
            Ok(records) => records
                .into_iter()
                .map(lockbox_store::SecretWithMetadata::from)
                .collect(),
            Err(e) => {
                eprintln!("Failed to get all secrets: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to fetch secrets"})),
                )
                    .into_response();
            }
        },
    };

    (
        StatusCode::OK,
        Json(DeltaSyncResponse {
            secrets,
            server_time,
        }),
    )
        .into_response()
}
