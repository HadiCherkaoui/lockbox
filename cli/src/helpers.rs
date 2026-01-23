use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};
use lockbox_proto::{
    ChallengeRequest, ChallengeResponse, GetSecretResponse, ListSecretsResponse,
    RegisterKeyRequest, SetSecretRequest,
};
use lockbox_store::Secret;
use reqwest::Client;

const USER_AGENT: &str = "lockbox-cli/1.0";

fn build_http_client() -> Result<Client, Box<dyn std::error::Error>> {
    Ok(Client::builder().user_agent(USER_AGENT).build()?)
}

pub async fn register_server(
    keypair: &SigningKey,
    base_url: &str,
    api_key: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = build_http_client()?;

    let request_payload = RegisterKeyRequest {
        public_key: keypair.verifying_key(),
        label: label.trim().to_string(),
    };

    let res = client
        .post(format!("{}/auth/register", base_url))
        .header("x-api-key", api_key.trim())
        .json(&request_payload)
        .send()
        .await?;

    if res.status().is_success() {
        println!("✓ Server registered successfully");
        Ok(())
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(format!("Failed to register: {} - {}", status, text).into())
    }
}

pub async fn set(
    namespace: String,
    name: String,
    secret: Secret,
    base_url: &str,
    keypair: &mut SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = authenticate(base_url, keypair).await?;
    let client = build_http_client()?;
    let request_payload = SetSecretRequest {
        namespace,
        name,
        secret,
    };
    let res = client
        .post(format!("{}/secrets", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&request_payload)
        .send()
        .await?;
    if res.status().is_success() {
        println!("✓ Secret set successfully");
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(format!("Failed to set secret: {} - {}", status, text).into());
    }
    Ok(())
}

pub async fn get(
    name: &str,
    base_url: &str,
    keypair: &mut SigningKey,
) -> Result<Secret, Box<dyn std::error::Error>> {
    let token = authenticate(base_url, keypair).await?;
    let client = build_http_client()?;
    let res = client
        .get(format!("{}/secrets/{}", base_url, name))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(format!("Failed to get secret: {}", res.status()).into());
    }
    Ok(res.json::<GetSecretResponse>().await?.secret)
}

pub async fn list(
    base_url: &str,
    keypair: &mut SigningKey,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let token = authenticate(base_url, keypair).await?;
    let client = build_http_client()?;
    let res = client
        .get(format!("{}/secrets", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    if !res.status().is_success() {
        return Err(format!("Failed to list secrets: {}", res.status()).into());
    }
    let list_response: ListSecretsResponse = res.json().await?;
    Ok(list_response.names)
}

pub async fn remove(
    name: &str,
    base_url: &str,
    keypair: &mut SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = authenticate(base_url, keypair).await?;
    let client = build_http_client()?;
    let res = client
        .delete(format!("{}/secrets/{}", base_url, name))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    if res.status().is_success() {
        Ok(())
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(format!("Failed to remove secret: {} - {}", status, text).into())
    }
}

pub async fn update(
    name: &str,
    secret: Secret,
    base_url: &str,
    keypair: &mut SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = authenticate(base_url, keypair).await?;
    let client = build_http_client()?;
    let res = client
        .patch(format!("{}/secrets/{}", base_url, name))
        .header("Authorization", format!("Bearer {}", token))
        .json(&secret)
        .send()
        .await?;
    if res.status().is_success() {
        Ok(())
    } else {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(format!("Failed to update secret: {} - {}", status, text).into())
    }
}

async fn authenticate(
    base_url: &str,
    keypair: &mut SigningKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = build_http_client()?;

    let request_payload = ChallengeRequest {
        public_key: keypair.verifying_key(),
    };

    let challenge_req = client
        .post(format!("{}/auth/challenge", base_url))
        .json(&request_payload)
        .send()
        .await?;
    if !challenge_req.status().is_success() {
        return Err(format!("Failed to get challenge: {}", challenge_req.status()).into());
    }
    let challenge: ChallengeResponse = challenge_req.json().await?;

    let signature = keypair.try_sign(&challenge.challenge)?;
    let auth_payload = lockbox_proto::AuthRequest {
        public_key: keypair.verifying_key(),
        challenge: challenge.challenge,
        signature,
    };
    let auth_req = client
        .post(format!("{}/auth/verify", base_url))
        .json(&auth_payload)
        .send()
        .await?;
    if !auth_req.status().is_success() {
        return Err(format!("Authentication failed: {}", auth_req.status()).into());
    }
    let auth_response: lockbox_proto::AuthResponse = auth_req.json().await?;
    Ok(auth_response.token)
}
