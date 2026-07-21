use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path, time::{SystemTime, UNIX_EPOCH}};

pub const SIGNING_PUBLIC_KEY: &str = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
pub const SIGNING_KEY_ID: &str = "eliteauth-ed25519-2026-01";

#[derive(Debug, Clone)]
pub struct ResultData {
    pub success: bool,
    pub valid: bool,
    pub error: Option<String>,
    pub data: Value,
    pub http_status: u16,
    pub request_id: String,
}

#[derive(Deserialize)]
struct Envelope {
    key_id: String,
    algorithm: String,
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
struct SignedPayload {
    protocol: String,
    request_id: String,
    server_time: i64,
    nonce: String,
    data: Value,
}

pub struct EliteAuthClient {
    api_url: String,
    app_id: String,
    version: String,
    integrity_sha256: Option<String>,
    http: HttpClient,
    verification_key: VerifyingKey,
    session_token: Option<String>,
    challenge: Option<String>,
}

impl EliteAuthClient {
    pub fn new(api_url: impl Into<String>, app_id: impl Into<String>, version: impl Into<String>, integrity_sha256: Option<String>) -> Result<Self, String> {
        let api_url = api_url.into().trim_end_matches('/').to_string();
        let app_id = app_id.into();
        let version = version.into();
        if api_url.is_empty() || app_id.is_empty() || version.is_empty() {
            return Err("api_url, app_id and version are required".into());
        }
        let integrity_sha256 = normalize_hash(integrity_sha256)?;
        let raw = URL_SAFE_NO_PAD.decode(SIGNING_PUBLIC_KEY).map_err(|_| "invalid pinned public key")?;
        let key_bytes: [u8; 32] = raw.try_into().map_err(|_| "invalid pinned public key length")?;
        let verification_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "invalid pinned public key")?;
        Ok(Self {
            api_url,
            app_id,
            version,
            integrity_sha256,
            http: HttpClient::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?,
            verification_key,
            session_token: None,
            challenge: None,
        })
    }

    pub async fn activate(&mut self, license_key: &str, hwid: &str) -> Result<ResultData, String> {
        let nonce = random_base64url(24);
        let body = json!({
            "app_id": self.app_id,
            "license_key": license_key,
            "hwid": hwid,
            "version": self.version,
            "sdk_version": "rust-1.1.0",
            "integrity_sha256": self.integrity_sha256,
            "timestamp": unix_time(),
            "nonce": nonce,
        });
        let result = self.post_signed("/v1/license/activate", body, &nonce).await?;
        if result.success {
            self.session_token = result.data.pointer("/session/token").and_then(Value::as_str).map(str::to_owned);
            self.challenge = result.data.pointer("/session/challenge").and_then(Value::as_str).map(str::to_owned);
            if self.session_token.is_none() || self.challenge.is_none() {
                return Err("signed activation response is missing session state".into());
            }
        }
        Ok(result)
    }

    pub async fn check_session(&mut self, hwid: &str) -> Result<ResultData, String> {
        let session_token = self.session_token.clone().ok_or("call activate before check_session")?;
        let challenge = self.challenge.clone().ok_or("call activate before check_session")?;
        let nonce = random_base64url(24);
        let body = json!({
            "app_id": self.app_id,
            "session_token": session_token,
            "challenge": challenge,
            "hwid": hwid,
            "sdk_version": "rust-1.1.0",
            "integrity_sha256": self.integrity_sha256,
            "timestamp": unix_time(),
            "nonce": nonce,
        });
        let result = self.post_signed("/v1/session/check", body, &nonce).await?;
        if result.success && result.valid {
            self.challenge = result.data.pointer("/session/challenge").and_then(Value::as_str).map(str::to_owned);
            if self.challenge.is_none() {
                return Err("signed session response did not rotate the challenge".into());
            }
        }
        Ok(result)
    }

    pub fn clear_session(&mut self) {
        self.session_token = None;
        self.challenge = None;
    }

    async fn post_signed(&self, path: &str, body: Value, expected_nonce: &str) -> Result<ResultData, String> {
        let response = self.http.post(format!("{}{}", self.api_url, path))
            .header("cache-control", "no-store")
            .json(&body)
            .send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let envelope: Envelope = response.json().await.map_err(|_| "EliteAuth returned invalid JSON")?;
        let payload = self.verify_envelope(envelope, expected_nonce)?;
        Ok(ResultData {
            success: payload.data.get("success").and_then(Value::as_bool).unwrap_or(false),
            valid: payload.data.get("valid").and_then(Value::as_bool).unwrap_or(false),
            error: payload.data.get("error").and_then(Value::as_str).map(str::to_owned),
            data: payload.data,
            http_status: status,
            request_id: payload.request_id,
        })
    }

    fn verify_envelope(&self, envelope: Envelope, expected_nonce: &str) -> Result<SignedPayload, String> {
        if envelope.key_id != SIGNING_KEY_ID || envelope.algorithm != "Ed25519" {
            return Err("unexpected EliteAuth signing key or algorithm".into());
        }
        let payload_bytes = URL_SAFE_NO_PAD.decode(envelope.payload).map_err(|_| "invalid signed payload")?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(envelope.signature).map_err(|_| "invalid signature")?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| "invalid signature length")?;
        self.verification_key.verify(&payload_bytes, &signature).map_err(|_| "EliteAuth response signature verification failed")?;
        let payload: SignedPayload = serde_json::from_slice(&payload_bytes).map_err(|_| "invalid verified payload")?;
        if payload.protocol != "eliteauth-signed-v1" { return Err("unsupported EliteAuth protocol".into()); }
        if payload.nonce != expected_nonce { return Err("EliteAuth response nonce mismatch".into()); }
        if (unix_time() - payload.server_time).abs() > 300 { return Err("EliteAuth response timestamp is outside the allowed window".into()); }
        Ok(payload)
    }
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 { break; }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalize_hash(value: Option<String>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(value) => {
            let hash = value.trim().to_lowercase();
            if hash.is_empty() { return Ok(None); }
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("integrity_sha256 must be a 64-character SHA-256 value".into());
            }
            Ok(Some(hash))
        }
    }
}

fn random_base64url(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_time() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}
