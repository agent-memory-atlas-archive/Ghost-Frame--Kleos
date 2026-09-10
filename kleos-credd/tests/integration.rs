//! Integration tests for engram-credd.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use kleos_cred::crypto::derive_key;
use kleos_credd::{build_router, state::AppState};
use kleos_lib::db::Database;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct TestApp {
    router: Router,
    master_token: String,
}

/// Provides authenticated and unauthenticated request helpers for integration tests.
impl TestApp {
    /// Builds an isolated credential-daemon router and temporary database.
    async fn new() -> Self {
        let db = Database::connect_memory().await.expect("in-memory db");

        let master_password = "test-master-password";
        let master_key = derive_key(1, master_password.as_bytes(), None);
        let master_token = hex::encode(*master_key);

        let state = AppState::new(db, *master_key);
        let router = build_router(state);

        Self {
            router,
            master_token,
        }
    }

    /// Sends an unauthenticated GET request to the test router.
    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.request("GET", path, None).await
    }

    /// Sends a GET request bearing the supplied authentication token.
    async fn get_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.request_auth("GET", path, None, token).await
    }

    /// Sends an authenticated POST request with a JSON body.
    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.request_auth("POST", path, Some(body), &self.master_token)
            .await
    }

    /// Sends an authenticated DELETE request to the test router.
    async fn delete(&self, path: &str) -> (StatusCode, Value) {
        self.request_auth("DELETE", path, None, &self.master_token)
            .await
    }

    /// Dispatches a request using the test application's master token.
    async fn request(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);

        let body = if let Some(json) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json).unwrap())
        } else {
            Body::empty()
        };

        let req = builder.body(body).unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: Value = if body_bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body_bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    /// Dispatches a request with an explicit bearer token and optional JSON body.
    async fn request_auth(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", token));

        let body = if let Some(json) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json).unwrap())
        } else {
            Body::empty()
        };

        let req = builder.body(body).unwrap();
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        let json: Value = if body_bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body_bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check() {
    let app = TestApp::new().await;
    let (status, _) = app.get("/health").await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_request_rejected() {
    let app = TestApp::new().await;
    let (status, _) = app.get("/secrets").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
/// Rejects a request carrying a token unknown to every authentication tier.
async fn invalid_token_rejected() {
    let app = TestApp::new().await;
    let (status, _) = app.get_auth("/secrets", "invalid-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
/// Accepts the configured master token and returns the protected response.
async fn master_token_accepted() {
    let app = TestApp::new().await;
    let (status, body) = app.get_auth("/secrets", &app.master_token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("secrets").is_some());
}

/// Proves the pre-authentication guard charges only failed authentication attempts.
#[tokio::test]
async fn valid_authentication_does_not_consume_the_failure_budget() {
    let app = TestApp::new().await;

    for _ in 0..20 {
        let (status, _) = app.get_auth("/secrets", &app.master_token).await;
        assert_eq!(status, StatusCode::OK);
    }

    for _ in 0..10 {
        let (status, _) = app.get_auth("/secrets", "invalid-token").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    let (status, _) = app.get_auth("/secrets", "invalid-token").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------------------
// Secret CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn store_and_get_api_key() {
    let app = TestApp::new().await;

    // Store secret
    let (status, body) = app
        .post(
            "/secret/openai/api-key",
            json!({
                "data": {
                    "type": "api_key",
                    "key": "sk-test-12345"
                }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("id").is_some());

    // Get secret
    let (status, body) = app
        .get_auth("/secret/openai/api-key", &app.master_token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["service"], "openai");
    assert_eq!(body["key"], "api-key");
    assert_eq!(body["value"]["key"], "sk-test-12345");
}

#[tokio::test]
/// Stores and retrieves a structured login credential through the master tier.
async fn store_and_get_login() {
    let app = TestApp::new().await;

    let (status, _) = app
        .post(
            "/secret/github/account",
            json!({
                "data": {
                    "type": "login",
                    "username": "user@example.com",
                    "password": "secret123"
                }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .get_auth("/secret/github/account", &app.master_token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["username"], "user@example.com");
    assert_eq!(body["value"]["password"], "secret123");
}

#[tokio::test]
/// Lists previously stored secrets for the authenticated owner.
async fn list_secrets() {
    let app = TestApp::new().await;

    // Store two secrets
    app.post(
        "/secret/aws/access-key",
        json!({
            "data": { "type": "api_key", "key": "AKIA123" }
        }),
    )
    .await;
    app.post(
        "/secret/aws/secret-key",
        json!({
            "data": { "type": "api_key", "key": "secret456" }
        }),
    )
    .await;

    // List all
    let (status, body) = app.get_auth("/secrets", &app.master_token).await;
    assert_eq!(status, StatusCode::OK);
    let secrets = body["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 2);
}

#[tokio::test]
/// Deletes a stored secret and verifies that it is no longer retrievable.
async fn delete_secret() {
    let app = TestApp::new().await;

    // Store
    app.post(
        "/secret/temp/key",
        json!({
            "data": { "type": "api_key", "key": "temp123" }
        }),
    )
    .await;

    // Delete
    let (status, body) = app.delete("/secret/temp/key").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], true);

    // Verify gone
    let (status, _) = app.get_auth("/secret/temp/key", &app.master_token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Agent keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_list_agent_keys() {
    let app = TestApp::new().await;

    // Create agent key
    let (status, body) = app
        .post(
            "/agents",
            json!({
                "name": "test-agent",
                "categories": ["openai", "aws"],
                "allow_raw": false
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("key").is_some());
    let agent_key = body["key"].as_str().unwrap();

    // List agent keys
    let (status, body) = app.get_auth("/agents", &app.master_token).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["name"], "test-agent");

    // A non-raw agent (allow_raw:false) is denied the raw /secret get, which
    // returns plaintext. Raw retrieval requires allow_raw; non-raw agents use
    // proxy resolve instead. (Previously asserted 200, codifying a plaintext hole.)
    app.post(
        "/secret/openai/key",
        json!({
            "data": { "type": "api_key", "key": "sk-agent-test" }
        }),
    )
    .await;

    let (status, body) = app.get_auth("/secret/openai/key", agent_key).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !body.to_string().contains("sk-agent-test"),
        "denied secret get must not leak the value"
    );
}

#[tokio::test]
/// Enforces a database-backed agent key's permitted secret categories.
async fn agent_key_category_restriction() {
    let app = TestApp::new().await;

    // Create agent with limited access
    let (status, body) = app
        .post(
            "/agents",
            json!({
                "name": "limited-agent",
                "categories": ["public"],
                "allow_raw": false
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap();

    // Store secret in restricted category
    app.post(
        "/secret/private/secret",
        json!({
            "data": { "type": "api_key", "key": "private-key" }
        }),
    )
    .await;

    // Agent cannot access restricted category
    let (status, _) = app.get_auth("/secret/private/secret", agent_key).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
/// Revokes an agent key and verifies that subsequent authentication fails.
async fn revoke_agent_key() {
    let app = TestApp::new().await;

    // Create and revoke
    let (status, body) = app
        .post(
            "/agents",
            json!({
                "name": "revokable",
                "categories": ["test"],
                "allow_raw": false
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    let (status, _) = app.post("/agents/revokable/revoke", json!({})).await;
    assert_eq!(status, StatusCode::OK);

    // Store a secret
    app.post(
        "/secret/test/key",
        json!({
            "data": { "type": "api_key", "key": "test123" }
        }),
    )
    .await;

    // Revoked key cannot access
    let (status, _) = app.get_auth("/secret/test/key", &agent_key).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Plaintext-tier gating: non-raw agents must never receive secret plaintext
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_raw_agent_denied_resolve_text() {
    let app = TestApp::new().await;

    // allow_raw:false agent WITH access to the category.
    let (status, body) = app
        .post(
            "/agents",
            json!({
                "name": "text-agent",
                "categories": ["openai"],
                "allow_raw": false
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    app.post(
        "/secret/openai/key",
        json!({ "data": { "type": "api_key", "key": "sk-leak-me" } }),
    )
    .await;

    // Text substitution would embed the plaintext in the response body, so a
    // non-raw agent must be denied and the value must not leak.
    let (status, body) = app
        .request_auth(
            "POST",
            "/resolve/text",
            Some(json!({ "text": "API_KEY={{secret:openai/key}}" })),
            &agent_key,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        !body.to_string().contains("sk-leak-me"),
        "denied text resolve must not leak the secret value"
    );
}

#[tokio::test]
/// Allows an agent with raw permission to retrieve an unredacted secret.
async fn raw_agent_allowed_secret_get() {
    let app = TestApp::new().await;

    // allow_raw:true agent retains direct plaintext retrieval.
    let (status, body) = app
        .post(
            "/agents",
            json!({
                "name": "raw-agent",
                "categories": ["openai"],
                "allow_raw": true
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let agent_key = body["key"].as_str().unwrap().to_string();

    app.post(
        "/secret/openai/key",
        json!({ "data": { "type": "api_key", "key": "sk-raw-ok" } }),
    )
    .await;

    let (status, body) = app.get_auth("/secret/openai/key", &agent_key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["key"], "sk-raw-ok");
}

// ---------------------------------------------------------------------------
// Three-tier resolve
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_text_substitution() {
    let app = TestApp::new().await;

    // Store secret
    app.post(
        "/secret/openai/api-key",
        json!({
            "data": { "type": "api_key", "key": "sk-real-key" }
        }),
    )
    .await;

    // Resolve placeholder
    let (status, body) = app
        .post(
            "/resolve/text",
            json!({
                "text": "Authorization: Bearer {{secret:openai/api-key}}"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["text"], "Authorization: Bearer sk-real-key");
}

#[tokio::test]
/// Resolves one raw credential field for an agent with raw access.
async fn resolve_raw_access() {
    let app = TestApp::new().await;

    // Store secret
    app.post(
        "/secret/db/password",
        json!({
            "data": { "type": "login", "username": "admin", "password": "secret123" }
        }),
    )
    .await;

    // Raw resolve
    let (status, body) = app
        .post(
            "/resolve/raw",
            json!({
                "category": "db",
                "name": "password"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["password"], "secret123");
}
