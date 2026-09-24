//! Security regressions for the authenticated Broca ingest receiver.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{bootstrap_admin_key, post, seed_user, send, test_app_with_sharding};

/// Build a representative Axon webhook payload.
fn ingest_payload(source: &str) -> serde_json::Value {
    json!({
        "id": 42,
        "source": source,
        "type": "task.completed",
        "channel": "audit",
        "payload": { "summary": "done" }
    })
}

/// Create a key with an exact scope and request budget for a known user.
async fn create_limited_key(
    app: &axum::Router,
    admin_key: &str,
    user_id: i64,
    scopes: &str,
    rate_limit: i64,
) -> String {
    let (status, body) = post(
        app,
        "/keys",
        admin_key,
        json!({
            "name": format!("broca-{scopes}-{rate_limit}"),
            "scopes": scopes,
            "user_id": user_id,
            "rate_limit": rate_limit
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["key"].as_str().expect("created key").to_string()
}

/// Broca ingest rejects anonymous callers before it accepts claimed metadata.
#[tokio::test]
async fn broca_ingest_requires_authentication() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let request = Request::builder()
        .method("POST")
        .uri("/broca/ingest")
        .header("Content-Type", "application/json")
        .body(Body::from(ingest_payload("spoofed-agent").to_string()))
        .expect("request");

    let (status, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Read-only keys cannot submit Broca actions.
#[tokio::test]
async fn broca_ingest_requires_write_scope() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin_key = bootstrap_admin_key(&app).await;
    let (user_id, _write_key) = seed_user(&app, &admin_key, "broca-read-only").await;
    let read_key = create_limited_key(&app, &admin_key, user_id, "read", 1000).await;

    let (status, _) = post(&app, "/broca/ingest", &read_key, ingest_payload("reader")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Claimed source metadata cannot redirect a write into another tenant shard.
#[tokio::test]
async fn broca_ingest_uses_authenticated_tenant() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin_key = bootstrap_admin_key(&app).await;
    let (user_id, user_key) = seed_user(&app, &admin_key, "broca-tenant-two").await;

    let (status, body) = post(&app, "/broca/ingest", &user_key, ingest_payload("operator")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let registry = state.tenant_registry.as_ref().expect("tenant registry");
    let tenant = registry
        .get_or_create(&user_id.to_string())
        .await
        .expect("tenant handle");
    let tenant_count: i64 = tenant
        .database()
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM broca_actions WHERE user_id = ?1",
                [user_id],
                |row| row.get(0),
            )?)
        })
        .await
        .expect("tenant count");
    assert_eq!(tenant_count, 1);

    let operator = registry.get_or_create("1").await.expect("operator handle");
    let operator_count: i64 = operator
        .database()
        .read(
            |conn| Ok(conn.query_row("SELECT COUNT(*) FROM broca_actions", [], |row| row.get(0))?),
        )
        .await
        .expect("operator count");
    assert_eq!(operator_count, 0);
}

/// Safe mode rejects Broca ingest through the shared authenticated write stack.
#[tokio::test]
async fn broca_ingest_obeys_safe_mode() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin_key = bootstrap_admin_key(&app).await;
    state
        .safe_mode
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let (status, _) = post(
        &app,
        "/broca/ingest",
        &admin_key,
        ingest_payload("operator"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// Broca ingest consumes the authenticated caller's shared rate budget.
#[tokio::test]
async fn broca_ingest_obeys_rate_limit() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin_key = bootstrap_admin_key(&app).await;
    let (user_id, _write_key) = seed_user(&app, &admin_key, "broca-rate-limited").await;
    let limited_key = create_limited_key(&app, &admin_key, user_id, "write", 1).await;

    let (status, body) = post(
        &app,
        "/broca/ingest",
        &limited_key,
        ingest_payload("limited-writer"),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}
