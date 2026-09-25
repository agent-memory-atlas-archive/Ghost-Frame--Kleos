//! Regression for the intended model self-approval policy.

mod common;

use axum::http::StatusCode;
use common::{bootstrap_admin_key, post, seed_user, test_app_with_sharding};
use serde_json::json;

/// The same authenticated model owner that created a pending memory may use
/// the dedicated inbox endpoint to approve it without a human reviewer.
#[tokio::test]
async fn owner_model_can_approve_its_own_pending_memory() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (user_id, key) = seed_user(&app, &admin, "self-approving-model").await;
    let handle = state
        .tenant_registry
        .as_ref()
        .expect("registry")
        .get_or_create(&user_id.to_string())
        .await
        .expect("tenant");
    let memory_id = handle
        .database()
        .write(move |conn| {
            Ok(conn.query_row(
                "INSERT INTO memories (content, source, status, user_id, sync_id) \
                 VALUES ('model-authored pending memory', 'agent', 'pending', ?1, 'self-approve') \
                 RETURNING id",
                [user_id],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await
        .expect("pending memory");

    let (status, body) = post(
        &app,
        &format!("/inbox/{memory_id}/approve"),
        &key,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["approved"], true);

    let persisted_status: String = handle
        .database()
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT status FROM memories WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![memory_id, user_id],
                |row| row.get(0),
            )?)
        })
        .await
        .expect("approved status");
    assert_eq!(persisted_status, "approved");
}
