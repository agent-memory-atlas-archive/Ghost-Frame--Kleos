//! Regressions for atomic, idempotent inline memory attachments.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use common::{bootstrap_admin_key, post, seed_user, send, test_app_with_sharding};
use kleos_lib::artifacts::{self, PreparedInlineArtifact};
use serde_json::json;

/// Encode a small inline attachment request.
fn attachment(filename: &str, bytes: &[u8]) -> serde_json::Value {
    json!({
        "filename": filename,
        "mime_type": "text/plain",
        "data_base64": base64::engine::general_purpose::STANDARD.encode(bytes)
    })
}

/// A malformed later attachment is rejected before the memory row is written.
#[tokio::test]
async fn invalid_later_attachment_leaves_no_memory() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (user_id, key) = seed_user(&app, &admin, "artifact-invalid").await;
    let (status, _) = post(
        &app,
        "/memory",
        &key,
        json!({
            "content":"must remain absent",
            "artifacts":[attachment("valid.txt", b"ok"), {
                "filename":"broken.txt", "mime_type":"text/plain", "data_base64":"%%%"
            }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let handle = state
        .tenant_registry
        .as_ref()
        .expect("registry")
        .get_or_create(&user_id.to_string())
        .await
        .expect("tenant");
    let count: i64 = handle
        .database()
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE content = 'must remain absent'",
                [],
                |row| row.get(0),
            )?)
        })
        .await
        .expect("memory count");
    assert_eq!(count, 0);
}

/// Sequential and concurrent retries reuse one attachment identity, and a
/// different owner cannot attach it to the memory.
#[tokio::test]
async fn attachment_batch_is_idempotent_and_owner_scoped() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (owner_id, owner_key) = seed_user(&app, &admin, "artifact-owner").await;
    let (other_id, _other_key) = seed_user(&app, &admin, "artifact-other").await;
    let (status, body) = post(
        &app,
        "/memory",
        &owner_key,
        json!({"content":"attachment retry memory","artifacts":[attachment("retry.txt", b"same")]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let memory_id = body["id"].as_i64().expect("memory id");

    let handle = state
        .tenant_registry
        .as_ref()
        .expect("registry")
        .get_or_create(&owner_id.to_string())
        .await
        .expect("tenant");
    let prepared = PreparedInlineArtifact {
        filename: "retry.txt".to_string(),
        mime_type: "text/plain".to_string(),
        data: b"same".to_vec(),
        sha256: artifacts::sha256_hex(b"same"),
        indexable_content: Some("same".to_string()),
    };
    let db_a = handle.database();
    let db_b = handle.database();
    let batch_a = vec![prepared.clone()];
    let batch_b = vec![prepared.clone()];
    let (first, second) = tokio::join!(
        artifacts::store_inline_batch(&db_a, owner_id, memory_id, &batch_a),
        artifacts::store_inline_batch(&db_b, owner_id, memory_id, &batch_b)
    );
    assert_eq!(
        first.expect("first retry")[0].id,
        second.expect("second retry")[0].id
    );
    let rows = artifacts::get_artifacts_by_memory(&db_a, owner_id, memory_id)
        .await
        .expect("attachments");
    assert_eq!(rows.len(), 1);

    let error = artifacts::store_inline_batch(&db_a, other_id, memory_id, &[prepared])
        .await
        .expect_err("foreign owner must fail");
    assert!(matches!(error, kleos_lib::EngError::NotFound(_)));
}

/// A database failure rolls back the attachment batch and reports the already
/// persisted memory identity with an explicit partial-persistence signal.
#[tokio::test]
async fn artifact_batch_failure_returns_recoverable_multi_status() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (user_id, key) = seed_user(&app, &admin, "artifact-partial").await;
    let registry = state.tenant_registry.as_ref().expect("registry");
    let handle = registry
        .get_or_create(&user_id.to_string())
        .await
        .expect("tenant");
    handle
        .database()
        .write(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_inline_artifacts BEFORE INSERT ON artifacts
                 BEGIN SELECT RAISE(ABORT, 'injected artifact failure'); END;",
            )?;
            Ok(())
        })
        .await
        .expect("failure trigger");

    let (status, body) = post(
        &app,
        "/memory",
        &key,
        json!({"content":"persisted partial identity","artifacts":[attachment("fail.txt", b"data")]}),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS, "{body}");
    assert_eq!(body["attachments_committed"], false);
    let memory_id = body["id"].as_i64().expect("persisted memory id");
    let counts: (i64, i64) = handle
        .database()
        .read(move |conn| {
            let memories = conn.query_row(
                "SELECT COUNT(*) FROM memories WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![memory_id, user_id],
                |row| row.get(0),
            )?;
            let artifacts = conn.query_row(
                "SELECT COUNT(*) FROM artifacts WHERE memory_id = ?1",
                [memory_id],
                |row| row.get(0),
            )?;
            Ok((memories, artifacts))
        })
        .await
        .expect("partial state");
    assert_eq!(counts, (1, 0));

    handle
        .database()
        .write(|conn| {
            conn.execute("DROP TRIGGER reject_inline_artifacts", [])?;
            Ok(())
        })
        .await
        .expect("remove failure trigger");
    let (status, retry) = post(
        &app,
        "/memory",
        &key,
        json!({"content":"persisted partial identity","artifacts":[attachment("fail.txt", b"data")]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(retry["existing_id"], memory_id);
    assert_eq!(retry["attachments_committed"], true);
    assert_eq!(retry["artifacts"].as_array().map(Vec::len), Some(1));
}

/// MCP converts an attachment partial-persistence response into an explicit
/// tool error while retaining the route's persisted memory identity.
#[tokio::test]
async fn mcp_marks_attachment_partial_persistence_as_error() {
    let (app, state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (user_id, key) = seed_user(&app, &admin, "artifact-mcp-partial").await;
    let handle = state
        .tenant_registry
        .as_ref()
        .expect("registry")
        .get_or_create(&user_id.to_string())
        .await
        .expect("tenant");
    handle
        .database()
        .write(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_inline_artifacts_mcp BEFORE INSERT ON artifacts
                 BEGIN SELECT RAISE(ABORT, 'injected MCP artifact failure'); END;",
            )?;
            Ok(())
        })
        .await
        .expect("failure trigger");

    let payload = json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"tools/call",
        "params":{
            "name":"memory_store",
            "arguments":{
                "content":"MCP persisted partial identity",
                "artifacts":[attachment("mcp-fail.txt", b"data")]
            }
        }
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("MCP request");
    let (status, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert!(
        body["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("partial result requiring caller recovery")),
        "{body}"
    );
    let memory_id: i64 = handle
        .database()
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT id FROM memories WHERE content = 'MCP persisted partial identity'",
                [],
                |row| row.get(0),
            )?)
        })
        .await
        .expect("persisted memory id");
    let error_text = body["result"]["content"][0]["text"]
        .as_str()
        .expect("tool error text");
    assert!(
        error_text.contains(&format!("\"id\":{memory_id}")),
        "{body}"
    );
    assert!(
        error_text.contains("\"attachments_committed\":false"),
        "{body}"
    );
}
