//! Direct HTTP regression coverage for bounded NDJSON export and v2 import.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use common::{bootstrap_admin_key, post, test_app_with_sharding};
use serde_json::{json, Value};
use tower::ServiceExt;

/// The endpoint emits a complete typed stream that its v2 importer accepts,
/// including the trailer needed to distinguish truncation from completion.
#[tokio::test]
async fn ndjson_endpoint_round_trip_has_header_records_and_trailer() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let key = bootstrap_admin_key(&app).await;
    let (status, body) = post(
        &app,
        "/memory",
        &key,
        json!({"content":"portable endpoint 🦀","status":"pending"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let export_request = Request::builder()
        .method("GET")
        .uri("/export")
        .header("Authorization", format!("Bearer {key}"))
        .body(Body::empty())
        .expect("export request");
    let export_response = app
        .clone()
        .oneshot(export_request)
        .await
        .expect("export response");
    assert_eq!(export_response.status(), StatusCode::OK);
    assert_eq!(
        export_response.headers()[header::CONTENT_TYPE],
        "application/x-ndjson"
    );
    let export_bytes = to_bytes(export_response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read export");
    let lines: Vec<Value> = std::str::from_utf8(&export_bytes)
        .expect("UTF-8 export")
        .lines()
        .map(|line| serde_json::from_str(line).expect("NDJSON object"))
        .collect();
    assert_eq!(
        lines.first().and_then(|line| line["type"].as_str()),
        Some("header")
    );
    assert_eq!(
        lines.first().and_then(|line| line["version"].as_str()),
        Some("2.0")
    );
    assert!(lines
        .iter()
        .any(|line| { line["type"] == "memory" && line["content"] == "portable endpoint 🦀" }));
    assert_eq!(
        lines.last().and_then(|line| line["type"].as_str()),
        Some("trailer")
    );
    assert_eq!(lines.last().expect("trailer")["counts"]["memory"], 1);

    let import_request = Request::builder()
        .method("POST")
        .uri("/import")
        .header("Authorization", format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from(export_bytes))
        .expect("import request");
    let import_response = app
        .clone()
        .oneshot(import_request)
        .await
        .expect("import response");
    assert_eq!(import_response.status(), StatusCode::OK);
    let import_body: Value = serde_json::from_slice(
        &to_bytes(import_response.into_body(), 1024 * 1024)
            .await
            .expect("read import response"),
    )
    .expect("import JSON");
    assert_eq!(import_body["format"], "kleos-ndjson");
    assert_eq!(import_body["counts"]["memory"], 1);
}
