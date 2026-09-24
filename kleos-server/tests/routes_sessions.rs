//! Session admission regressions exercise capacity before durable creation.

mod common;

use axum::http::StatusCode;
use common::{bootstrap_admin_key, post, test_app};
use kleos_server::state::SessionBroadcast;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Two simultaneous admissions compete for one slot without leaving a rejected row.
#[tokio::test]
async fn maintenance_session_capacity_is_atomic() {
    let (app, state) = test_app().await;
    let key = bootstrap_admin_key(&app).await;
    {
        let mut sessions = state.sessions.write().await;
        for index in 0..63 {
            sessions.insert(
                (1, format!("existing-{index}")),
                Arc::new(Mutex::new(SessionBroadcast::new())),
            );
        }
    }
    let (first, second) = tokio::join!(
        post(&app, "/sessions", &key, json!({"agent": "first"})),
        post(&app, "/sessions", &key, json!({"agent": "second"}))
    );
    assert_eq!(
        [first.0, second.0]
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(state.sessions.read().await.len(), 64);
    let rows = state
        .db
        .read(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| {
                row.get::<_, i64>(0)
            })?)
        })
        .await
        .unwrap();
    assert_eq!(
        rows, 1,
        "capacity rejection must not persist a second session"
    );
}
