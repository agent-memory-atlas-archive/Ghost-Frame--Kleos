//! Space Sharing enforcement tests (whole-instance, sharded model).
//!
//! These tests anchor the security definitions from the threat model. The
//! chokepoint is the `ResolvedDb` extractor: a request names a target owner via
//! the `X-Kleos-Act-As` header, and the extractor authorizes delegated access
//! (caller is owner, caller is Admin, or an `instance_grants` row covers the
//! requested access) before resolving the owner's shard.
//!
//! `/projects` is the test vehicle: it is `ResolvedDb`-backed, needs no
//! embedding model, and the existing cross-tenant suite already proves it
//! isolates shards. Making the chokepoint act-as aware makes every
//! ResolvedDb-backed route inherit delegated access from one place.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{
    bootstrap_admin_key, get, get_as, get_as_raw, post, post_as, seed_user, send,
    test_app_with_sharding,
};
use serde_json::json;

/// Create a project in the shard the caller resolves to. Asserts success.
async fn make_project(app: &axum::Router, key: &str, name: &str) {
    let (status, body) = post(
        app,
        "/projects",
        key,
        json!({ "name": name, "status": "active" }),
    )
    .await;
    assert!(
        status.is_success(),
        "create project {name}: {status} {body}"
    );
}

/// Collect project names from a `/projects` list response body.
fn project_names(body: &serde_json::Value) -> Vec<String> {
    body["projects"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Send an MCP JSON-RPC payload while acting inside another owner's shard.
async fn mcp_as(
    app: &axum::Router,
    key: &str,
    owner: i64,
    payload: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .header(common::ACT_AS_HEADER, owner.to_string())
        .body(Body::from(payload.to_string()))
        .expect("MCP act-as request");
    send(app, request).await
}

/// Read delegation permits read-only MCP tools, rejects writes per tool, and
/// an unrelated owner remains inaccessible at the outer delegation boundary.
#[tokio::test]
async fn read_grant_is_enforced_per_mcp_tool() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "mcp-owner").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "mcp-reader").await;
    let (carol_uid, _carol_key) = seed_user(&app, &admin, "mcp-unshared-owner").await;

    let (status, body) = post(
        &app,
        "/store",
        &alice_key,
        json!({"content":"delegated MCP search target","category":"test"}),
    )
    .await;
    assert!(status.is_success(), "{body}");
    let (status, body) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({"owner_user_id":alice_uid,"grantee_user_id":bob_uid,"access":"read"}),
    )
    .await;
    assert!(status.is_success(), "{body}");

    let batch = json!([
        {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"memory_search","arguments":{"query":"delegated MCP search target"}}},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"memory_store","arguments":{"content":"blocked delegated write"}}}
    ]);
    let (status, body) = mcp_as(&app, &bob_key, alice_uid, batch.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let responses = body.as_array().expect("batch response");
    assert_eq!(responses[0]["result"]["isError"], false, "{body}");
    assert_eq!(responses[1]["result"]["isError"], true, "{body}");
    assert!(
        responses[1]["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("insufficient delegated access")),
        "{body}"
    );

    let (status, _) = mcp_as(&app, &bob_key, carol_uid, batch).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// SD1a: a grantee holding a read grant can read the owner's data by acting as
/// the owner.
#[tokio::test]
async fn sd1a_read_grant_allows_act_as_read() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;

    make_project(&app, &alice_key, "alice-secret").await;

    // Admin grants bob read access to alice's instance.
    let (status, body) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success(), "grant create: {status} {body}");

    // Bob acts as alice and sees alice's project.
    let (status, body) = get_as(&app, "/projects", &bob_key, alice_uid).await;
    assert!(
        status.is_success(),
        "bob act-as alice read: {status} {body}"
    );
    assert!(
        project_names(&body).contains(&"alice-secret".to_string()),
        "bob with read grant must see alice's project: {body}"
    );
}

/// SD1b: a caller with no grant cannot act as another owner. This is the leak
/// guard; it must be 403, not a silent fall-through to the caller's own shard.
#[tokio::test]
async fn sd1b_no_grant_act_as_is_forbidden() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (_carol_uid, carol_key) = seed_user(&app, &admin, "carol").await;

    make_project(&app, &alice_key, "alice-secret").await;

    let (status, _body) = get_as(&app, "/projects", &carol_key, alice_uid).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "act-as without a grant must be 403"
    );
}

/// SD1c: acting as yourself is always allowed and resolves your own shard,
/// regardless of any grant. The act-as header naming your own id is a no-op.
#[tokio::test]
async fn sd1c_act_as_self_is_noop() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;

    make_project(&app, &alice_key, "alice-own").await;

    let (status, body) = get_as(&app, "/projects", &alice_key, alice_uid).await;
    assert!(
        status.is_success(),
        "act-as self must succeed: {status} {body}"
    );
    assert!(project_names(&body).contains(&"alice-own".to_string()));
}

/// SD2: a non-owner, non-admin cannot create a grant on another user's
/// instance, and the attempt writes nothing (the caller still cannot act-as).
#[tokio::test]
async fn sd2_non_owner_cannot_grant() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;

    make_project(&app, &alice_key, "alice-secret").await;

    // Bob tries to grant himself write access to alice's instance.
    let (status, _body) = post(
        &app,
        "/instance-grants",
        &bob_key,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "write" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-owner grant attempt must be 403"
    );

    // No grant was written: bob still cannot act as alice.
    let (status, _body) = get_as(&app, "/projects", &bob_key, alice_uid).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "self-service escalation must not have created a grant"
    );
}

/// SD3: a read grant conveys read only. A read-grantee cannot write into the
/// owner's shard; a write grant is required.
#[tokio::test]
async fn sd3_read_grant_cannot_write() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;

    // Bob gets a read grant on alice.
    let (status, _b) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success());

    // Read grant: a write (POST) acting as alice is forbidden.
    let (status, _b) = post_as(
        &app,
        "/projects",
        &bob_key,
        alice_uid,
        json!({ "name": "bob-injected", "status": "active" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "read grant must not authorize writes"
    );

    // Upgrade bob to a write grant; now the write succeeds and lands in alice's shard.
    let (status, _b) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "write" }),
    )
    .await;
    assert!(status.is_success());

    let (status, body) = post_as(
        &app,
        "/projects",
        &bob_key,
        alice_uid,
        json!({ "name": "bob-collab", "status": "active" }),
    )
    .await;
    assert!(
        status.is_success(),
        "write grant must allow writes: {status} {body}"
    );

    // The row landed in alice's shard, not bob's.
    let (_s, body) = get(&app, "/projects", &alice_key).await;
    assert!(
        project_names(&body).contains(&"bob-collab".to_string()),
        "write by grantee must persist in the owner's shard: {body}"
    );
}

/// SD4: an Admin may act as any user (god-mode) with no grant required.
#[tokio::test]
async fn sd4_admin_act_as_any_user() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;

    make_project(&app, &alice_key, "alice-secret").await;

    let (status, body) = get_as(&app, "/projects", &admin, alice_uid).await;
    assert!(status.is_success(), "admin act-as alice: {status} {body}");
    assert!(
        project_names(&body).contains(&"alice-secret".to_string()),
        "admin god-mode must see any user's data: {body}"
    );
}

/// SD6: a grant is scoped to a single owner. A grant to one owner does not let
/// the grantee act as a different owner.
#[tokio::test]
async fn sd6_grant_is_scoped_to_owner() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, _alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;
    let (dave_uid, dave_key) = seed_user(&app, &admin, "dave").await;

    make_project(&app, &dave_key, "dave-secret").await;

    // Bob is granted read on alice only.
    let (status, _b) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success());

    // Bob's alice-grant does not extend to dave.
    let (status, _b) = get_as(&app, "/projects", &bob_key, dave_uid).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a grant for one owner must not authorize acting as another"
    );
}

/// Grant CRUD roundtrip: grant -> list -> revoke, and a revoked grantee loses
/// access immediately.
#[tokio::test]
async fn grant_roundtrip_and_revoke_drops_access() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;

    make_project(&app, &alice_key, "alice-secret").await;

    // Grant.
    let (status, _b) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success());

    // List shows the grant.
    let (status, body) = get(&app, &format!("/instance-grants?owner={alice_uid}"), &admin).await;
    assert!(status.is_success(), "list grants: {status} {body}");
    let grantees: Vec<i64> = body["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|g| g["grantee_user_id"].as_i64())
        .collect();
    assert!(grantees.contains(&bob_uid), "grant must be listed: {body}");

    // Bob can act as alice.
    let (status, _b) = get_as(&app, "/projects", &bob_key, alice_uid).await;
    assert!(status.is_success());

    // Revoke.
    let (status, _b) = common::delete(
        &app,
        &format!("/instance-grants/{alice_uid}/{bob_uid}"),
        &admin,
    )
    .await;
    assert!(status.is_success(), "revoke: {status}");

    // Access is gone immediately.
    let (status, _b) = get_as(&app, "/projects", &bob_key, alice_uid).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "revoked grantee must lose access immediately"
    );
}

/// An owner (non-admin) may self-manage grants on their own shard.
#[tokio::test]
async fn owner_can_self_manage_grants() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;

    make_project(&app, &alice_key, "alice-secret").await;

    // Alice (owner, non-admin) grants bob read on her own instance.
    let (status, body) = post(
        &app,
        "/instance-grants",
        &alice_key,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success(), "owner self-grant: {status} {body}");

    let (status, body) = get_as(&app, "/projects", &bob_key, alice_uid).await;
    assert!(
        status.is_success(),
        "grantee read after owner grant: {status} {body}"
    );
    assert!(project_names(&body).contains(&"alice-secret".to_string()));
}

/// A malformed act-as header is a client error, not a silent self-resolution.
#[tokio::test]
async fn malformed_act_as_header_is_bad_request() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (_alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;

    let (status, _b) = get_as_raw(&app, "/projects", &alice_key, "not-a-number").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-integer act-as header must be rejected"
    );
}

/// Rollout coverage: the act-as chokepoint surfaces the owner's MEMORIES, not
/// just projects -- confirms effective_user_id() adoption in the memory routes.
#[tokio::test]
async fn act_as_surfaces_owner_memories() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, bob_key) = seed_user(&app, &admin, "bob").await;

    // Alice stores a private memory in her shard.
    let (status, _b) = post(
        &app,
        "/store",
        &alice_key,
        json!({ "content": "alice-memory-secret", "category": "test" }),
    )
    .await;
    assert!(status.is_success(), "alice store memory: {status}");

    // Admin grants bob read on alice's instance.
    let (status, _b) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success());

    // Bob, acting as alice, reads alice's memory.
    let (status, body) = get_as(&app, "/list", &bob_key, alice_uid).await;
    assert!(
        status.is_success(),
        "bob act-as alice /list: {status} {body}"
    );
    let contents: Vec<String> = body["results"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["content"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        contents.contains(&"alice-memory-secret".to_string()),
        "read grant must surface owner's memory under act-as: {body}"
    );

    // Without a grant, a third user cannot read alice's memories.
    let (_carol_uid, carol_key) = seed_user(&app, &admin, "carol").await;
    let (status, _b) = get_as(&app, "/list", &carol_key, alice_uid).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no grant must be 403 on memory act-as"
    );
}

/// GET /me reports the caller's real identity and scopes so the GUI can gate
/// admin-only surfaces. Admin keys report is_admin true; others false.
#[tokio::test]
async fn me_reports_caller_scopes() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (_uid, user_key) = seed_user(&app, &admin, "alice").await;

    let (status, body) = get(&app, "/me", &admin).await;
    assert!(status.is_success(), "admin /me: {status} {body}");
    assert_eq!(
        body["is_admin"], true,
        "admin key must report is_admin: {body}"
    );

    let (status, body) = get(&app, "/me", &user_key).await;
    assert!(status.is_success(), "user /me: {status} {body}");
    assert_eq!(
        body["is_admin"], false,
        "non-admin must report is_admin false: {body}"
    );
    let scopes = body["scopes"].as_array().expect("scopes array");
    assert!(
        scopes.iter().any(|s| s == "write"),
        "seeded user has read,write scopes: {body}"
    );
}

/// The admin overview endpoints list every grant and every space across all
/// users with usernames resolved, and reject non-admins.
#[tokio::test]
async fn admin_overviews_list_all() {
    let (app, _state, _tmp) = test_app_with_sharding().await;
    let admin = bootstrap_admin_key(&app).await;
    let (alice_uid, alice_key) = seed_user(&app, &admin, "alice").await;
    let (bob_uid, _bob_key) = seed_user(&app, &admin, "bob").await;

    let (status, _b) = post(
        &app,
        "/spaces",
        &alice_key,
        json!({ "name": "alice-space" }),
    )
    .await;
    assert!(status.is_success(), "create space: {status}");
    let (status, _b) = post(
        &app,
        "/instance-grants",
        &admin,
        json!({ "owner_user_id": alice_uid, "grantee_user_id": bob_uid, "access": "read" }),
    )
    .await;
    assert!(status.is_success());

    // All grants, with usernames.
    let (status, body) = get(&app, "/sharing/grants", &admin).await;
    assert!(status.is_success(), "admin grants: {status} {body}");
    assert!(
        body["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["owner_username"] == "alice" && g["grantee_username"] == "bob"),
        "grant overview must resolve usernames: {body}"
    );

    // All spaces, with owner username.
    let (status, body) = get(&app, "/sharing/spaces", &admin).await;
    assert!(status.is_success(), "admin spaces: {status} {body}");
    assert!(
        body["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["owner_username"] == "alice" && s["name"] == "alice-space"),
        "space overview must resolve owner username: {body}"
    );

    // Non-admins are rejected.
    let (status, _b) = get(&app, "/sharing/grants", &alice_key).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin overview must be 403"
    );
}
