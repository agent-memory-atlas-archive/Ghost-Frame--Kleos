// Portability routes: export, import (auto-detect), state, preferences

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query},
    http::{header, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use rusqlite::params;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::AppError,
    extractors::{Auth, ResolvedDb},
    state::AppState,
};
use kleos_lib::db::Database;

/// Routes for export/import portability plus current-state and preference CRUD.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/export", get(export_handler))
        .route("/import", axum::routing::post(import_handler))
        // NOTE: /import/mem0 is in ingestion.rs to avoid duplicate routes
        .route(
            "/state",
            get(get_state_handler).delete(delete_state_handler),
        )
        .route(
            "/preferences",
            get(list_preferences_handler)
                .put(put_preferences_handler)
                .delete(delete_all_preferences_handler),
        )
        .route(
            "/preferences/{key}",
            get(get_preference_handler).delete(delete_preference_handler),
        )
}

// --- Export ---

// DOS-L2: stream export as NDJSON so large user datasets don't require
// buffering the entire response as a single JSON blob. One JSON object per
// line; clients can parse records as they arrive.
async fn export_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
) -> Result<Response, AppError> {
    let (sender, receiver) = tokio::sync::mpsc::channel::<String>(16);
    let error_sender = sender.clone();
    let user_id = auth.effective_user_id();
    tokio::spawn(async move {
        if let Err(error) = kleos_lib::admin::stream_user_data_ndjson(&db, user_id, sender).await {
            let _ = error_sender
                .send(json!({ "type": "error", "message": error.to_string() }).to_string() + "\n")
                .await;
        }
    });
    let stream = futures::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|line| {
            (
                Ok::<Bytes, std::convert::Infallible>(Bytes::from(line)),
                receiver,
            )
        })
    });

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(stream))
        .unwrap())
}

// --- Import (auto-detect format) ---

/// Cap on per-request import error messages echoed back to the caller.
const MAX_REPORTED_ERRORS: usize = 5;

/// Maximum number of typed records accepted in one version 2 import.
const MAX_V2_RECORDS: usize = 100_000;

/// Build the import response. Any failed write makes the status 207
/// Multi-Status so callers can detect partial or total data loss instead of
/// reading an unconditional 200; `skipped` counts only rows intentionally
/// ignored (empty content), never failures.
fn import_response(
    format: &str,
    imported: i64,
    skipped: i64,
    failed: i64,
    errors: Vec<String>,
) -> (StatusCode, Json<Value>) {
    let status = if failed > 0 {
        StatusCode::MULTI_STATUS
    } else {
        StatusCode::OK
    };
    (
        status,
        Json(json!({
            "imported": imported,
            "skipped": skipped,
            "failed": failed,
            "errors": errors,
            "format": format,
            "warnings": match format {
                "kleos" | "kleos-ndjson-v1" => vec!["legacy Kleos imports memories only; recognized non-memory sections are not portable in this format"],
                "mem0" => vec!["mem0 import preserves memory text and limited metadata only"],
                "array" => vec!["plain array import preserves memory text and limited metadata only"],
                _ => Vec::<&str>::new(),
            },
        })),
    )
}

/// POST /import: auto-detects the payload format (kleos export, mem0, plain
/// array) and inserts the rows for the caller. Returns 207 when any write
/// failed (see `import_response`).
async fn import_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let parsed = parse_import_body(&body)?;
    let (body, legacy_ndjson) = match parsed {
        ParsedImport::Json(body) => (body, false),
        ParsedImport::LegacyNdjson(body) => (Value::Object(body), true),
        ParsedImport::VerifiedV2(body) => {
            return import_kleos_v2(&db, auth.effective_user_id(), &body).await;
        }
    };
    // Auto-detect format based on shape
    if body.is_array() {
        let arr = body.as_array().ok_or_else(|| {
            AppError(kleos_lib::EngError::InvalidInput(
                "expected JSON array".into(),
            ))
        })?;
        return import_array(&db, auth.effective_user_id(), arr).await;
    }
    if let Some(obj) = body.as_object() {
        if obj.contains_key("memories") {
            // Kleos JSON export or generic format with memories key
            let version = obj.get("version").and_then(|v| v.as_str());
            if version == Some("2.0") {
                return Err(AppError(kleos_lib::EngError::InvalidInput(
                    "version 2 imports require verified NDJSON with a count trailer".into(),
                )));
            }
            if version == Some("1.0") {
                return import_kleos_export(
                    &db,
                    auth.effective_user_id(),
                    obj,
                    if legacy_ndjson {
                        "kleos-ndjson-v1"
                    } else {
                        "kleos"
                    },
                )
                .await;
            }
            if let Some(version) = version {
                return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                    "unsupported Kleos import version '{version}'"
                ))));
            }
            // mem0-style: has "memories" but no version
            if let Some(arr) = obj.get("memories").and_then(|v| v.as_array()) {
                return import_mem0_array(&db, auth.effective_user_id(), arr).await;
            }
        }
        if obj.contains_key("results") {
            if let Some(arr) = obj.get("results").and_then(|v| v.as_array()) {
                return import_mem0_array(&db, auth.effective_user_id(), arr).await;
            }
        }
        if obj.contains_key("documents") || obj.contains_key("data") {
            let items = obj
                .get("documents")
                .or_else(|| obj.get("data"))
                .and_then(|v| v.as_array());
            if let Some(arr) = items {
                return import_array(&db, auth.effective_user_id(), arr).await;
            }
        }
    }
    Err(AppError(kleos_lib::EngError::InvalidInput(
        "unrecognized import format".into(),
    )))
}

/// Parsed payload whose v2 verification state cannot be forged in JSON.
enum ParsedImport {
    /// Legacy JSON with partial import semantics.
    Json(Value),
    /// Legacy version 1 NDJSON reconstructed into recognized sections.
    LegacyNdjson(serde_json::Map<String, Value>),
    /// Version 2 NDJSON whose trailer and cap were verified locally.
    VerifiedV2(serde_json::Map<String, Value>),
}

/// Parse a legacy JSON payload or a complete versioned NDJSON stream.
fn parse_import_body(body: &[u8]) -> Result<ParsedImport, AppError> {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        return Ok(ParsedImport::Json(value));
    }
    let text = std::str::from_utf8(body).map_err(|error| {
        AppError(kleos_lib::EngError::InvalidInput(format!(
            "import body is not UTF-8: {error}"
        )))
    })?;
    let mut header: Option<serde_json::Map<String, Value>> = None;
    let mut trailer: Option<serde_json::Map<String, Value>> = None;
    let mut sections: HashMap<&'static str, Vec<Value>> = HashMap::new();
    let mut record_count = 0usize;
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if trailer.is_some() {
            return Err(AppError(kleos_lib::EngError::InvalidInput(
                "NDJSON contains data after the count trailer".into(),
            )));
        }
        let mut record = serde_json::from_str::<Value>(line).map_err(|error| {
            AppError(kleos_lib::EngError::InvalidInput(format!(
                "malformed NDJSON line {}: {error}",
                line_index + 1
            )))
        })?;
        let object = record.as_object_mut().ok_or_else(|| {
            AppError(kleos_lib::EngError::InvalidInput(format!(
                "NDJSON line {} is not an object",
                line_index + 1
            )))
        })?;
        let record_type = object
            .remove("type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| {
                AppError(kleos_lib::EngError::InvalidInput(format!(
                    "NDJSON line {} has no string type",
                    line_index + 1
                )))
            })?;
        match record_type.as_str() {
            "header" if header.is_none() && record_count == 0 => header = Some(object.clone()),
            "header" => {
                return Err(AppError(kleos_lib::EngError::InvalidInput(
                    "duplicate or misplaced NDJSON header".into(),
                )))
            }
            "trailer" => trailer = Some(object.clone()),
            "memory" | "conversation" | "episode" | "entity" | "fact" | "preference" | "skill" => {
                if header.is_none() {
                    return Err(AppError(kleos_lib::EngError::InvalidInput(
                        "NDJSON record precedes header".into(),
                    )));
                }
                record_count = record_count.checked_add(1).ok_or_else(|| {
                    AppError(kleos_lib::EngError::InvalidInput(
                        "NDJSON record count overflow".into(),
                    ))
                })?;
                if record_count > MAX_V2_RECORDS {
                    return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                        "NDJSON exceeds {MAX_V2_RECORDS} records"
                    ))));
                }
                let key = match record_type.as_str() {
                    "memory" => "memories",
                    "conversation" => "conversations",
                    "episode" => "episodes",
                    "entity" => "entities",
                    "fact" => "facts",
                    "preference" => "preferences",
                    "skill" => "skills",
                    _ => unreachable!(),
                };
                sections.entry(key).or_default().push(record);
            }
            other => {
                return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                    "unknown NDJSON record type '{other}'"
                ))));
            }
        }
    }
    let mut aggregate = header.ok_or_else(|| {
        AppError(kleos_lib::EngError::InvalidInput(
            "NDJSON header is missing".into(),
        ))
    })?;
    let version = aggregate.get("version").and_then(Value::as_str);
    if !matches!(version, Some("1.0" | "2.0")) {
        return Err(AppError(kleos_lib::EngError::InvalidInput(
            "NDJSON header version must be 1.0 or 2.0".into(),
        )));
    }
    if version == Some("1.0") {
        for plural in [
            "memories",
            "conversations",
            "episodes",
            "entities",
            "facts",
            "preferences",
            "skills",
        ] {
            aggregate.insert(
                plural.to_string(),
                Value::Array(sections.remove(plural).unwrap_or_default()),
            );
        }
        return Ok(ParsedImport::LegacyNdjson(aggregate));
    }
    let trailer = trailer.ok_or_else(|| {
        AppError(kleos_lib::EngError::InvalidInput(
            "NDJSON count trailer is missing; export may be truncated".into(),
        ))
    })?;
    let expected = trailer
        .get("counts")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            AppError(kleos_lib::EngError::InvalidInput(
                "NDJSON trailer counts are missing".into(),
            ))
        })?;
    for (singular, plural) in [
        ("memory", "memories"),
        ("conversation", "conversations"),
        ("episode", "episodes"),
        ("entity", "entities"),
        ("fact", "facts"),
        ("preference", "preferences"),
        ("skill", "skills"),
    ] {
        let records = sections.remove(plural).unwrap_or_default();
        let expected_count = expected
            .get(singular)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                AppError(kleos_lib::EngError::InvalidInput(format!(
                    "NDJSON trailer has no count for {singular}"
                )))
            })?;
        if usize::try_from(expected_count).ok() != Some(records.len()) {
            return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                "NDJSON trailer count mismatch for {singular}"
            ))));
        }
        aggregate.insert(plural.to_string(), Value::Array(records));
    }
    Ok(ParsedImport::VerifiedV2(aggregate))
}

/// Import one complete version 2 logical export in a single transaction.
async fn import_kleos_v2(
    db: &Arc<Database>,
    user_id: i64,
    obj: &serde_json::Map<String, Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let allowed: HashSet<&str> = [
        "version",
        "exported_at",
        "user_id",
        "memories",
        "conversations",
        "episodes",
        "entities",
        "facts",
        "preferences",
        "skills",
    ]
    .into_iter()
    .collect();
    if let Some(key) = obj.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
            "unknown version 2 section '{key}'"
        ))));
    }

    let memories = import_section(obj, "memories")?;
    let conversations = import_section(obj, "conversations")?;
    let episodes = import_section(obj, "episodes")?;
    let entities = import_section(obj, "entities")?;
    let facts = import_section(obj, "facts")?;
    let preferences = import_section(obj, "preferences")?;
    let skills = import_section(obj, "skills")?;
    for (name, records) in [
        ("memories", &memories),
        ("conversations", &conversations),
        ("episodes", &episodes),
        ("entities", &entities),
        ("facts", &facts),
        ("preferences", &preferences),
        ("skills", &skills),
    ] {
        validate_unique_source_ids(name, records)?;
    }
    let memory_ids: HashSet<i64> = memories
        .iter()
        .map(import_record_id)
        .collect::<Result<_, _>>()?;
    for fact in &facts {
        if let Some(source_memory_id) = optional_i64(fact, "memory_id")? {
            if memory_ids.contains(&source_memory_id) {
                continue;
            }
            return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                "fact references unresolved memory id {source_memory_id}"
            ))));
        }
    }
    for preference in &preferences {
        if let Some(source_memory_id) = optional_i64(preference, "evidence_memory_id")? {
            if !memory_ids.contains(&source_memory_id) {
                return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                    "preference references unresolved memory id {source_memory_id}"
                ))));
            }
        }
    }

    let counts = db
        .transaction(move |tx| {
            let mut memory_map = HashMap::with_capacity(memories.len());
            for record in &memories {
                let source_id = import_record_id(record)?;
                let content = required_string(record, "content")?;
                let category = string_or(record, "category", "general")?;
                let source = string_or(record, "source", "import")?;
                let importance = i64_or(record, "importance", 5)?;
                let tags = optional_string(record, "tags")?;
                let session_id = optional_string(record, "session_id")?;
                let version = i64_or(record, "version", 1)?;
                let source_count = i64_or(record, "source_count", 1)?;
                let is_static = i64_or(record, "is_static", 0)?;
                let model = optional_string(record, "model")?;
                let confidence = f64_or(record, "confidence", 1.0)?;
                let status = string_or(record, "status", "approved")?;
                let created_at = string_or(record, "created_at", "1970-01-01 00:00:00")?;
                let updated_at = string_or(record, "updated_at", &created_at)?;
                let is_archived = i64_or(record, "is_archived", 0)?;
                let sync_id = Uuid::new_v4().to_string();
                let new_id = tx.query_row(
                    "INSERT INTO memories
                     (user_id, content, category, source, importance, tags, session_id, version,
                      source_count, is_static, model, confidence, status, created_at, updated_at,
                      is_archived, sync_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                             ?14, ?15, ?16, ?17) RETURNING id",
                    params![
                        user_id,
                        content,
                        category,
                        source,
                        importance,
                        tags,
                        session_id,
                        version,
                        source_count,
                        is_static,
                        model,
                        confidence,
                        status,
                        created_at,
                        updated_at,
                        is_archived,
                        sync_id
                    ],
                    |row| row.get::<_, i64>(0),
                )?;
                memory_map.insert(source_id, new_id);
            }

            for record in &conversations {
                tx.execute(
                    "INSERT INTO conversations
                     (user_id, session_id, agent, title, metadata, started_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        user_id,
                        optional_string(record, "session_id")?,
                        string_or(record, "agent", "import")?,
                        optional_string(record, "title")?,
                        optional_string(record, "metadata")?,
                        string_or(record, "started_at", "1970-01-01 00:00:00")?,
                        string_or(record, "updated_at", "1970-01-01 00:00:00")?,
                    ],
                )?;
            }

            for record in &episodes {
                tx.execute(
                    "INSERT INTO episodes
                     (user_id, title, summary, session_id, agent, memory_count, duration_seconds,
                      started_at, ended_at, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        user_id,
                        optional_string(record, "title")?,
                        optional_string(record, "summary")?,
                        optional_string(record, "session_id")?,
                        optional_string(record, "agent")?,
                        i64_or(record, "memory_count", 0)?,
                        optional_i64(record, "duration_seconds")?,
                        string_or(record, "started_at", "1970-01-01 00:00:00")?,
                        optional_string(record, "ended_at")?,
                        string_or(record, "created_at", "1970-01-01 00:00:00")?,
                    ],
                )?;
            }

            for record in &entities {
                tx.execute(
                    "INSERT INTO entities
                     (user_id, name, entity_type, description, aliases, aka, metadata, confidence,
                      occurrence_count, first_seen_at, last_seen_at, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                     ON CONFLICT(name, entity_type, user_id) DO UPDATE SET
                       description=excluded.description, aliases=excluded.aliases,
                       aka=excluded.aka, metadata=excluded.metadata,
                       confidence=excluded.confidence,
                       occurrence_count=excluded.occurrence_count,
                       first_seen_at=excluded.first_seen_at,
                       last_seen_at=excluded.last_seen_at,
                       updated_at=excluded.updated_at",
                    params![
                        user_id,
                        required_string(record, "name")?,
                        string_or(record, "entity_type", "concept")?,
                        optional_string(record, "description")?,
                        optional_string(record, "aliases")?,
                        optional_string(record, "aka")?,
                        optional_string(record, "metadata")?,
                        f64_or(record, "confidence", 1.0)?,
                        i64_or(record, "occurrence_count", 1)?,
                        string_or(record, "first_seen_at", "1970-01-01 00:00:00")?,
                        string_or(record, "last_seen_at", "1970-01-01 00:00:00")?,
                        string_or(record, "created_at", "1970-01-01 00:00:00")?,
                        string_or(record, "updated_at", "1970-01-01 00:00:00")?,
                    ],
                )?;
            }

            for record in &facts {
                let memory_id = optional_i64(record, "memory_id")?
                    .map(|source_memory_id| {
                        memory_map.get(&source_memory_id).copied().ok_or_else(|| {
                            kleos_lib::EngError::InvalidInput(format!(
                                "fact references unresolved memory id {source_memory_id}"
                            ))
                        })
                    })
                    .transpose()?;
                tx.execute(
                    "INSERT INTO structured_facts
                     (user_id, memory_id, subject, predicate, object, verb, quantity, unit,
                      date_ref, date_approx, location, context, valid_at, invalid_at,
                      confidence, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                             ?14, ?15, ?16)",
                    params![
                        user_id,
                        memory_id,
                        required_string(record, "subject")?,
                        required_string(record, "predicate")?,
                        required_string(record, "object")?,
                        string_or(record, "verb", "")?,
                        optional_f64(record, "quantity")?,
                        optional_string(record, "unit")?,
                        optional_string(record, "date_ref")?,
                        optional_string(record, "date_approx")?,
                        optional_string(record, "location")?,
                        optional_string(record, "context")?,
                        optional_string(record, "valid_at")?,
                        optional_string(record, "invalid_at")?,
                        f64_or(record, "confidence", 1.0)?,
                        string_or(record, "created_at", "1970-01-01 00:00:00")?,
                    ],
                )?;
            }

            for record in &preferences {
                let evidence_memory_id = optional_i64(record, "evidence_memory_id")?
                    .and_then(|source_id| memory_map.get(&source_id).copied());
                tx.execute(
                    "INSERT INTO user_preferences
                     (user_id, key, value, domain, preference, strength, evidence_memory_id,
                      created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(user_id, key) DO UPDATE SET
                       value=excluded.value, domain=excluded.domain,
                       preference=excluded.preference, strength=excluded.strength,
                       evidence_memory_id=excluded.evidence_memory_id,
                       updated_at=excluded.updated_at",
                    params![
                        user_id,
                        required_string(record, "key")?,
                        required_string(record, "value")?,
                        optional_string(record, "domain")?,
                        optional_string(record, "preference")?,
                        f64_or(record, "strength", 1.0)?,
                        evidence_memory_id,
                        string_or(record, "created_at", "1970-01-01 00:00:00")?,
                        string_or(record, "updated_at", "1970-01-01 00:00:00")?,
                    ],
                )?;
            }

            for record in &skills {
                let imported_skill_id = format!("imported-{}", Uuid::new_v4());
                tx.execute(
                    "INSERT INTO skill_records
                     (user_id, skill_id, name, agent, description, code, content, category, origin,
                      generation, language, version, trust_score, is_active, is_deprecated,
                      visibility, metadata, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                             ?14, ?15, ?16, ?17, ?18, ?19)
                     ON CONFLICT(name, agent, version, user_id) DO UPDATE SET
                       description=excluded.description, code=excluded.code,
                       content=excluded.content, category=excluded.category,
                       origin=excluded.origin, generation=excluded.generation,
                       language=excluded.language, trust_score=excluded.trust_score,
                       is_active=excluded.is_active, is_deprecated=excluded.is_deprecated,
                       visibility=excluded.visibility, metadata=excluded.metadata,
                       updated_at=excluded.updated_at",
                    params![
                        user_id,
                        imported_skill_id,
                        required_string(record, "name")?,
                        string_or(record, "agent", "import")?,
                        optional_string(record, "description")?,
                        required_string(record, "code")?,
                        string_or(record, "content", "")?,
                        string_or(record, "category", "workflow")?,
                        string_or(record, "origin", "imported")?,
                        i64_or(record, "generation", 0)?,
                        string_or(record, "language", "javascript")?,
                        i64_or(record, "version", 1)?,
                        f64_or(record, "trust_score", 50.0)?,
                        i64_or(record, "is_active", 1)?,
                        i64_or(record, "is_deprecated", 0)?,
                        string_or(record, "visibility", "private")?,
                        optional_string(record, "metadata")?,
                        string_or(record, "created_at", "1970-01-01 00:00:00")?,
                        string_or(record, "updated_at", "1970-01-01 00:00:00")?,
                    ],
                )?;
            }

            Ok(json!({
                "memory": memories.len(),
                "conversation": conversations.len(),
                "episode": episodes.len(),
                "entity": entities.len(),
                "fact": facts.len(),
                "preference": preferences.len(),
                "skill": skills.len(),
            }))
        })
        .await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "format": "kleos-ndjson",
            "version": "2.0",
            "counts": counts,
            "warnings": [],
        })),
    ))
}

/// Clone one required version 2 section as an array of record objects.
fn import_section(
    obj: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<Value>, AppError> {
    let records = obj.get(name).and_then(Value::as_array).ok_or_else(|| {
        AppError(kleos_lib::EngError::InvalidInput(format!(
            "version 2 section '{name}' must be an array"
        )))
    })?;
    if records.iter().any(|record| !record.is_object()) {
        return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
            "version 2 section '{name}' contains a non-object record"
        ))));
    }
    Ok(records.clone())
}

/// Reject duplicate source IDs before any version 2 write starts.
fn validate_unique_source_ids(section: &str, records: &[Value]) -> Result<(), AppError> {
    let mut ids = HashSet::with_capacity(records.len());
    for record in records {
        let id = import_record_id(record).map_err(AppError)?;
        if !ids.insert(id) {
            return Err(AppError(kleos_lib::EngError::InvalidInput(format!(
                "duplicate source id {id} in section '{section}'"
            ))));
        }
    }
    Ok(())
}

/// Read the required integer source ID from one portable record.
fn import_record_id(record: &Value) -> kleos_lib::Result<i64> {
    required_i64(record, "id")
}

/// Read a required string field from one portable record.
fn required_string(record: &Value, key: &str) -> kleos_lib::Result<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            kleos_lib::EngError::InvalidInput(format!("record field '{key}' must be a string"))
        })
}

/// Read an optional nullable string field from one portable record.
fn optional_string(record: &Value, key: &str) -> kleos_lib::Result<Option<String>> {
    match record.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(kleos_lib::EngError::InvalidInput(format!(
            "record field '{key}' must be a string or null"
        ))),
    }
}

/// Read a string field or use a stable default when absent or null.
fn string_or(record: &Value, key: &str, default: &str) -> kleos_lib::Result<String> {
    Ok(optional_string(record, key)?.unwrap_or_else(|| default.to_string()))
}

/// Read a required integer field from one portable record.
fn required_i64(record: &Value, key: &str) -> kleos_lib::Result<i64> {
    record.get(key).and_then(Value::as_i64).ok_or_else(|| {
        kleos_lib::EngError::InvalidInput(format!("record field '{key}' must be an integer"))
    })
}

/// Read an optional nullable integer field from one portable record.
fn optional_i64(record: &Value, key: &str) -> kleos_lib::Result<Option<i64>> {
    match record.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            kleos_lib::EngError::InvalidInput(format!(
                "record field '{key}' must be an integer or null"
            ))
        }),
    }
}

/// Read an integer field or use a stable default when absent or null.
fn i64_or(record: &Value, key: &str, default: i64) -> kleos_lib::Result<i64> {
    Ok(optional_i64(record, key)?.unwrap_or(default))
}

/// Read an optional nullable floating-point field from one portable record.
fn optional_f64(record: &Value, key: &str) -> kleos_lib::Result<Option<f64>> {
    match record.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_f64().map(Some).ok_or_else(|| {
            kleos_lib::EngError::InvalidInput(format!(
                "record field '{key}' must be numeric or null"
            ))
        }),
    }
}

/// Read a floating-point field or use a stable default when absent or null.
fn f64_or(record: &Value, key: &str, default: f64) -> kleos_lib::Result<f64> {
    Ok(optional_f64(record, key)?.unwrap_or(default))
}

/// Import a versioned Kleos JSON export's memories array.
async fn import_kleos_export(
    db: &Arc<Database>,
    user_id: i64,
    obj: &serde_json::Map<String, Value>,
    format: &str,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let mut imported = 0i64;
    let mut skipped = 0i64;
    let mut failed = 0i64;
    let mut errors: Vec<String> = Vec::new();
    if let Some(memories) = obj.get("memories").and_then(|v| v.as_array()) {
        for mem in memories {
            let content = mem
                .get("content")
                .or_else(|| mem.get("col_1"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            let content = match content.filter(|c| !c.is_empty()) {
                Some(c) => c,
                None => {
                    skipped += 1;
                    continue;
                }
            };
            let category = mem
                .get("category")
                .or_else(|| mem.get("col_2"))
                .and_then(|v| v.as_str())
                .unwrap_or("general")
                .to_string();
            let source = mem
                .get("source")
                .or_else(|| mem.get("col_3"))
                .and_then(|v| v.as_str())
                .unwrap_or("import")
                .to_string();
            let importance = mem
                .get("importance")
                .or_else(|| mem.get("col_4"))
                .and_then(|v| v.as_i64())
                .unwrap_or(5) as i32;
            let sync_id = Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();
            let created_at = mem
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or(&now)
                .to_string();
            let updated_at = mem
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or(&now)
                .to_string();
            match db.write(move |conn| {
                conn.execute(
                    "INSERT INTO memories (user_id, content, category, source, importance, sync_id, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![user_id, content, category, source, importance, sync_id, created_at, updated_at],
                ).map_err(|e| kleos_lib::EngError::Internal(e.to_string()))
            }).await {
                Ok(_) => imported += 1,
                Err(e) => {
                    tracing::warn!("import_kleos_memory_failed: {}", e);
                    if errors.len() < MAX_REPORTED_ERRORS {
                        errors.push(e.to_string());
                    }
                    failed += 1;
                }
            }
        }
    }
    Ok(import_response(format, imported, skipped, failed, errors))
}

/// Import a plain JSON array of objects carrying content/text/memory fields.
async fn import_array(
    db: &Arc<Database>,
    user_id: i64,
    arr: &[Value],
) -> Result<(StatusCode, Json<Value>), AppError> {
    let mut imported = 0i64;
    let mut skipped = 0i64;
    let mut failed = 0i64;
    let mut errors: Vec<String> = Vec::new();
    for item in arr {
        let content = item
            .get("content")
            .or_else(|| item.get("text"))
            .or_else(|| item.get("memory"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let content = match content.filter(|c| !c.is_empty()) {
            Some(c) => c,
            None => {
                skipped += 1;
                continue;
            }
        };
        let category = item
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_string();
        let source = item
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("import")
            .to_string();
        let importance = item.get("importance").and_then(|v| v.as_i64()).unwrap_or(5) as i32;
        let sync_id = Uuid::new_v4().to_string();
        match db.write(move |conn| {
            conn.execute(
                "INSERT INTO memories (user_id, content, category, source, importance, sync_id, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'), datetime('now'))",
                params![user_id, content, category, source, importance, sync_id],
            ).map_err(|e| kleos_lib::EngError::Internal(e.to_string()))
        }).await {
            Ok(_) => imported += 1,
            Err(e) => {
                tracing::warn!("import_array_write_failed: {}", e);
                if errors.len() < MAX_REPORTED_ERRORS {
                    errors.push(e.to_string());
                }
                failed += 1;
            }
        }
    }
    Ok(import_response("array", imported, skipped, failed, errors))
}

/// Import a mem0-style array (memory/text/content + optional metadata).
async fn import_mem0_array(
    db: &Arc<Database>,
    user_id: i64,
    arr: &[Value],
) -> Result<(StatusCode, Json<Value>), AppError> {
    let mut imported = 0i64;
    let mut skipped = 0i64;
    let mut failed = 0i64;
    let mut errors: Vec<String> = Vec::new();
    for mem in arr {
        let content = mem
            .get("memory")
            .or_else(|| mem.get("text"))
            .or_else(|| mem.get("content"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let content = match content.filter(|c| !c.is_empty()) {
            Some(c) => c,
            None => {
                skipped += 1;
                continue;
            }
        };
        let meta = mem.get("metadata").and_then(|m| m.as_object());
        let category = meta
            .and_then(|m| m.get("category"))
            .and_then(|v| v.as_str())
            .or_else(|| mem.get("category").and_then(|v| v.as_str()))
            .unwrap_or("general")
            .to_string();
        let source = meta
            .and_then(|m| m.get("source"))
            .and_then(|v| v.as_str())
            .or_else(|| mem.get("source").and_then(|v| v.as_str()))
            .unwrap_or("mem0-import")
            .to_string();
        let importance = meta
            .and_then(|m| m.get("importance"))
            .and_then(|v| v.as_i64())
            .unwrap_or(5) as i32;
        let sync_id = Uuid::new_v4().to_string();
        match db.write(move |conn| {
            conn.execute(
                "INSERT INTO memories (user_id, content, category, source, importance, sync_id, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'), datetime('now'))",
                params![user_id, content, category, source, importance, sync_id],
            ).map_err(|e| kleos_lib::EngError::Internal(e.to_string()))
        }).await {
            Ok(_) => imported += 1,
            Err(e) => {
                tracing::warn!("import_mem0_write_failed: {}", e);
                if errors.len() < MAX_REPORTED_ERRORS {
                    errors.push(e.to_string());
                }
                failed += 1;
            }
        }
    }
    Ok(import_response("mem0", imported, skipped, failed, errors))
}

// --- State ---

async fn get_state_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
    Query(params): Query<GetStateQuery>,
) -> Result<Json<Value>, AppError> {
    let prefix = format!("user:{}:", auth.effective_user_id());
    let prefix_len = prefix.len();
    let filter_key = params.key.clone();

    let user_state: serde_json::Map<String, Value> = db
        .read(move |conn| {
            if let Some(key) = &filter_key {
                let full_key = format!("{}{}", prefix, key);
                let mut stmt = conn
                    .prepare("SELECT key, value FROM app_state WHERE key = ?1")
                    .map_err(|e| kleos_lib::EngError::Internal(e.to_string()))?;
                let rows = stmt
                    .query_map(params![full_key], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(|e| kleos_lib::EngError::Internal(e.to_string()))?;
                let mut result = serde_json::Map::new();
                for row in rows {
                    let (k, v) = row.map_err(|e| kleos_lib::EngError::Internal(e.to_string()))?;
                    let short_key = k[prefix_len..].to_string();
                    result.insert(short_key, Value::String(v));
                }
                Ok(result)
            } else {
                let prefix_like = format!("{}%", prefix);
                let mut stmt = conn
                    .prepare("SELECT key, value FROM app_state WHERE key LIKE ?1 ORDER BY key")
                    .map_err(|e| kleos_lib::EngError::Internal(e.to_string()))?;
                let rows = stmt
                    .query_map(params![prefix_like], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(|e| kleos_lib::EngError::Internal(e.to_string()))?;
                let mut result = serde_json::Map::new();
                for row in rows {
                    let (k, v) = row.map_err(|e| kleos_lib::EngError::Internal(e.to_string()))?;
                    let short_key = k[prefix_len..].to_string();
                    result.insert(short_key, Value::String(v));
                }
                Ok(result)
            }
        })
        .await
        .map_err(AppError)?;
    Ok(Json(json!({ "state": user_state })))
}

#[derive(Debug, serde::Deserialize)]
/// Query params for GET /state (optional key filter).
struct GetStateQuery {
    key: Option<String>,
}

/// DELETE /state: remove the caller's current-state rows (optionally by key).
async fn delete_state_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
) -> Result<Json<Value>, AppError> {
    let prefix = format!("user:{}:%", auth.effective_user_id());
    let affected = db
        .write(move |conn| {
            conn.execute("DELETE FROM app_state WHERE key LIKE ?1", params![prefix])
                .map_err(|e| kleos_lib::EngError::Internal(e.to_string()))
        })
        .await
        .map_err(AppError)? as i64;
    Ok(Json(json!({ "deleted": affected })))
}

// --- Preferences ---

async fn list_preferences_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
) -> Result<Json<Value>, AppError> {
    let prefs = kleos_lib::preferences::list_preferences(&db, auth.effective_user_id()).await?;
    let count = prefs.len();
    let items = serde_json::to_value(prefs)
        .map_err(|e| AppError(kleos_lib::EngError::Internal(e.to_string())))?;
    Ok(Json(json!({ "items": items, "count": count })))
}

/// GET /preferences/{key}: fetch one preference for the caller.
async fn get_preference_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
    Path(key): Path<String>,
) -> Result<Json<Value>, AppError> {
    let pref = kleos_lib::preferences::get_preference(&db, auth.effective_user_id(), &key).await?;
    Ok(Json(serde_json::to_value(pref).map_err(|e| {
        AppError(kleos_lib::EngError::Internal(e.to_string()))
    })?))
}

/// PUT /preferences: upsert the caller's preferences from a JSON object.
async fn put_preferences_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
    Json(body): Json<serde_json::Map<String, Value>>,
) -> Result<Json<Value>, AppError> {
    let mut updated = 0i64;
    for (key, val) in &body {
        let v = val
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| val.to_string());
        kleos_lib::preferences::set_preference(&db, auth.effective_user_id(), key, &v).await?;
        updated += 1;
    }
    Ok(Json(json!({ "updated": updated })))
}

/// DELETE /preferences: remove every preference for the caller.
async fn delete_all_preferences_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
) -> Result<Json<Value>, AppError> {
    let deleted =
        kleos_lib::preferences::delete_all_preferences(&db, auth.effective_user_id()).await?;
    Ok(Json(json!({ "deleted": deleted })))
}

/// DELETE /preferences/{key}: remove one preference for the caller.
async fn delete_preference_handler(
    Auth(auth): Auth,
    ResolvedDb(db): ResolvedDb,
    Path(key): Path<String>,
) -> Result<Json<Value>, AppError> {
    kleos_lib::preferences::delete_preference(&db, auth.effective_user_id(), &key).await?;
    Ok(Json(json!({ "deleted": true, "key": key })))
}

#[cfg(test)]
/// Tests for the import helpers' loss accounting: skipped counts only
/// intentionally ignored rows, failed writes surface as 207 Multi-Status.
mod tests {
    use super::*;

    /// Encode a library export with the same header, typed records, and
    /// count trailer emitted by the HTTP export route.
    fn export_as_ndjson(data: &kleos_lib::admin::types::UserExport) -> Vec<u8> {
        let mut lines = vec![json!({
            "type": "header",
            "version": data.version,
            "exported_at": data.exported_at,
            "user_id": data.user_id,
        })
        .to_string()];
        for (record_type, records) in [
            ("memory", &data.memories),
            ("conversation", &data.conversations),
            ("episode", &data.episodes),
            ("entity", &data.entities),
            ("fact", &data.facts),
            ("preference", &data.preferences),
            ("skill", &data.skills),
        ] {
            for record in records {
                let mut record = record.clone();
                record
                    .as_object_mut()
                    .expect("exported row is an object")
                    .insert("type".into(), Value::String(record_type.into()));
                lines.push(record.to_string());
            }
        }
        lines.push(
            json!({
                "type": "trailer",
                "counts": {
                    "memory": data.memories.len(),
                    "conversation": data.conversations.len(),
                    "episode": data.episodes.len(),
                    "entity": data.entities.len(),
                    "fact": data.facts.len(),
                    "preference": data.preferences.len(),
                    "skill": data.skills.len(),
                }
            })
            .to_string(),
        );
        (lines.join("\n") + "\n").into_bytes()
    }

    /// Parse a test export and require the locally verified v2 variant.
    fn verified_v2(bytes: &[u8]) -> serde_json::Map<String, Value> {
        match parse_import_body(bytes).expect("parse export") {
            ParsedImport::VerifiedV2(object) => object,
            _ => panic!("expected verified v2 NDJSON"),
        }
    }

    /// Seed one portable row in every advertised section and return its
    /// consistent-snapshot export.
    async fn complete_export() -> kleos_lib::admin::types::UserExport {
        let db = kleos_lib::db::Database::connect_memory()
            .await
            .expect("source db");
        db.transaction(|tx| {
            let memory_id = tx.query_row(
                "INSERT INTO memories
                 (user_id, content, category, source, importance, tags, session_id,
                  version, source_count, is_static, model, confidence, status,
                  created_at, updated_at, is_archived, sync_id)
                 VALUES (1, 'héllo 世界', 'note', 'test', 8, '[\"unicode\"]',
                         'session-one', 3, 2, 1, 'model-a', 0.75, 'pending',
                         '2026-01-02T03:04:05Z', '2026-01-03T03:04:05Z', 0, 'source-sync')
                 RETURNING id",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            tx.execute(
                "INSERT INTO conversations
                 (user_id, session_id, agent, title, metadata, started_at, updated_at)
                 VALUES (1, 'session-one', 'codex', '', '{}',
                         '2026-01-02T03:04:05Z', '2026-01-03T03:04:05Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO episodes
                 (user_id, title, summary, session_id, agent, memory_count,
                  duration_seconds, started_at, ended_at, created_at)
                 VALUES (1, 'Episode', '', 'session-one', 'codex', 1, 42,
                         '2026-01-02T03:04:05Z', NULL, '2026-01-03T03:04:05Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO entities
                 (user_id, name, entity_type, description, aliases, aka, metadata,
                  confidence, occurrence_count, first_seen_at, last_seen_at,
                  created_at, updated_at)
                 VALUES (1, 'Zürich', 'place', '', '[]', NULL, '{}', 0.8, 2,
                         '2026-01-02T03:04:05Z', '2026-01-03T03:04:05Z',
                         '2026-01-02T03:04:05Z', '2026-01-03T03:04:05Z')",
                [],
            )?;
            tx.execute(
                "INSERT INTO structured_facts
                 (user_id, memory_id, subject, predicate, object, verb, quantity,
                  unit, context, confidence, created_at)
                 VALUES (1, ?1, 'Zan', 'visited', 'Zürich', 'visit', 1.0,
                         'trip', '', 0.9, '2026-01-03T03:04:05Z')",
                [memory_id],
            )?;
            tx.execute(
                "INSERT INTO user_preferences
                 (user_id, key, value, domain, preference, strength,
                  evidence_memory_id, created_at, updated_at)
                 VALUES (1, 'locale', 'de-CH', 'travel', 'locale', 0.7, ?1,
                         '2026-01-02T03:04:05Z', '2026-01-03T03:04:05Z')",
                [memory_id],
            )?;
            tx.execute(
                "INSERT INTO skill_records
                 (user_id, skill_id, name, agent, description, code, content,
                  category, origin, generation, language, version, trust_score,
                  is_active, is_deprecated, visibility, metadata, created_at, updated_at)
                 VALUES (1, 'source-skill', 'portable-skill', 'codex', '',
                         'return \"héllo\";', '', 'workflow', 'learned', 2,
                         'javascript', 4, 91.0, 1, 0, 'private', '{}',
                         '2026-01-02T03:04:05Z', '2026-01-03T03:04:05Z')",
                [],
            )?;
            Ok(())
        })
        .await
        .expect("seed source");
        kleos_lib::admin::export_user_data(&db, 1)
            .await
            .expect("export source")
    }

    /// Empty-content rows are skipped, valid rows import, status stays 200.
    #[tokio::test]
    async fn import_array_counts_skips_separately_from_failures() {
        let db = Arc::new(
            kleos_lib::db::Database::connect_memory()
                .await
                .expect("in-mem db"),
        );
        let rows = vec![
            json!({ "content": "a valid imported memory" }),
            json!({ "content": "   " }),
            json!({ "note": "no content field at all" }),
        ];
        let (status, Json(body)) = import_array(&db, 1, &rows).await.expect("import ok");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["imported"], 1);
        assert_eq!(body["skipped"], 2);
        assert_eq!(body["failed"], 0);
        assert!(body["errors"].as_array().unwrap().is_empty());
    }

    /// Write failures are reported as failed + 207, never silently folded
    /// into skipped with a 200 (the silent-data-loss regression this module
    /// shipped with).
    #[tokio::test]
    async fn import_array_write_failures_return_multi_status() {
        let db = Arc::new(
            kleos_lib::db::Database::connect_memory()
                .await
                .expect("in-mem db"),
        );
        // Make every INSERT fail deterministically: move the table away.
        db.write(|conn| {
            conn.execute_batch("ALTER TABLE memories RENAME TO memories_gone;")
                .map_err(|e| kleos_lib::EngError::Internal(e.to_string()))
        })
        .await
        .expect("rename table");

        let rows = vec![
            json!({ "content": "first row that will fail to write" }),
            json!({ "content": "second row that will fail to write" }),
        ];
        let (status, Json(body)) = import_array(&db, 1, &rows).await.expect("handler returns");
        assert_eq!(status, StatusCode::MULTI_STATUS);
        assert_eq!(body["imported"], 0);
        assert_eq!(body["skipped"], 0);
        assert_eq!(body["failed"], 2);
        assert!(
            !body["errors"].as_array().unwrap().is_empty(),
            "failure messages must be surfaced to the caller"
        );
    }

    /// Version 2 carries all seven sections, remaps internal memory
    /// references, preserves review status and skill code, and overrides the
    /// exported owner with the authenticated destination owner.
    #[tokio::test]
    async fn v2_round_trip_preserves_fields_and_remaps_references() {
        let export = complete_export().await;
        assert_eq!(export.version, "2.0");
        assert_eq!(export.memories[0]["status"], "pending");
        assert_eq!(export.skills[0]["code"], "return \"héllo\";");
        let parsed = verified_v2(&export_as_ndjson(&export));
        let destination = Arc::new(
            kleos_lib::db::Database::connect_memory()
                .await
                .expect("destination db"),
        );
        let (status, Json(result)) = import_kleos_v2(&destination, 1, &parsed)
            .await
            .expect("import export");
        assert_eq!(status, StatusCode::OK);
        for section in [
            "memory",
            "conversation",
            "episode",
            "entity",
            "fact",
            "preference",
            "skill",
        ] {
            assert_eq!(result["counts"][section], 1, "section {section}");
        }
        destination
            .read(|conn| {
                let (memory_id, owner, content, status, tags): (i64, i64, String, String, String) =
                    conn.query_row(
                        "SELECT id, user_id, content, status, tags FROM memories",
                        [],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    )?;
                assert_eq!(owner, 1);
                assert_eq!(content, "héllo 世界");
                assert_eq!(status, "pending");
                assert_eq!(tags, "[\"unicode\"]");
                let fact_memory: i64 =
                    conn.query_row("SELECT memory_id FROM structured_facts", [], |row| {
                        row.get(0)
                    })?;
                let preference_memory: i64 = conn.query_row(
                    "SELECT evidence_memory_id FROM user_preferences",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(fact_memory, memory_id);
                assert_eq!(preference_memory, memory_id);
                let code: String = conn.query_row(
                    "SELECT code FROM skill_records WHERE name = 'portable-skill'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(code, "return \"héllo\";");
                Ok(())
            })
            .await
            .expect("verify destination");
    }

    /// A repeated v2 import deliberately appends event-like rows while
    /// entity, preference, and skill natural keys update their existing row.
    #[tokio::test]
    async fn v2_repeat_behavior_is_deterministic() {
        let export = complete_export().await;
        let parsed = verified_v2(&export_as_ndjson(&export));
        let object = &parsed;
        let destination = Arc::new(
            kleos_lib::db::Database::connect_memory()
                .await
                .expect("destination db"),
        );
        let _ = import_kleos_v2(&destination, 1, object)
            .await
            .expect("first import");
        let _ = import_kleos_v2(&destination, 1, object)
            .await
            .expect("repeat import");
        destination
            .read(|conn| {
                for (table, expected) in [
                    ("memories", 2),
                    ("conversations", 2),
                    ("episodes", 2),
                    ("structured_facts", 2),
                    ("entities", 1),
                    ("user_preferences", 1),
                    ("skill_records", 1),
                ] {
                    let count: i64 =
                        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })?;
                    assert_eq!(count, expected, "table {table}");
                }
                Ok(())
            })
            .await
            .expect("verify repeat import");
    }

    /// Parser and preflight validation reject truncation, unknown record
    /// types, duplicate IDs, and unresolved memory references before writes.
    #[tokio::test]
    async fn v2_rejects_invalid_streams_before_writing() {
        let truncated = b"{\"type\":\"header\",\"version\":\"2.0\"}\n\
                          {\"type\":\"memory\",\"id\":1}\n";
        assert!(parse_import_body(truncated).is_err());
        let unknown = b"{\"type\":\"header\",\"version\":\"2.0\"}\n\
                        {\"type\":\"mystery\",\"id\":1}\n\
                        {\"type\":\"trailer\",\"counts\":{}}\n";
        assert!(parse_import_body(unknown).is_err());

        let export = complete_export().await;
        let parsed = verified_v2(&export_as_ndjson(&export));
        let mut duplicate = parsed.clone();
        let memories = duplicate["memories"].as_array_mut().expect("memories");
        memories.push(memories[0].clone());
        let destination = Arc::new(
            kleos_lib::db::Database::connect_memory()
                .await
                .expect("destination db"),
        );
        assert!(import_kleos_v2(&destination, 1, &duplicate).await.is_err());

        let mut unresolved = parsed;
        unresolved["facts"][0]["memory_id"] = json!(999_999);
        assert!(import_kleos_v2(&destination, 1, &unresolved).await.is_err());
        let count = destination
            .read(|conn| {
                conn.query_row("SELECT COUNT(*) FROM memories", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(Into::into)
            })
            .await
            .expect("count memories");
        assert_eq!(count, 0);
    }

    /// Legacy v1 NDJSON remains recognizable with partial-import semantics,
    /// while a JSON marker cannot manufacture the verified v2 parser state.
    #[test]
    fn parser_distinguishes_legacy_ndjson_from_verified_v2() {
        let legacy = b"{\"type\":\"header\",\"version\":\"1.0\"}\n\
                       {\"type\":\"memory\",\"id\":1,\"content\":\"legacy\"}\n";
        match parse_import_body(legacy).expect("parse legacy NDJSON") {
            ParsedImport::LegacyNdjson(object) => {
                assert_eq!(object["memories"].as_array().map(Vec::len), Some(1));
            }
            _ => panic!("version 1 must retain legacy semantics"),
        }
        let spoof = br#"{"version":"2.0","_ndjson_complete":true,"memories":[]}"#;
        assert!(matches!(
            parse_import_body(spoof).expect("parse JSON"),
            ParsedImport::Json(_)
        ));
    }

    /// A late database failure rolls the whole versioned import back, so no
    /// earlier section or tenant counter update survives.
    #[tokio::test]
    async fn v2_late_failure_rolls_back_every_section() {
        let export = complete_export().await;
        let parsed = verified_v2(&export_as_ndjson(&export));
        let destination = Arc::new(
            kleos_lib::db::Database::connect_memory()
                .await
                .expect("destination db"),
        );
        destination
            .write(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER reject_portable_skill
                     BEFORE INSERT ON skill_records
                     BEGIN SELECT RAISE(ABORT, 'injected skill failure'); END;",
                )?;
                Ok(())
            })
            .await
            .expect("install failure trigger");
        assert!(import_kleos_v2(&destination, 1, &parsed).await.is_err());
        destination
            .read(|conn| {
                for table in [
                    "memories",
                    "conversations",
                    "episodes",
                    "entities",
                    "structured_facts",
                    "user_preferences",
                    "skill_records",
                ] {
                    let count: i64 =
                        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })?;
                    assert_eq!(count, 0, "table {table}");
                }
                Ok(())
            })
            .await
            .expect("verify rollback");
    }

    /// A quota failure on a later memory aborts every advertised section and
    /// restores the writer-maintained usage counters to their pre-import state.
    #[tokio::test]
    async fn v2_quota_failure_halfway_rolls_back_rows_and_counters() {
        let export = complete_export().await;
        let mut parsed = verified_v2(&export_as_ndjson(&export));
        let memories = parsed["memories"].as_array_mut().expect("memories");
        let mut second = memories[0].clone();
        second["id"] = json!(999);
        second["content"] = json!("second memory exceeds quota");
        memories.push(second);

        let destination = Arc::new(
            kleos_lib::db::Database::open_tenant_memory()
                .await
                .expect("tenant destination"),
        );
        let first_bytes = export.memories[0]["content"]
            .as_str()
            .expect("content")
            .len() as i64;
        let quota = kleos_lib::tenant::types::shared_quota(kleos_lib::tenant::types::QuotaConfig {
            content_bytes: Some(first_bytes),
            memory_count: Some(2),
            disk_bytes: None,
        });
        destination
            .bind_tenant_write_policy(
                quota,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .expect("bind quota");
        assert!(import_kleos_v2(&destination, 1, &parsed).await.is_err());
        destination
            .read(|conn| {
                for table in [
                    "memories",
                    "conversations",
                    "episodes",
                    "entities",
                    "structured_facts",
                    "user_preferences",
                    "skill_records",
                ] {
                    let count: i64 =
                        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })?;
                    assert_eq!(count, 0, "table {table}");
                }
                let usage: (i64, i64) = conn.query_row(
                    "SELECT
                       (SELECT value FROM tenant_state WHERE key = 'content_bytes'),
                       (SELECT value FROM tenant_state WHERE key = 'memory_count')",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                assert_eq!(usage, (0, 0));
                Ok(())
            })
            .await
            .expect("verify quota rollback");
    }
}
