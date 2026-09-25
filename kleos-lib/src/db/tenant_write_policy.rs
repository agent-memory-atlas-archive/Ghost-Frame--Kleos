//! Writer-boundary tenant policy shared by every memory producer.

use crate::tenant::types::QuotaConfig;
use crate::{EngError, Result};
use arc_swap::ArcSwap;
use rusqlite::Connection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Live limits and disk state owned jointly by the tenant handle and its database.
pub(super) struct TenantWritePolicy {
    pub quota: Arc<ArcSwap<QuotaConfig>>,
    pub read_only: Arc<AtomicBool>,
    pub dirty: Arc<AtomicBool>,
}

/// Refresh connection-local guards after acquiring the shard's sole writer.
///
/// Limits linearize here. Changes during this closure apply to the next write.
/// Temporary triggers cover raw import and ingestion SQL as well as memory APIs.
pub(super) fn prepare(conn: &mut Connection, policy: &TenantWritePolicy) -> Result<()> {
    let installed: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE name = 'kleos_memory_policy')",
        [],
        |row| row.get(0),
    )?;
    if !installed {
        // Installation is atomic so a partial trigger set can never fail open.
        let tx = conn.transaction()?;
        tx.execute_batch(
            "CREATE TEMP TABLE kleos_memory_policy (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                byte_limit INTEGER, count_limit INTEGER, read_only INTEGER NOT NULL,
                initial_bytes INTEGER NOT NULL, initial_count INTEGER NOT NULL
            );
            INSERT INTO kleos_memory_policy VALUES (1, NULL, NULL, 0, 0, 0);",
        )?;
        for (event, bytes, count) in [
            ("INSERT", "CASE WHEN NEW.is_latest = 1 THEN length(CAST(NEW.content AS BLOB)) ELSE 0 END", "CASE WHEN NEW.is_latest = 1 THEN 1 ELSE 0 END"),
            ("UPDATE", "(CASE WHEN NEW.is_latest = 1 THEN length(CAST(NEW.content AS BLOB)) ELSE 0 END) - (CASE WHEN OLD.is_latest = 1 THEN length(CAST(OLD.content AS BLOB)) ELSE 0 END)", "(CASE WHEN NEW.is_latest = 1 THEN 1 ELSE 0 END) - (CASE WHEN OLD.is_latest = 1 THEN 1 ELSE 0 END)"),
            ("DELETE", "-(CASE WHEN OLD.is_latest = 1 THEN length(CAST(OLD.content AS BLOB)) ELSE 0 END)", "-(CASE WHEN OLD.is_latest = 1 THEN 1 ELSE 0 END)"),
        ] {
            tx.execute_batch(&format!(
                "CREATE TEMP TRIGGER kleos_memory_before_{event} BEFORE {event} ON main.memories BEGIN
                    SELECT CASE WHEN (SELECT read_only FROM kleos_memory_policy) != 0
                        THEN RAISE(ABORT, 'KLEOS_TENANT_QUOTA: disk read-only') END;
                 END;
                 CREATE TEMP TRIGGER kleos_memory_after_{event} AFTER {event} ON main.memories BEGIN
                    UPDATE tenant_state SET value = value + ({bytes}), updated_at = datetime('now')
                        WHERE key = 'content_bytes';
                    UPDATE tenant_state SET value = value + ({count}), updated_at = datetime('now')
                        WHERE key = 'memory_count';
                    SELECT CASE WHEN (SELECT COUNT(*) FROM tenant_state WHERE key IN ('content_bytes', 'memory_count')) != 2
                        OR EXISTS(SELECT 1 FROM tenant_state WHERE key IN ('content_bytes', 'memory_count') AND (value < 0 OR typeof(value) != 'integer'))
                        THEN RAISE(ABORT, 'KLEOS_TENANT_QUOTA: invalid usage counter') END;
                    SELECT CASE WHEN EXISTS(
                        SELECT 1 FROM tenant_state, kleos_memory_policy
                        WHERE (key = 'content_bytes' AND byte_limit IS NOT NULL AND value > MAX(byte_limit, initial_bytes))
                           OR (key = 'memory_count' AND count_limit IS NOT NULL AND value > MAX(count_limit, initial_count)))
                        THEN RAISE(ABORT, 'KLEOS_TENANT_QUOTA: memory limit exceeded') END;
                 END;"
            ))?;
        }
        tx.commit()?;
    }
    let quota = policy.quota.load();
    conn.execute(
        "UPDATE kleos_memory_policy SET byte_limit = ?1, count_limit = ?2, read_only = ?3,
            initial_bytes = (SELECT value FROM tenant_state WHERE key = 'content_bytes'),
            initial_count = (SELECT value FROM tenant_state WHERE key = 'memory_count')",
        rusqlite::params![
            quota.content_bytes,
            quota.memory_count,
            policy.read_only.load(Ordering::Acquire)
        ],
    )?;
    Ok(())
}

/// Preserve the public quota error contract when a guarded SQL statement aborts.
pub(super) fn classify(error: EngError) -> EngError {
    if matches!(&error, EngError::Database(_) | EngError::DatabaseMessage(_))
        && error.to_string().contains("KLEOS_TENANT_QUOTA:")
    {
        EngError::QuotaExceeded(
            "tenant memory limit or disk read-only policy rejected the write".into(),
        )
    } else {
        error
    }
}

#[cfg(test)]
/// Regression coverage using isolated, fully migrated in-memory tenant shards.
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::memory::{self, types::StoreRequest};

    /// Create a shard with mutable live policy and no external storage.
    async fn fixture(
        quota: QuotaConfig,
    ) -> (Arc<Database>, Arc<ArcSwap<QuotaConfig>>, Arc<AtomicBool>) {
        let db = Arc::new(Database::open_tenant_memory().await.unwrap());
        let quota = Arc::new(ArcSwap::from_pointee(quota));
        let read_only = Arc::new(AtomicBool::new(false));
        db.bind_tenant_write_policy(
            quota.clone(),
            read_only.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        (db, quota, read_only)
    }

    /// Read counters together with independently calculated current-row usage.
    async fn usage(db: &Database) -> (i64, i64) {
        db.read(|conn| {
            let actual: (i64, i64) = conn.query_row("SELECT COALESCE(SUM(length(CAST(content AS BLOB))), 0), COUNT(*) FROM memories WHERE is_latest = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let counters: (i64, i64) = conn.query_row("SELECT (SELECT value FROM tenant_state WHERE key = 'content_bytes'), (SELECT value FROM tenant_state WHERE key = 'memory_count')", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
            assert_eq!(counters, actual);
            Ok(actual)
        }).await.unwrap()
    }

    /// Insert through the same raw writer boundary used by import and ingestion.
    async fn raw_store(db: &Database, content: &'static str) -> Result<()> {
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO memories(content, user_id) VALUES (?1, 1)",
                [content],
            )?;
            Ok(())
        })
        .await
    }

    /// Unicode bytes, live quota changes, and raw producers share one guard.
    #[tokio::test]
    async fn quota_raw_unicode_live_policy() {
        let (db, quota, _) = fixture(QuotaConfig {
            content_bytes: Some(4),
            memory_count: Some(2),
            disk_bytes: None,
        })
        .await;
        raw_store(&db, "🦀").await.unwrap();
        assert!(matches!(
            raw_store(&db, "a").await,
            Err(EngError::QuotaExceeded(_))
        ));
        assert_eq!(usage(&db).await, (4, 1));
        quota.store(Arc::new(QuotaConfig::default()));
        raw_store(&db, "a").await.unwrap();
        assert_eq!(usage(&db).await, (5, 2));
    }

    /// A final count slot can be claimed by exactly one concurrent writer.
    #[tokio::test]
    async fn quota_concurrent_final_slot() {
        let (db, _, _) = fixture(QuotaConfig {
            memory_count: Some(1),
            ..QuotaConfig::default()
        })
        .await;
        let (a, b) = tokio::join!(raw_store(&db, "first"), raw_store(&db, "second"));
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            a.err().or_else(|| b.err()),
            Some(EngError::QuotaExceeded(_))
        ));
        assert_eq!(usage(&db).await.1, 1);
    }

    /// Failed multi-section transactions leave both memory rows and counters intact.
    #[tokio::test]
    async fn quota_transaction_rollback() {
        let (db, _, _) = fixture(QuotaConfig {
            memory_count: Some(1),
            ..QuotaConfig::default()
        })
        .await;
        let result = db
            .transaction(|tx| {
                tx.execute(
                    "INSERT INTO memories(content, user_id) VALUES ('one', 1)",
                    [],
                )?;
                tx.execute(
                    "INSERT INTO memories(content, user_id) VALUES ('two', 1)",
                    [],
                )?;
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(EngError::QuotaExceeded(_))));
        assert_eq!(usage(&db).await, (0, 0));
    }

    /// Disk read-only state rejects raw inserts and updates at the writer boundary.
    #[tokio::test]
    async fn quota_read_only_raw_and_normal() {
        let (db, _, read_only) = fixture(QuotaConfig::default()).await;
        raw_store(&db, "original").await.unwrap();
        read_only.store(true, Ordering::Release);
        assert!(matches!(
            raw_store(&db, "blocked").await,
            Err(EngError::QuotaExceeded(_))
        ));
        let update = db
            .write(|conn| {
                conn.execute("UPDATE memories SET content = 'changed'", [])?;
                Ok(())
            })
            .await;
        assert!(matches!(update, Err(EngError::QuotaExceeded(_))));
        let normal = memory::store(
            &db,
            StoreRequest {
                content: "distinct normal write".into(),
                user_id: Some(1),
                ..Default::default()
            },
            None,
            false,
        )
        .await;
        assert!(matches!(normal, Err(EngError::QuotaExceeded(_))));
        assert_eq!(usage(&db).await, (8, 1));
    }

    /// Duplicate retries and version replacement do not double count current rows.
    #[tokio::test]
    async fn quota_versions_shrinking_and_duplicate() {
        let (db, quota, _) = fixture(QuotaConfig {
            content_bytes: Some(4),
            memory_count: Some(1),
            disk_bytes: None,
        })
        .await;
        let req = StoreRequest {
            content: "🦀".into(),
            user_id: Some(1),
            ..Default::default()
        };
        let first = memory::store(&db, req.clone(), Some(quota.load_full()), false)
            .await
            .unwrap();
        let duplicate = memory::store(&db, req, None, false).await.unwrap();
        assert_eq!(duplicate.duplicate_of, Some(first.id));
        assert_eq!(usage(&db).await, (4, 1));
        quota.store(Arc::new(QuotaConfig {
            content_bytes: Some(1),
            memory_count: Some(1),
            disk_bytes: None,
        }));
        let smaller = memory::update(
            &db,
            first.id,
            serde_json::from_value(serde_json::json!({"content": "ab"})).unwrap(),
            1,
            true,
        )
        .await
        .unwrap();
        assert_eq!(usage(&db).await, (2, 1));
        let rejected = memory::update(
            &db,
            smaller.id,
            serde_json::from_value(serde_json::json!({"content": "abc"})).unwrap(),
            1,
            true,
        )
        .await;
        assert!(matches!(rejected, Err(EngError::QuotaExceeded(_))));
        assert_eq!(usage(&db).await, (2, 1));
        let (a, b) = tokio::join!(
            memory::update(
                &db,
                smaller.id,
                serde_json::from_value(serde_json::json!({"content": "x"})).unwrap(),
                1,
                true
            ),
            memory::update(
                &db,
                smaller.id,
                serde_json::from_value(serde_json::json!({"content": "y"})).unwrap(),
                1,
                true
            )
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert_eq!(usage(&db).await, (1, 1));
    }

    /// An overflowing counter fails closed and undoes the attempted insert.
    #[tokio::test]
    async fn quota_counter_overflow_rejected() {
        let (db, _, _) = fixture(QuotaConfig::default()).await;
        db.write(|conn| {
            conn.execute(
                "UPDATE tenant_state SET value = ?1 WHERE key = 'content_bytes'",
                [i64::MAX],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(matches!(
            raw_store(&db, "overflow").await,
            Err(EngError::QuotaExceeded(_))
        ));
        let count: i64 = db
            .read(|conn| Ok(conn.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// Deterministic embedder that changes live policy during embedding work.
    struct LimitChangingEmbedder {
        quota: Arc<ArcSwap<QuotaConfig>>,
    }

    /// Simulate an administrator reducing limits while a request is embedding.
    impl crate::embeddings::EmbeddingProvider for LimitChangingEmbedder {
        /// Publish the changed limit before returning an in-memory embedding.
        fn embed<'a>(
            &'a self,
            _text: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<f32>>> + Send + 'a>>
        {
            Box::pin(async move {
                self.quota.store(Arc::new(QuotaConfig {
                    memory_count: Some(0),
                    ..QuotaConfig::default()
                }));
                Ok(vec![0.0; 1024])
            })
        }
    }

    /// Chunked producers use the limit current after embedding, not a request snapshot.
    #[tokio::test]
    async fn quota_changed_during_embedding_is_enforced() {
        let (db, quota, _) = fixture(QuotaConfig::default()).await;
        let embedder = LimitChangingEmbedder { quota };
        let result = memory::store_with_chunks(
            &db,
            &embedder,
            StoreRequest {
                content: "quota must be checked after expensive work".into(),
                user_id: Some(1),
                chunk_embeddings: Some(Vec::new()),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(result, Err(EngError::QuotaExceeded(_))));
        assert_eq!(usage(&db).await, (0, 0));
    }

    /// Raw lifecycle mutations keep usage aligned with latest rows and UTF-8 bytes.
    #[tokio::test]
    async fn quota_raw_lifecycle_accounting() {
        let (db, _, _) = fixture(QuotaConfig::default()).await;
        raw_store(&db, "é").await.unwrap();
        db.write(|conn| {
            conn.execute("UPDATE memories SET is_archived = 1, is_forgotten = 1", [])?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(usage(&db).await, (2, 1));
        db.write(|conn| {
            conn.execute("DELETE FROM memories", [])?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(usage(&db).await, (0, 0));
    }
}
