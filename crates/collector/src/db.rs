use std::path::Path;
use std::str::FromStr;

use arch_fos_common::{
    CollectorCommand, CollectorResponse, FindingStatus, InstallReason, NewEvent, Severity,
};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use thiserror::Error;

use crate::inventory::PackageSnapshot;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("failed to create database directory {0}: {1}")]
    CreateDir(String, std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Existing package state loaded from SQLite to compute snapshot diffs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPackageState {
    pub name: String,
    pub version: String,
    pub repo: Option<String>,
    pub is_foreign: bool,
    pub reason: InstallReason,
    pub first_seen_at: i64,
}

/// Finding candidate emitted by collector rules prior to suppression/dedup checks.
#[derive(Debug, Clone, PartialEq)]
pub struct NewFinding {
    pub ts: i64,
    pub rule_id: String,
    pub severity: Severity,
    pub entity_type: String,
    pub entity_id: String,
    pub title: String,
    pub summary: String,
    pub evidence: serde_json::Value,
}

/// Opens the sole-writer SQLite pool in WAL mode and runs embedded migrations.
pub async fn open_writer_pool(db_path: &Path) -> Result<SqlitePool, DbError> {
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| DbError::CreateDir(parent.display().to_string(), err))?;
    }

    let dsn = format!("sqlite://{}", db_path.display());
    let options = SqliteConnectOptions::from_str(&dsn)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;

    // Enable incremental auto_vacuum if DB is newly created before migrations.
    let _ = sqlx::query("PRAGMA auto_vacuum = INCREMENTAL")
        .execute(&pool)
        .await;

    sqlx::migrate!("../../migrations").run(&pool).await?;

    // Allow group readers (arch-fos-api via SupplementaryGroups=arch-fos-collector)
    // to map SQLite WAL shared-memory read marks in `-shm` while `.db` and `-wal` remain 0640.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let shm_path = format!("{}-shm", db_path.display());
        if Path::new(&shm_path).exists() {
            let _ = std::fs::set_permissions(&shm_path, std::fs::Permissions::from_mode(0o660));
        }
    }

    Ok(pool)
}

/// Loads minimal package metadata needed to detect inventory diffs.
pub async fn load_stored_packages(pool: &SqlitePool) -> Result<Vec<StoredPackageState>, DbError> {
    let rows: Vec<(String, String, Option<String>, i64, String, i64)> = sqlx::query_as(
        "SELECT name, version, repo, is_foreign, reason, first_seen_at FROM packages",
    )
    .fetch_all(pool)
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (name, version, repo, is_foreign, reason, first_seen_at) in rows {
        result.push(StoredPackageState {
            name,
            version,
            repo,
            is_foreign: is_foreign != 0,
            reason: InstallReason::parse(&reason).unwrap_or(InstallReason::Explicit),
            first_seen_at,
        });
    }
    Ok(result)
}

/// Persists package inventory changes and diff events in a single atomic transaction.
pub async fn apply_package_snapshot(
    pool: &SqlitePool,
    upserts: &[(&PackageSnapshot, i64)],
    unchanged_names: &[&str],
    removed_names: &[String],
    events: &[NewEvent],
    now_ms: i64,
) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;

    if !unchanged_names.is_empty() {
        sqlx::query("UPDATE packages SET last_seen_at = ?")
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;
    }

    for name in removed_names {
        sqlx::query("DELETE FROM packages WHERE name = ?")
            .bind(name)
            .execute(&mut *tx)
            .await?;
    }

    for (pkg, first_seen_at) in upserts {
        let files_json = serde_json::to_string(&pkg.files)?;
        sqlx::query(
            r#"
            INSERT INTO packages (
                name, version, repo, is_foreign, install_date, reason,
                description, size_bytes, files, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                version = excluded.version,
                repo = excluded.repo,
                is_foreign = excluded.is_foreign,
                install_date = excluded.install_date,
                reason = excluded.reason,
                description = excluded.description,
                size_bytes = excluded.size_bytes,
                files = excluded.files,
                last_seen_at = excluded.last_seen_at
            "#,
        )
        .bind(&pkg.name)
        .bind(&pkg.version)
        .bind(&pkg.repo)
        .bind(i64::from(pkg.is_foreign))
        .bind(pkg.install_date)
        .bind(pkg.reason.as_str())
        .bind(&pkg.description)
        .bind(pkg.size_bytes)
        .bind(files_json)
        .bind(*first_seen_at)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
    }

    for event in events {
        insert_event_tx(&mut tx, event).await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Inserts a batch of raw events in a single transaction.
pub async fn insert_events(pool: &SqlitePool, events: &[NewEvent]) -> Result<(), DbError> {
    if events.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for event in events {
        insert_event_tx(&mut tx, event).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn insert_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    event: &NewEvent,
) -> Result<(), DbError> {
    let payload_json = serde_json::to_string(&event.payload)?;
    sqlx::query(
        r#"
        INSERT INTO events (ts, type, severity, source, entity_type, entity_id, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(event.ts)
    .bind(&event.event_type)
    .bind(event.severity.as_str())
    .bind(&event.source)
    .bind(&event.entity_type)
    .bind(&event.entity_id)
    .bind(payload_json)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Upserts a finding if not suppressed and not already open with identical `(rule_id, entity)`.
/// Returns `Ok(true)` if a new finding row was inserted.
pub async fn upsert_finding_respecting_suppression(
    pool: &SqlitePool,
    finding: &NewFinding,
    now_ms: i64,
) -> Result<bool, DbError> {
    let suppressed: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT id FROM suppressions
        WHERE rule_id = ?
          AND entity_type = ?
          AND entity_id = ?
          AND (expires_at IS NULL OR expires_at > ?)
        LIMIT 1
        "#,
    )
    .bind(&finding.rule_id)
    .bind(&finding.entity_type)
    .bind(&finding.entity_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await?;

    if suppressed.is_some() {
        return Ok(false);
    }

    let existing: Option<(i64, String)> = sqlx::query_as(
        r#"
        SELECT id, status FROM findings
        WHERE rule_id = ? AND entity_type = ? AND entity_id = ?
          AND status IN ('new', 'acknowledged', 'ignored')
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .bind(&finding.rule_id)
    .bind(&finding.entity_type)
    .bind(&finding.entity_id)
    .fetch_optional(pool)
    .await?;

    let evidence_json = serde_json::to_string(&finding.evidence)?;

    if let Some((existing_id, existing_status)) = existing {
        if existing_status == "ignored" {
            let expired_sup: Option<(i64,)> = sqlx::query_as(
                r#"
                SELECT id FROM suppressions
                WHERE rule_id = ?
                  AND entity_type = ?
                  AND entity_id = ?
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                LIMIT 1
                "#,
            )
            .bind(&finding.rule_id)
            .bind(&finding.entity_type)
            .bind(&finding.entity_id)
            .bind(now_ms)
            .fetch_optional(pool)
            .await?;

            if let Some((sup_id,)) = expired_sup {
                let mut tx = pool.begin().await?;
                sqlx::query(
                    r#"
                    UPDATE findings
                    SET status = 'new', updated_at = ?, severity = ?, title = ?, summary = ?, evidence = ?
                    WHERE id = ?
                    "#,
                )
                .bind(now_ms)
                .bind(finding.severity.as_str())
                .bind(&finding.title)
                .bind(&finding.summary)
                .bind(&evidence_json)
                .bind(existing_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    r#"
                    INSERT INTO finding_audit_log (finding_id, actor, action, old_status, new_status, note, ts)
                    VALUES (?, 'collector', 'suppression_expired', 'ignored', 'new', 'Suppression expired', ?)
                    "#,
                )
                .bind(existing_id)
                .bind(now_ms)
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM suppressions WHERE id = ?")
                    .bind(sup_id)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                return Ok(true);
            }
        }

        sqlx::query(
            r#"
            UPDATE findings
            SET updated_at = ?, severity = ?, title = ?, summary = ?, evidence = ?
            WHERE id = ?
            "#,
        )
        .bind(now_ms)
        .bind(finding.severity.as_str())
        .bind(&finding.title)
        .bind(&finding.summary)
        .bind(evidence_json)
        .bind(existing_id)
        .execute(pool)
        .await?;
        return Ok(false);
    }

    sqlx::query(
        r#"
        INSERT INTO findings (
            ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence
        ) VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?)
        "#,
    )
    .bind(finding.ts)
    .bind(now_ms)
    .bind(&finding.rule_id)
    .bind(finding.severity.as_str())
    .bind(&finding.entity_type)
    .bind(&finding.entity_id)
    .bind(&finding.title)
    .bind(&finding.summary)
    .bind(evidence_json)
    .execute(pool)
    .await?;

    Ok(true)
}

/// Executes a finding management or hook audit command sent to the collector sole writer.
pub async fn apply_collector_command(
    pool: &SqlitePool,
    cmd: CollectorCommand,
    now_ms: i64,
) -> Result<CollectorResponse, DbError> {
    match cmd {
        CollectorCommand::UpdateFindingStatus {
            finding_id,
            status,
            actor,
            note,
        } => {
            let mut tx = pool.begin().await?;
            let current: Option<(String,)> =
                sqlx::query_as("SELECT status FROM findings WHERE id = ?")
                    .bind(finding_id)
                    .fetch_optional(&mut *tx)
                    .await?;

            let Some((old_status,)) = current else {
                return Ok(CollectorResponse::NotFound {
                    message: format!("finding {finding_id} not found"),
                });
            };

            let new_status = status.as_str();
            sqlx::query("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?")
                .bind(new_status)
                .bind(now_ms)
                .bind(finding_id)
                .execute(&mut *tx)
                .await?;

            sqlx::query(
                r#"
                INSERT INTO finding_audit_log (finding_id, actor, action, old_status, new_status, note, ts)
                VALUES (?, ?, 'status_change', ?, ?, ?, ?)
                "#,
            )
            .bind(finding_id)
            .bind(&actor)
            .bind(&old_status)
            .bind(new_status)
            .bind(&note)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok(CollectorResponse::Ok {
                id: Some(finding_id),
            })
        }
        CollectorCommand::CreateSuppression {
            rule_id,
            entity_type,
            entity_id,
            reason,
            actor,
            expires_at,
        } => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                r#"
                INSERT INTO suppressions (rule_id, entity_type, entity_id, reason, created_by, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id, entity_type, entity_id) DO UPDATE SET
                    reason = excluded.reason,
                    created_by = excluded.created_by,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                "#,
            )
            .bind(&rule_id)
            .bind(&entity_type)
            .bind(&entity_id)
            .bind(&reason)
            .bind(&actor)
            .bind(now_ms)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;

            let (sup_id,): (i64,) = sqlx::query_as(
                "SELECT id FROM suppressions WHERE rule_id = ? AND entity_type = ? AND entity_id = ?",
            )
            .bind(&rule_id)
            .bind(&entity_type)
            .bind(&entity_id)
            .fetch_one(&mut *tx)
            .await?;

            // Also mark any matching 'new' findings as 'ignored' and record in audit log.
            let open_ids: Vec<(i64, String)> = sqlx::query_as(
                "SELECT id, status FROM findings WHERE rule_id = ? AND entity_type = ? AND entity_id = ? AND status IN ('new', 'acknowledged')",
            )
            .bind(&rule_id)
            .bind(&entity_type)
            .bind(&entity_id)
            .fetch_all(&mut *tx)
            .await?;

            for (fid, old_status) in open_ids {
                sqlx::query("UPDATE findings SET status = 'ignored', updated_at = ? WHERE id = ?")
                    .bind(now_ms)
                    .bind(fid)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    r#"
                    INSERT INTO finding_audit_log (finding_id, actor, action, old_status, new_status, note, ts)
                    VALUES (?, ?, 'suppressed', ?, ?, ?, ?)
                    "#,
                )
                .bind(fid)
                .bind(&actor)
                .bind(&old_status)
                .bind(FindingStatus::Ignored.as_str())
                .bind(&reason)
                .bind(now_ms)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit().await?;
            Ok(CollectorResponse::Ok { id: Some(sup_id) })
        }
        CollectorCommand::DeleteSuppression {
            suppression_id,
            actor: _,
        } => {
            let res = sqlx::query("DELETE FROM suppressions WHERE id = ?")
                .bind(suppression_id)
                .execute(pool)
                .await?;
            if res.rows_affected() == 0 {
                return Ok(CollectorResponse::NotFound {
                    message: format!("suppression {suppression_id} not found"),
                });
            }
            Ok(CollectorResponse::Ok {
                id: Some(suppression_id),
            })
        }
        CollectorCommand::RecordHookEvent {
            event_type,
            severity,
            entity_id,
            payload,
        } => {
            let ev = NewEvent {
                ts: now_ms,
                event_type,
                severity,
                source: "pacman:hook".to_string(),
                entity_type: "package".to_string(),
                entity_id,
                payload,
            };
            insert_events(pool, &[ev]).await?;
            Ok(CollectorResponse::Ok { id: None })
        }
        CollectorCommand::SaveLlmExplanation {
            finding_id,
            finding_hash,
            model,
            summary,
            risk,
            suggested_actions,
            references,
            rag_sources,
        } => {
            let mut tx = pool.begin().await?;
            let actions_json = serde_json::to_string(&suggested_actions)?;
            let refs_json = serde_json::to_string(&references)?;
            let rag_json = serde_json::to_string(&rag_sources)?;

            sqlx::query(
                r#"
                INSERT INTO llm_explanations (
                    finding_hash, finding_id, model, summary, risk,
                    suggested_actions, references_json, rag_sources, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_hash) DO UPDATE SET
                    summary = excluded.summary,
                    risk = excluded.risk,
                    suggested_actions = excluded.suggested_actions,
                    references_json = excluded.references_json,
                    rag_sources = excluded.rag_sources,
                    created_at = excluded.created_at
                "#,
            )
            .bind(&finding_hash)
            .bind(finding_id)
            .bind(&model)
            .bind(&summary)
            .bind(&risk)
            .bind(actions_json)
            .bind(refs_json)
            .bind(rag_json)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;

            // US-28: Persist suggested actions in `pending` state for explicit human review.
            for cmd in &suggested_actions {
                let trimmed = cmd.trim();
                if trimmed.is_empty() {
                    continue;
                }
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO suggested_actions (
                        finding_id, command, rationale, status, created_at
                    ) VALUES (?, ?, ?, 'pending', ?)
                    "#,
                )
                .bind(finding_id)
                .bind(trimmed)
                .bind(&summary)
                .bind(now_ms)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit().await?;
            Ok(CollectorResponse::Ok {
                id: Some(finding_id),
            })
        }
        CollectorCommand::ReviewSuggestedAction {
            action_id,
            status,
            actor,
        } => {
            let res = sqlx::query(
                "UPDATE suggested_actions SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
            )
            .bind(status.as_str())
            .bind(&actor)
            .bind(now_ms)
            .bind(action_id)
            .execute(pool)
            .await?;

            if res.rows_affected() == 0 {
                return Ok(CollectorResponse::NotFound {
                    message: format!("suggested action {action_id} not found"),
                });
            }
            Ok(CollectorResponse::Ok {
                id: Some(action_id),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    async fn temp_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("arch_fos_col_db_{name}_{nanos}.db"));
        let pool = open_writer_pool(&path).await.unwrap();
        (pool, path)
    }

    #[tokio::test]
    async fn suppressions_block_new_findings_until_expired() {
        let (pool, path) = temp_pool("suppression").await;

        let f = NewFinding {
            ts: 1000,
            rule_id: "aur_low_votes".to_string(),
            severity: Severity::Low,
            entity_type: "package".to_string(),
            entity_id: "demo".to_string(),
            title: "Low votes".to_string(),
            summary: "few votes".to_string(),
            evidence: serde_json::json!({}),
        };

        // Insert initial finding
        assert!(
            upsert_finding_respecting_suppression(&pool, &f, 1000)
                .await
                .unwrap()
        );

        // Suppress until ts=5000
        let resp = apply_collector_command(
            &pool,
            CollectorCommand::CreateSuppression {
                rule_id: "aur_low_votes".to_string(),
                entity_type: "package".to_string(),
                entity_id: "demo".to_string(),
                reason: "expected".to_string(),
                actor: "tester".to_string(),
                expires_at: Some(5000),
            },
            2000,
        )
        .await
        .unwrap();
        assert!(matches!(resp, CollectorResponse::Ok { .. }));

        // At ts=3000 suppression is active -> blocked
        assert!(
            !upsert_finding_respecting_suppression(&pool, &f, 3000)
                .await
                .unwrap()
        );

        // At ts=6000 suppression expired -> allowed again
        assert!(
            upsert_finding_respecting_suppression(&pool, &f, 6000)
                .await
                .unwrap()
        );

        pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
