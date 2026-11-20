use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::Severity;
use serde_json::json;
use sqlx::SqlitePool;

use crate::db::{NewFinding, upsert_finding_respecting_suppression};

#[derive(Debug, Clone, Copy, Default)]
pub struct RetentionStats {
    pub summarized_groups: usize,
    pub pruned_events: u64,
}

/// Summarizes raw events older than `retention_days` into `event_daily_summaries`,
/// prunes expired rows, and runs incremental vacuum (US-30).
pub async fn run_retention_and_vacuum(
    pool: &SqlitePool,
    retention_days: u64,
    now_ms: i64,
) -> Result<RetentionStats, sqlx::Error> {
    let cutoff_ms = now_ms.saturating_sub(i64::try_from(retention_days).unwrap_or(30) * 86_400_000);

    let mut tx = pool.begin().await?;

    let summary_rows: Vec<(String, String, String, i64)> = sqlx::query_as(
        r#"
        SELECT
            strftime('%Y-%m-%d', ts / 1000, 'unixepoch') AS day,
            type,
            severity,
            COUNT(*) AS cnt
        FROM events
        WHERE ts < ?
        GROUP BY day, type, severity
        "#,
    )
    .bind(cutoff_ms)
    .fetch_all(&mut *tx)
    .await?;

    let summarized_groups = summary_rows.len();
    for (day, event_type, severity, count) in summary_rows {
        sqlx::query(
            r#"
            INSERT INTO event_daily_summaries (day, event_type, severity, count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(day, event_type, severity) DO UPDATE SET
                count = event_daily_summaries.count + excluded.count
            "#,
        )
        .bind(day)
        .bind(event_type)
        .bind(severity)
        .bind(count)
        .execute(&mut *tx)
        .await?;
    }

    let delete_res = sqlx::query("DELETE FROM events WHERE ts < ?")
        .bind(cutoff_ms)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    if delete_res.rows_affected() > 0 {
        let _ = sqlx::query("PRAGMA incremental_vacuum(200)")
            .execute(pool)
            .await;
    }

    Ok(RetentionStats {
        summarized_groups,
        pruned_events: delete_res.rows_affected(),
    })
}

/// Records collector self-health metrics (CPU, RSS, DB size, ingestion latency) and checks
/// whether the previous heartbeat had gone stale beyond `stale_threshold_ms` (US-30).
pub async fn record_collector_health(
    pool: &SqlitePool,
    db_path: &Path,
    ingest_latency_ms: i64,
    stale_threshold_ms: i64,
) -> Result<(), sqlx::Error> {
    let now_ms = current_unix_ms();

    let prev: Option<(i64,)> =
        sqlx::query_as("SELECT last_heartbeat_at FROM collector_health WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    if let Some((prev_ts,)) = prev
        && now_ms.saturating_sub(prev_ts) > stale_threshold_ms
    {
        let finding = NewFinding {
            ts: now_ms,
            rule_id: "collector_unhealthy".to_string(),
            severity: Severity::High,
            entity_type: "system".to_string(),
            entity_id: "arch-fos-collector".to_string(),
            title: "El colector dejó de reportar durante un intervalo prolongado".to_string(),
            summary: format!(
                "Brecha de heartbeat detectada: {} s sin reporte.",
                now_ms.saturating_sub(prev_ts) / 1000
            ),
            evidence: json!({
                "previous_heartbeat_at": prev_ts,
                "current_heartbeat_at": now_ms,
                "gap_ms": now_ms.saturating_sub(prev_ts),
            }),
        };
        let _ = upsert_finding_respecting_suppression(pool, &finding, now_ms).await;
    }

    let rss_bytes = read_self_rss_bytes();
    let cpu_time_ms = read_self_cpu_time_ms();
    let db_size_bytes = std::fs::metadata(db_path)
        .map(|m| i64::try_from(m.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);

    sqlx::query(
        r#"
        INSERT INTO collector_health (
            id, last_heartbeat_at, cpu_time_ms, rss_bytes, db_size_bytes, last_ingest_latency_ms, status
        ) VALUES (1, ?, ?, ?, ?, ?, 'healthy')
        ON CONFLICT(id) DO UPDATE SET
            last_heartbeat_at = excluded.last_heartbeat_at,
            cpu_time_ms = excluded.cpu_time_ms,
            rss_bytes = excluded.rss_bytes,
            db_size_bytes = excluded.db_size_bytes,
            last_ingest_latency_ms = excluded.last_ingest_latency_ms,
            status = excluded.status
        "#,
    )
    .bind(now_ms)
    .bind(cpu_time_ms)
    .bind(rss_bytes)
    .bind(db_size_bytes)
    .bind(ingest_latency_ms)
    .execute(pool)
    .await?;

    Ok(())
}

fn read_self_rss_bytes() -> i64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: i64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

fn read_self_cpu_time_ms() -> i64 {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return 0;
    };
    // Fields after ') ': utime is index 11, stime is index 12 (in clock ticks).
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        return 0;
    };
    let parts: Vec<&str> = after_comm.split_whitespace().collect();
    let utime: i64 = parts.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: i64 = parts.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Assume standard Linux USER_HZ = 100 -> 1 tick = 10ms.
    (utime + stime) * 10
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_writer_pool;

    #[tokio::test]
    async fn retention_summarizes_prunes_old_events_and_health_detects_staleness() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("arch_fos_ret_{nanos}.db"));
        let pool = open_writer_pool(&path).await.unwrap();

        let now_ms = current_unix_ms();
        let old_ts = now_ms - 40 * 86_400_000;
        let recent_ts = now_ms - 1_000;

        sqlx::query(
            "INSERT INTO events (ts, type, severity, source, entity_type, entity_id, payload) VALUES (?, 'old_ev', 'info', 't', 'pkg', 'a', '{}'), (?, 'new_ev', 'info', 't', 'pkg', 'b', '{}')",
        )
        .bind(old_ts)
        .bind(recent_ts)
        .execute(&pool)
        .await
        .unwrap();

        let stats = run_retention_and_vacuum(&pool, 30, now_ms).await.unwrap();
        assert_eq!(stats.pruned_events, 1);
        assert_eq!(stats.summarized_groups, 1);

        let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);

        let (sum_count,): (i64,) =
            sqlx::query_as("SELECT count FROM event_daily_summaries WHERE event_type = 'old_ev'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sum_count, 1);

        // Seed a stale heartbeat and verify collector_unhealthy finding is emitted
        sqlx::query(
            "INSERT INTO collector_health (id, last_heartbeat_at, cpu_time_ms, rss_bytes, db_size_bytes, last_ingest_latency_ms, status) VALUES (1, ?, 0, 0, 0, 0, 'healthy')",
        )
        .bind(now_ms - 120_000)
        .execute(&pool)
        .await
        .unwrap();

        record_collector_health(&pool, &path, 25, 60_000)
            .await
            .unwrap();

        let (unhealthy_cnt,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM findings WHERE rule_id = 'collector_unhealthy'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(unhealthy_cnt, 1);

        pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
