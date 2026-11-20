use arch_fos_common::{
    ApiErrorBody, OverviewSummary, PackageSummary, SeverityCounts, StatusCounts, TimeSeriesPoint,
    TopProcessTraffic, TopServiceUsage,
};
use axum::Json;
use axum::extract::State;
use std::collections::BTreeMap;

use crate::routes::{ApiError, AppState};

/// Returns aggregated system security and inventory metrics for the overview dashboard.
#[utoipa::path(
    get,
    path = "/api/v1/summary",
    tag = "dashboard",
    responses(
        (status = 200, description = "Overview dashboard summary", body = OverviewSummary),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn get_summary(State(state): State<AppState>) -> Result<Json<OverviewSummary>, ApiError> {
    let (total_events,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events")
        .fetch_one(&state.pool)
        .await?;

    let (total_findings,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings")
        .fetch_one(&state.pool)
        .await?;

    let sev_rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
            .fetch_all(&state.pool)
            .await?;
    let mut findings_by_severity = SeverityCounts {
        info: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
    };
    for (sev, cnt) in sev_rows {
        match sev.as_str() {
            "info" => findings_by_severity.info = cnt,
            "low" => findings_by_severity.low = cnt,
            "medium" => findings_by_severity.medium = cnt,
            "high" => findings_by_severity.high = cnt,
            "critical" => findings_by_severity.critical = cnt,
            _ => {}
        }
    }

    let status_rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, COUNT(*) FROM findings GROUP BY status")
            .fetch_all(&state.pool)
            .await?;
    let mut findings_by_status = StatusCounts {
        new: 0,
        acknowledged: 0,
        ignored: 0,
        resolved: 0,
    };
    for (status, cnt) in status_rows {
        match status.as_str() {
            "new" => findings_by_status.new = cnt,
            "acknowledged" => findings_by_status.acknowledged = cnt,
            "ignored" => findings_by_status.ignored = cnt,
            "resolved" => findings_by_status.resolved = cnt,
            _ => {}
        }
    }

    let pkg_row: (i64, i64, i64, Option<i64>) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            COALESCE(SUM(CASE WHEN is_foreign = 1 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN reason = 'explicit' THEN 1 ELSE 0 END), 0),
            MAX(last_seen_at)
        FROM packages
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    let (pending_cve_packages,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT entity_id)
        FROM findings
        WHERE entity_type = 'package'
          AND status IN ('new', 'acknowledged')
          AND rule_id LIKE 'cve%'
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    let packages = PackageSummary {
        total: pkg_row.0,
        official: pkg_row.0 - pkg_row.1,
        foreign: pkg_row.1,
        explicit: pkg_row.2,
        dependency: pkg_row.0 - pkg_row.2,
        pending_cve_packages,
        last_sync_ts: pkg_row.3,
    };

    let top_proc_rows: Vec<(String, Option<String>, i64, i64, i64)> = sqlx::query_as(
        r#"
        SELECT
            comm,
            MAX(exe_path) AS exe_path,
            COALESCE(SUM(bytes_tx), 0) AS tx,
            COALESCE(SUM(bytes_rx), 0) AS rx,
            COALESCE(SUM(bytes_tx + bytes_rx), 0) AS total
        FROM flows_1m
        GROUP BY comm
        ORDER BY total DESC
        LIMIT 5
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let top_processes = top_proc_rows
        .into_iter()
        .map(|(comm, exe_path, tx, rx, total)| TopProcessTraffic {
            comm,
            exe_path,
            total_tx_bytes: tx,
            total_rx_bytes: rx,
            total_bytes: total,
        })
        .collect();

    let top_svc_rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        r#"
        SELECT unit_name, active_state, cpu_usage_ns, memory_bytes
        FROM services
        ORDER BY memory_bytes DESC, cpu_usage_ns DESC
        LIMIT 5
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let top_services = top_svc_rows
        .into_iter()
        .map(
            |(unit_name, active_state, cpu_usage_ns, memory_bytes)| TopServiceUsage {
                unit_name,
                active_state,
                cpu_usage_ns,
                memory_bytes,
            },
        )
        .collect();

    // Aggregate time-series buckets (per minute) over recent events, findings, and flows.
    let (latest_ts,): (Option<i64>,) = sqlx::query_as("SELECT MAX(ts) FROM events")
        .fetch_one(&state.pool)
        .await?;
    let window_start = latest_ts.map_or(0, |ts| ts.saturating_sub(24 * 60 * 60 * 1000));

    let mut buckets: BTreeMap<i64, (i64, i64, i64)> = BTreeMap::new();

    let event_series: Vec<(i64, i64)> = sqlx::query_as(
        r#"
        SELECT (ts / 60000) * 60 AS bucket_sec, COUNT(*)
        FROM events
        WHERE ts >= ?
        GROUP BY bucket_sec
        ORDER BY bucket_sec ASC
        LIMIT 1440
        "#,
    )
    .bind(window_start)
    .fetch_all(&state.pool)
    .await?;
    for (ts_sec, count) in event_series {
        buckets.entry(ts_sec).or_default().0 = count;
    }

    let finding_series: Vec<(i64, i64)> = sqlx::query_as(
        r#"
        SELECT (ts / 60000) * 60 AS bucket_sec, COUNT(*)
        FROM findings
        WHERE ts >= ?
        GROUP BY bucket_sec
        ORDER BY bucket_sec ASC
        LIMIT 1440
        "#,
    )
    .bind(window_start)
    .fetch_all(&state.pool)
    .await?;
    for (ts_sec, count) in finding_series {
        buckets.entry(ts_sec).or_default().1 = count;
    }

    let flow_series: Vec<(i64, i64)> = sqlx::query_as(
        r#"
        SELECT (bucket_ts / 60000) * 60 AS bucket_sec, COALESCE(SUM(bytes_tx + bytes_rx), 0)
        FROM flows_1m
        WHERE bucket_ts >= ?
        GROUP BY bucket_sec
        ORDER BY bucket_sec ASC
        LIMIT 1440
        "#,
    )
    .bind(window_start)
    .fetch_all(&state.pool)
    .await?;
    for (ts_sec, bytes_total) in flow_series {
        buckets.entry(ts_sec).or_default().2 = bytes_total;
    }

    let time_series = buckets
        .into_iter()
        .map(
            |(ts_sec, (events_count, findings_count, bytes_total))| TimeSeriesPoint {
                ts_sec,
                events_count,
                findings_count,
                bytes_total,
            },
        )
        .collect();

    Ok(Json(OverviewSummary {
        total_events,
        total_findings,
        findings_by_severity,
        findings_by_status,
        packages,
        top_processes,
        top_services,
        time_series,
    }))
}
