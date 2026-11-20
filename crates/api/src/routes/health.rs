use arch_fos_common::{ApiErrorBody, CollectorHealth, HealthResponse};
use axum::Json;
use axum::extract::State;

use crate::routes::{ApiError, AppState};

/// Returns API liveness status and verifies read-only SQLite access.
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "system",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
    )
)]
pub async fn health_check(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let _: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&state.pool).await?;
    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_read_only: true,
    }))
}

#[derive(sqlx::FromRow)]
struct CollectorHealthRow {
    last_heartbeat_at: i64,
    cpu_time_ms: i64,
    rss_bytes: i64,
    db_size_bytes: i64,
    last_ingest_latency_ms: i64,
    status: String,
}

/// Returns the latest self-health telemetry recorded by the collector daemon (US-30).
#[utoipa::path(
    get,
    path = "/api/v1/health/collector",
    tag = "system",
    responses(
        (status = 200, description = "Collector self-health metrics", body = CollectorHealth),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn collector_health(
    State(state): State<AppState>,
) -> Result<Json<CollectorHealth>, ApiError> {
    let row: Option<CollectorHealthRow> = sqlx::query_as(
        "SELECT last_heartbeat_at, cpu_time_ms, rss_bytes, db_size_bytes, last_ingest_latency_ms, status FROM collector_health WHERE id = 1",
    )
    .fetch_optional(&state.pool)
    .await?;

    let health = match row {
        Some(r) => CollectorHealth {
            last_heartbeat_at: r.last_heartbeat_at,
            cpu_time_ms: r.cpu_time_ms,
            rss_bytes: r.rss_bytes,
            db_size_bytes: r.db_size_bytes,
            last_ingest_latency_ms: r.last_ingest_latency_ms,
            status: r.status,
        },
        None => CollectorHealth {
            last_heartbeat_at: 0,
            cpu_time_ms: 0,
            rss_bytes: 0,
            db_size_bytes: 0,
            last_ingest_latency_ms: 0,
            status: "unknown".to_string(),
        },
    };

    Ok(Json(health))
}
