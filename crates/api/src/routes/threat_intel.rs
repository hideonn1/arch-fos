use std::collections::HashMap;

use arch_fos_common::{ApiErrorBody, ThreatFeedStatus, ThreatIntelStatusResponse};
use axum::Json;
use axum::extract::State;

use crate::routes::{ApiError, AppState};

/// Returns URLhaus and Feodo Tracker indicator counts and last sync timestamps (US-18).
#[utoipa::path(
    get,
    path = "/api/v1/threat-intel/status",
    tag = "network",
    responses(
        (status = 200, description = "Threat intelligence feed sync status", body = ThreatIntelStatusResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn threat_intel_status(
    State(state): State<AppState>,
) -> Result<Json<ThreatIntelStatusResponse>, ApiError> {
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT feed, COUNT(*) FROM threat_indicators GROUP BY feed")
            .fetch_all(&state.pool)
            .await?;
    let count_map: HashMap<String, i64> = counts.into_iter().collect();

    let sync_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT feed_name, last_synced_at FROM feed_cache WHERE feed_name IN ('feodo_tracker', 'urlhaus')",
    )
    .fetch_all(&state.pool)
    .await?;
    let sync_map: HashMap<String, i64> = sync_rows.into_iter().collect();

    let mut feeds = Vec::new();
    let mut total_indicators = 0_i64;
    for feed_name in ["feodo_tracker", "urlhaus"] {
        let indicator_count = count_map.get(feed_name).copied().unwrap_or(0);
        total_indicators += indicator_count;
        feeds.push(ThreatFeedStatus {
            feed_name: feed_name.to_string(),
            indicator_count,
            last_synced_at: sync_map.get(feed_name).copied(),
        });
    }

    Ok(Json(ThreatIntelStatusResponse {
        feeds,
        total_indicators,
    }))
}
