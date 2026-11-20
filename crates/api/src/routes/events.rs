use arch_fos_common::{ApiErrorBody, Event, EventsPage, Severity, TimeEntityFilterQuery};
use axum::Json;
use axum::extract::{Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{ApiError, AppState, normalize_limit, parse_i64_cursor};

#[derive(sqlx::FromRow)]
struct EventRow {
    id: i64,
    ts: i64,
    #[sqlx(rename = "type")]
    event_type: String,
    severity: String,
    source: String,
    entity_type: String,
    entity_id: String,
    payload: String,
}

/// Lists raw collector events with cursor pagination and severity/time/entity filters.
#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "events",
    params(TimeEntityFilterQuery),
    responses(
        (status = 200, description = "Paginated events", body = EventsPage),
        (status = 400, description = "Invalid query parameter", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<TimeEntityFilterQuery>,
) -> Result<Json<EventsPage>, ApiError> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_i64_cursor(query.cursor.as_deref())?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT id, ts, type, severity, source, entity_type, entity_id, payload FROM events WHERE 1=1",
    );

    if let Some(c) = cursor {
        qb.push(" AND id < ").push_bind(c);
    }
    if let Some(sev) = query.severity {
        qb.push(" AND severity = ").push_bind(sev.as_str());
    }
    if let Some(from) = query.from {
        qb.push(" AND ts >= ").push_bind(from);
    }
    if let Some(to) = query.to {
        qb.push(" AND ts <= ").push_bind(to);
    }
    if let Some(ref entity_type) = query.entity_type {
        qb.push(" AND entity_type = ").push_bind(entity_type);
    }
    if let Some(ref entity_id) = query.entity_id {
        qb.push(" AND entity_id = ").push_bind(entity_id);
    }

    qb.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

    let rows: Vec<EventRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<Event> = rows
        .into_iter()
        .take(take_count)
        .map(|row| Event {
            id: row.id,
            ts: row.ts,
            event_type: row.event_type,
            severity: Severity::parse(&row.severity).unwrap_or(Severity::Info),
            source: row.source,
            entity_type: row.entity_type,
            entity_id: row.entity_id,
            payload: serde_json::from_str(&row.payload).unwrap_or(serde_json::Value::Null),
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|e| e.id.to_string())
    } else {
        None
    };

    Ok(Json(EventsPage {
        items,
        next_cursor,
        has_more,
    }))
}
