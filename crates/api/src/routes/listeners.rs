use arch_fos_common::{ApiErrorBody, Listener, ListenersPage, TimeEntityFilterQuery};
use axum::Json;
use axum::extract::{Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{ApiError, AppState, normalize_limit, parse_i64_cursor};

#[derive(sqlx::FromRow)]
struct ListenerRow {
    id: i64,
    ts: i64,
    protocol: String,
    local_addr: String,
    local_port: i64,
    pid: Option<i64>,
    process_name: Option<String>,
    exe_path: Option<String>,
    package_name: Option<String>,
    entity_type: String,
    entity_id: String,
}

/// Lists listening network sockets attributed to processes and owning packages (US-07).
#[utoipa::path(
    get,
    path = "/api/v1/listeners",
    tag = "listeners",
    params(TimeEntityFilterQuery),
    responses(
        (status = 200, description = "Paginated listeners", body = ListenersPage),
        (status = 400, description = "Invalid query parameter", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_listeners(
    State(state): State<AppState>,
    Query(query): Query<TimeEntityFilterQuery>,
) -> Result<Json<ListenersPage>, ApiError> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_i64_cursor(query.cursor.as_deref())?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT id, ts, protocol, local_addr, local_port, pid, process_name, exe_path, package_name, entity_type, entity_id FROM listeners WHERE 1=1",
    );

    if let Some(c) = cursor {
        qb.push(" AND id < ").push_bind(c);
    }
    if let Some(ref entity_id) = query.entity_id {
        qb.push(" AND entity_id = ").push_bind(entity_id);
    }

    qb.push(" ORDER BY local_port ASC, id DESC LIMIT ")
        .push_bind(limit + 1);

    let rows: Vec<ListenerRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<Listener> = rows
        .into_iter()
        .take(take_count)
        .map(|r| Listener {
            id: r.id,
            ts: r.ts,
            protocol: r.protocol,
            local_addr: r.local_addr,
            local_port: r.local_port,
            pid: r.pid,
            process_name: r.process_name,
            exe_path: r.exe_path,
            package_name: r.package_name,
            entity_type: r.entity_type,
            entity_id: r.entity_id,
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|l| l.id.to_string())
    } else {
        None
    };

    Ok(Json(ListenersPage {
        items,
        next_cursor,
        has_more,
    }))
}
