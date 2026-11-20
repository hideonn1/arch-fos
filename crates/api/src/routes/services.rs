use arch_fos_common::{ApiErrorBody, Service, ServiceFilterQuery, ServicesPage};
use axum::Json;
use axum::extract::{Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{ApiError, AppState, normalize_limit};

#[derive(sqlx::FromRow)]
struct ServiceRow {
    unit_name: String,
    active_state: String,
    sub_state: String,
    unit_file_state: String,
    cpu_usage_ns: i64,
    memory_bytes: i64,
    io_read_bytes: i64,
    io_write_bytes: i64,
    last_seen_at: i64,
}

/// Lists systemd services and cgroup resource metrics with cursor pagination.
#[utoipa::path(
    get,
    path = "/api/v1/services",
    tag = "services",
    params(ServiceFilterQuery),
    responses(
        (status = 200, description = "Paginated services", body = ServicesPage),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_services(
    State(state): State<AppState>,
    Query(query): Query<ServiceFilterQuery>,
) -> Result<Json<ServicesPage>, ApiError> {
    let limit = normalize_limit(query.limit);

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT unit_name, active_state, sub_state, unit_file_state, cpu_usage_ns, memory_bytes, io_read_bytes, io_write_bytes, last_seen_at FROM services WHERE 1=1",
    );

    if let Some(ref cursor) = query.cursor
        && !cursor.is_empty()
    {
        qb.push(" AND unit_name > ").push_bind(cursor);
    }
    if let Some(ref active_state) = query.active_state
        && !active_state.is_empty()
    {
        qb.push(" AND active_state = ").push_bind(active_state);
    }

    qb.push(" ORDER BY unit_name ASC LIMIT ")
        .push_bind(limit + 1);

    let rows: Vec<ServiceRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<Service> = rows
        .into_iter()
        .take(take_count)
        .map(|row| Service {
            unit_name: row.unit_name,
            active_state: row.active_state,
            sub_state: row.sub_state,
            unit_file_state: row.unit_file_state,
            cpu_usage_ns: row.cpu_usage_ns,
            memory_bytes: row.memory_bytes,
            io_read_bytes: row.io_read_bytes,
            io_write_bytes: row.io_write_bytes,
            last_seen_at: row.last_seen_at,
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|s| s.unit_name.clone())
    } else {
        None
    };

    Ok(Json(ServicesPage {
        items,
        next_cursor,
        has_more,
    }))
}
