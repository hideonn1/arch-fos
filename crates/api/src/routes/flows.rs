use arch_fos_common::{ApiErrorBody, Flow1m, FlowsPage, TimeEntityFilterQuery};
use axum::Json;
use axum::extract::{Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{ApiError, AppState, normalize_limit, parse_i64_cursor};

#[derive(sqlx::FromRow)]
struct FlowRow {
    id: i64,
    bucket_ts: i64,
    ts: i64,
    pid: Option<i64>,
    uid: Option<i64>,
    comm: String,
    exe_path: Option<String>,
    src_ip: String,
    dst_ip: String,
    dst_port: i64,
    protocol: String,
    bytes_tx: i64,
    bytes_rx: i64,
    packets: i64,
    entity_type: String,
    entity_id: String,
}

/// Lists minute-aggregated network flows with cursor pagination and time/entity filters.
#[utoipa::path(
    get,
    path = "/api/v1/flows",
    tag = "flows",
    params(TimeEntityFilterQuery),
    responses(
        (status = 200, description = "Paginated flows", body = FlowsPage),
        (status = 400, description = "Invalid query parameter", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_flows(
    State(state): State<AppState>,
    Query(query): Query<TimeEntityFilterQuery>,
) -> Result<Json<FlowsPage>, ApiError> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_i64_cursor(query.cursor.as_deref())?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT id, bucket_ts, ts, pid, uid, comm, exe_path, src_ip, dst_ip, dst_port, protocol, bytes_tx, bytes_rx, packets, entity_type, entity_id FROM flows_1m WHERE 1=1",
    );

    if let Some(c) = cursor {
        qb.push(" AND id < ").push_bind(c);
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

    let rows: Vec<FlowRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<Flow1m> = rows
        .into_iter()
        .take(take_count)
        .map(|row| Flow1m {
            id: row.id,
            bucket_ts: row.bucket_ts,
            ts: row.ts,
            pid: row.pid,
            uid: row.uid,
            comm: row.comm,
            exe_path: row.exe_path,
            src_ip: row.src_ip,
            dst_ip: row.dst_ip,
            dst_port: row.dst_port,
            protocol: row.protocol,
            bytes_tx: row.bytes_tx,
            bytes_rx: row.bytes_rx,
            packets: row.packets,
            entity_type: row.entity_type,
            entity_id: row.entity_id,
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|f| f.id.to_string())
    } else {
        None
    };

    Ok(Json(FlowsPage {
        items,
        next_cursor,
        has_more,
    }))
}
