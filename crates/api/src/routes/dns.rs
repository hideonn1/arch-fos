use arch_fos_common::{ApiErrorBody, DnsQueriesPage, DnsQuery, TimeEntityFilterQuery};
use axum::Json;
use axum::extract::{Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{ApiError, AppState, normalize_limit, parse_i64_cursor};

#[derive(sqlx::FromRow)]
struct DnsRow {
    id: i64,
    ts: i64,
    pid: Option<i64>,
    uid: Option<i64>,
    comm: String,
    exe_path: Option<String>,
    package_name: Option<String>,
    qname: String,
    qtype: String,
    rcode: i64,
    entropy: f64,
}

/// Lists captured DNS queries attributed to processes with cursor pagination (US-17).
#[utoipa::path(
    get,
    path = "/api/v1/dns",
    tag = "network",
    params(TimeEntityFilterQuery),
    responses(
        (status = 200, description = "Paginated DNS queries", body = DnsQueriesPage),
        (status = 400, description = "Invalid query parameter", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_dns_queries(
    State(state): State<AppState>,
    Query(query): Query<TimeEntityFilterQuery>,
) -> Result<Json<DnsQueriesPage>, ApiError> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_i64_cursor(query.cursor.as_deref())?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT id, ts, pid, uid, comm, exe_path, package_name, qname, qtype, rcode, entropy FROM dns_queries WHERE 1=1",
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
    if let Some(ref entity_id) = query.entity_id {
        qb.push(" AND (comm = ")
            .push_bind(entity_id)
            .push(" OR qname = ")
            .push_bind(entity_id)
            .push(")");
    }

    qb.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

    let rows: Vec<DnsRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<DnsQuery> = rows
        .into_iter()
        .take(take_count)
        .map(|r| DnsQuery {
            id: r.id,
            ts: r.ts,
            pid: r.pid,
            uid: r.uid,
            comm: r.comm,
            exe_path: r.exe_path,
            package_name: r.package_name,
            qname: r.qname,
            qtype: r.qtype,
            rcode: r.rcode,
            entropy: r.entropy,
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|d| d.id.to_string())
    } else {
        None
    };

    Ok(Json(DnsQueriesPage {
        items,
        next_cursor,
        has_more,
    }))
}
