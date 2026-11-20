use arch_fos_common::{
    ApiErrorBody, CollectorCommand, Finding, FindingAuditEntry, FindingAuditResponse,
    FindingStatus, FindingsPage, MutationAck, Severity, TimeEntityFilterQuery,
    UpdateFindingRequest,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::routes::{
    ApiError, AppState, normalize_limit, parse_i64_cursor, send_collector_command,
};

#[derive(sqlx::FromRow)]
struct FindingRow {
    id: i64,
    ts: i64,
    updated_at: i64,
    rule_id: String,
    severity: String,
    status: String,
    entity_type: String,
    entity_id: String,
    title: String,
    summary: String,
    evidence: String,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    finding_id: i64,
    actor: String,
    action: String,
    old_status: Option<String>,
    new_status: Option<String>,
    note: String,
    ts: i64,
}

/// Lists security findings with cursor pagination and severity/status/time/entity filters.
#[utoipa::path(
    get,
    path = "/api/v1/findings",
    tag = "findings",
    params(TimeEntityFilterQuery),
    responses(
        (status = 200, description = "Paginated findings", body = FindingsPage),
        (status = 400, description = "Invalid query parameter", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_findings(
    State(state): State<AppState>,
    Query(query): Query<TimeEntityFilterQuery>,
) -> Result<Json<FindingsPage>, ApiError> {
    let limit = normalize_limit(query.limit);
    let cursor = parse_i64_cursor(query.cursor.as_deref())?;

    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT id, ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence FROM findings WHERE 1=1",
    );

    if let Some(c) = cursor {
        qb.push(" AND id < ").push_bind(c);
    }
    if let Some(sev) = query.severity {
        qb.push(" AND severity = ").push_bind(sev.as_str());
    }
    if let Some(status) = query.status {
        qb.push(" AND status = ").push_bind(status.as_str());
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

    let rows: Vec<FindingRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<Finding> = rows
        .into_iter()
        .take(take_count)
        .map(|row| Finding {
            id: row.id,
            ts: row.ts,
            updated_at: row.updated_at,
            rule_id: row.rule_id,
            severity: Severity::parse(&row.severity).unwrap_or(Severity::Info),
            status: FindingStatus::parse(&row.status).unwrap_or(FindingStatus::New),
            entity_type: row.entity_type,
            entity_id: row.entity_id,
            title: row.title,
            summary: row.summary,
            evidence: serde_json::from_str(&row.evidence).unwrap_or(serde_json::Value::Null),
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|f| f.id.to_string())
    } else {
        None
    };

    Ok(Json(FindingsPage {
        items,
        next_cursor,
        has_more,
    }))
}

/// Updates a finding status (`new`, `acknowledged`, `ignored`, `resolved`) with audit logging (US-23).
#[utoipa::path(
    patch,
    path = "/api/v1/findings/{id}",
    tag = "findings",
    params(
        ("id" = i64, Path, description = "Finding ID")
    ),
    request_body = UpdateFindingRequest,
    responses(
        (status = 200, description = "Finding status updated", body = MutationAck),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
        (status = 403, description = "CSRF validation failed", body = ApiErrorBody),
        (status = 404, description = "Finding not found", body = ApiErrorBody),
    )
)]
pub async fn update_finding_status(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateFindingRequest>,
) -> Result<Json<MutationAck>, ApiError> {
    let cmd = CollectorCommand::UpdateFindingStatus {
        finding_id: id,
        status: body.status,
        actor: "local-admin".to_string(),
        note: body.note.unwrap_or_default(),
    };
    let updated_id = send_collector_command(&state.collector_socket, cmd).await?;
    Ok(Json(MutationAck {
        ok: true,
        id: updated_id,
    }))
}

/// Returns the audit trail for a specific finding (US-23).
#[utoipa::path(
    get,
    path = "/api/v1/findings/{id}/audit",
    tag = "findings",
    params(
        ("id" = i64, Path, description = "Finding ID")
    ),
    responses(
        (status = 200, description = "Finding audit entries", body = FindingAuditResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_finding_audit(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<FindingAuditResponse>, ApiError> {
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT id, finding_id, actor, action, old_status, new_status, note, ts FROM finding_audit_log WHERE finding_id = ? ORDER BY ts DESC, id DESC LIMIT 100",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|r| FindingAuditEntry {
            id: r.id,
            finding_id: r.finding_id,
            actor: r.actor,
            action: r.action,
            old_status: r.old_status,
            new_status: r.new_status,
            note: r.note,
            ts: r.ts,
        })
        .collect();

    Ok(Json(FindingAuditResponse { items }))
}
