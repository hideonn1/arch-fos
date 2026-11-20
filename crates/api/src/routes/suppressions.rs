use arch_fos_common::{
    ApiErrorBody, CollectorCommand, CreateSuppressionRequest, MutationAck, Suppression,
    SuppressionsPage,
};
use axum::Json;
use axum::extract::{Path, State};

use crate::routes::{ApiError, AppState, send_collector_command};

#[derive(sqlx::FromRow)]
struct SuppressionRow {
    id: i64,
    rule_id: String,
    entity_type: String,
    entity_id: String,
    reason: String,
    created_by: String,
    created_at: i64,
    expires_at: Option<i64>,
}

/// Lists configured finding suppressions (US-23).
#[utoipa::path(
    get,
    path = "/api/v1/suppressions",
    tag = "findings",
    responses(
        (status = 200, description = "Suppression rules", body = SuppressionsPage),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_suppressions(
    State(state): State<AppState>,
) -> Result<Json<SuppressionsPage>, ApiError> {
    let rows: Vec<SuppressionRow> = sqlx::query_as(
        "SELECT id, rule_id, entity_type, entity_id, reason, created_by, created_at, expires_at FROM suppressions ORDER BY id DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|r| Suppression {
            id: r.id,
            rule_id: r.rule_id,
            entity_type: r.entity_type,
            entity_id: r.entity_id,
            reason: r.reason,
            created_by: r.created_by,
            created_at: r.created_at,
            expires_at: r.expires_at,
        })
        .collect();

    Ok(Json(SuppressionsPage {
        items,
        next_cursor: None,
        has_more: false,
    }))
}

/// Creates or updates a suppression rule for a `(rule_id, entity_type, entity_id)` tuple (US-23).
#[utoipa::path(
    post,
    path = "/api/v1/suppressions",
    tag = "findings",
    request_body = CreateSuppressionRequest,
    responses(
        (status = 200, description = "Suppression rule created", body = MutationAck),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
        (status = 403, description = "CSRF validation failed", body = ApiErrorBody),
    )
)]
pub async fn create_suppression(
    State(state): State<AppState>,
    Json(body): Json<CreateSuppressionRequest>,
) -> Result<Json<MutationAck>, ApiError> {
    if body.rule_id.trim().is_empty()
        || body.entity_type.trim().is_empty()
        || body.entity_id.trim().is_empty()
    {
        return Err(ApiError::bad_request(
            "rule_id, entity_type and entity_id must be non-empty",
        ));
    }

    let cmd = CollectorCommand::CreateSuppression {
        rule_id: body.rule_id.trim().to_string(),
        entity_type: body.entity_type.trim().to_string(),
        entity_id: body.entity_id.trim().to_string(),
        reason: body.reason.unwrap_or_default(),
        actor: "local-admin".to_string(),
        expires_at: body.expires_at,
    };
    let id = send_collector_command(&state.collector_socket, cmd).await?;
    Ok(Json(MutationAck { ok: true, id }))
}

/// Removes an existing suppression rule (US-23).
#[utoipa::path(
    delete,
    path = "/api/v1/suppressions/{id}",
    tag = "findings",
    params(
        ("id" = i64, Path, description = "Suppression ID")
    ),
    responses(
        (status = 200, description = "Suppression removed", body = MutationAck),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
        (status = 403, description = "CSRF validation failed", body = ApiErrorBody),
        (status = 404, description = "Suppression not found", body = ApiErrorBody),
    )
)]
pub async fn delete_suppression(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<MutationAck>, ApiError> {
    let cmd = CollectorCommand::DeleteSuppression {
        suppression_id: id,
        actor: "local-admin".to_string(),
    };
    let deleted_id = send_collector_command(&state.collector_socket, cmd).await?;
    Ok(Json(MutationAck {
        ok: true,
        id: deleted_id,
    }))
}
