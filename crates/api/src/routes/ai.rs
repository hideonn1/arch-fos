use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::{
    ActionFilterQuery, ActionStatus, ApiErrorBody, CollectorCommand, ExplainFindingRequest,
    Finding, FindingStatus, LlmExplanation, MutationAck, RagSource, ReviewActionRequest, Severity,
    SuggestedAction, SuggestedActionsPage, WikiSearchQuery, WikiSearchResponse,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use sqlx::{QueryBuilder, Sqlite};

use crate::llm::{compute_finding_hash, explain_finding_with_ollama, try_ollama_embed};
use crate::rag::search_arch_wiki;
use crate::routes::{ApiError, AppState, normalize_limit, send_collector_command};

#[derive(sqlx::FromRow)]
struct FindingLookupRow {
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
struct CachedExplanationRow {
    finding_hash: String,
    finding_id: i64,
    model: String,
    summary: String,
    risk: String,
    suggested_actions: String,
    references_json: String,
    rag_sources: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct SuggestedActionRow {
    id: i64,
    finding_id: i64,
    command: String,
    rationale: String,
    status: String,
    decided_by: Option<String>,
    decided_at: Option<i64>,
    created_at: i64,
}

/// Explains a finding using the local Ollama LLM (`qwen2.5-coder:14b` by default) enriched with
/// offline Arch Wiki RAG citations and cached by finding hash (US-26, US-27, US-28).
#[utoipa::path(
    post,
    path = "/api/v1/findings/{id}/explain",
    tag = "ai",
    params(
        ("id" = i64, Path, description = "Finding ID")
    ),
    request_body = ExplainFindingRequest,
    responses(
        (status = 200, description = "Validated LLM explanation", body = LlmExplanation),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
        (status = 403, description = "CSRF validation failed", body = ApiErrorBody),
        (status = 404, description = "Finding not found", body = ApiErrorBody),
        (status = 502, description = "Ollama unavailable or invalid response", body = ApiErrorBody),
    )
)]
pub async fn explain_finding(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<ExplainFindingRequest>>,
) -> Result<Json<LlmExplanation>, ApiError> {
    let force_refresh = body.and_then(|b| b.force_refresh).unwrap_or(false);

    let row: Option<FindingLookupRow> = sqlx::query_as(
        "SELECT id, ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence FROM findings WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(r) = row else {
        return Err(ApiError::not_found(format!("finding {id} not found")));
    };

    let finding = Finding {
        id: r.id,
        ts: r.ts,
        updated_at: r.updated_at,
        rule_id: r.rule_id,
        severity: Severity::parse(&r.severity).unwrap_or(Severity::Info),
        status: FindingStatus::parse(&r.status).unwrap_or(FindingStatus::New),
        entity_type: r.entity_type,
        entity_id: r.entity_id,
        title: r.title,
        summary: r.summary,
        evidence: serde_json::from_str(&r.evidence).unwrap_or(serde_json::Value::Null),
    };

    let finding_hash = compute_finding_hash(&finding, &state.llm.model);

    if !force_refresh {
        let cached: Option<CachedExplanationRow> = sqlx::query_as(
            "SELECT finding_hash, finding_id, model, summary, risk, suggested_actions, references_json, rag_sources, created_at FROM llm_explanations WHERE finding_hash = ?",
        )
        .bind(&finding_hash)
        .fetch_optional(&state.pool)
        .await?;

        if let Some(c) = cached {
            return Ok(Json(LlmExplanation {
                finding_id: c.finding_id,
                finding_hash: c.finding_hash,
                model: c.model,
                summary: c.summary,
                risk: c.risk,
                suggested_actions: serde_json::from_str(&c.suggested_actions).unwrap_or_default(),
                references: serde_json::from_str(&c.references_json).unwrap_or_default(),
                rag_sources: serde_json::from_str(&c.rag_sources).unwrap_or_default(),
                cached: true,
                created_at: c.created_at,
            }));
        }
    }

    // US-27: Retrieve relevant Arch Wiki passages (vector if embed model available, else lexical)
    let rag_query = format!(
        "{} {} {} {}",
        finding.rule_id, finding.entity_type, finding.title, finding.summary
    );
    let q_emb = try_ollama_embed(&state.llm, &rag_query).await;
    let rag_sources: Vec<RagSource> =
        search_arch_wiki(&state.pool, &rag_query, q_emb.as_deref(), 3).await?;

    // US-26: Invoke local Ollama and strictly validate output schema & safety
    let validated = explain_finding_with_ollama(&state.llm, &finding, &rag_sources)
        .await
        .map_err(|err| ApiError {
            status: axum::http::StatusCode::BAD_GATEWAY,
            code: "llm_error",
            message: err.to_string(),
        })?;

    // Merge cited Arch Wiki URLs into references so sources are always verifiable
    let mut references = validated.references;
    for src in &rag_sources {
        if !references.contains(&src.url) {
            references.push(src.url.clone());
        }
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);

    // Best-effort cache write via sole-writer collector socket (also registers pending US-28 actions)
    let _ = send_collector_command(
        &state.collector_socket,
        CollectorCommand::SaveLlmExplanation {
            finding_id: finding.id,
            finding_hash: finding_hash.clone(),
            model: state.llm.model.clone(),
            summary: validated.summary.clone(),
            risk: validated.risk.clone(),
            suggested_actions: validated.suggested_actions.clone(),
            references: references.clone(),
            rag_sources: rag_sources.clone(),
        },
    )
    .await;

    Ok(Json(LlmExplanation {
        finding_id: finding.id,
        finding_hash,
        model: state.llm.model.clone(),
        summary: validated.summary,
        risk: validated.risk,
        suggested_actions: validated.suggested_actions,
        references,
        rag_sources,
        cached: false,
        created_at: now_ms,
    }))
}

/// Lists suggested remediation commands awaiting or having received human approval (US-28).
#[utoipa::path(
    get,
    path = "/api/v1/actions",
    tag = "ai",
    params(ActionFilterQuery),
    responses(
        (status = 200, description = "Suggested remediation actions", body = SuggestedActionsPage),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_suggested_actions(
    State(state): State<AppState>,
    Query(query): Query<ActionFilterQuery>,
) -> Result<Json<SuggestedActionsPage>, ApiError> {
    let limit = normalize_limit(query.limit);
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "SELECT id, finding_id, command, rationale, status, decided_by, decided_at, created_at FROM suggested_actions WHERE 1=1",
    );

    if let Some(status) = query.status {
        qb.push(" AND status = ").push_bind(status.as_str());
    }
    if let Some(fid) = query.finding_id {
        qb.push(" AND finding_id = ").push_bind(fid);
    }
    qb.push(" ORDER BY id DESC LIMIT ").push_bind(limit + 1);

    let rows: Vec<SuggestedActionRow> = qb.build_query_as().fetch_all(&state.pool).await?;
    let has_more = i64::try_from(rows.len()).unwrap_or(0) > limit;
    let take_count = usize::try_from(limit).unwrap_or(50);

    let items: Vec<SuggestedAction> = rows
        .into_iter()
        .take(take_count)
        .map(|r| SuggestedAction {
            id: r.id,
            finding_id: r.finding_id,
            command: r.command,
            rationale: r.rationale,
            status: ActionStatus::parse(&r.status).unwrap_or(ActionStatus::Pending),
            decided_by: r.decided_by,
            decided_at: r.decided_at,
            created_at: r.created_at,
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|a| a.id.to_string())
    } else {
        None
    };

    Ok(Json(SuggestedActionsPage {
        items,
        next_cursor,
        has_more,
    }))
}

/// Records explicit human approval or rejection for a suggested action without auto-executing it (US-28).
#[utoipa::path(
    patch,
    path = "/api/v1/actions/{id}",
    tag = "ai",
    params(
        ("id" = i64, Path, description = "Suggested Action ID")
    ),
    request_body = ReviewActionRequest,
    responses(
        (status = 200, description = "Action review recorded", body = MutationAck),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
        (status = 403, description = "CSRF validation failed", body = ApiErrorBody),
        (status = 404, description = "Action not found", body = ApiErrorBody),
    )
)]
pub async fn review_suggested_action(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ReviewActionRequest>,
) -> Result<Json<MutationAck>, ApiError> {
    let updated_id = send_collector_command(
        &state.collector_socket,
        CollectorCommand::ReviewSuggestedAction {
            action_id: id,
            status: body.status,
            actor: "local-admin".to_string(),
        },
    )
    .await?;
    Ok(Json(MutationAck {
        ok: true,
        id: updated_id,
    }))
}

/// Searches the offline Arch Wiki RAG index (US-27).
#[utoipa::path(
    get,
    path = "/api/v1/wiki/search",
    tag = "ai",
    params(WikiSearchQuery),
    responses(
        (status = 200, description = "Cited Arch Wiki search results", body = WikiSearchResponse),
        (status = 400, description = "Empty query", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn search_wiki_rag(
    State(state): State<AppState>,
    Query(query): Query<WikiSearchQuery>,
) -> Result<Json<WikiSearchResponse>, ApiError> {
    if query.q.trim().is_empty() {
        return Err(ApiError::bad_request("query 'q' must be non-empty"));
    }
    let limit = usize::try_from(query.limit.unwrap_or(5).clamp(1, 10)).unwrap_or(5);
    let q_emb = try_ollama_embed(&state.llm, &query.q).await;
    let items = search_arch_wiki(&state.pool, &query.q, q_emb.as_deref(), limit).await?;
    Ok(Json(WikiSearchResponse { items }))
}
