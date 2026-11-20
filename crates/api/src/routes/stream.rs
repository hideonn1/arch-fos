use std::convert::Infallible;
use std::time::Duration;

use arch_fos_common::{Finding, FindingStatus, Severity};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use serde::Deserialize;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;

use crate::routes::AppState;

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub after_id: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct StreamFindingRow {
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

/// Real-time Server-Sent Events (SSE) stream emitting newly recorded findings (US-21).
/// Supports automatic reconnection via `Last-Event-ID` or `?after_id=...`.
#[utoipa::path(
    get,
    path = "/api/v1/stream",
    tag = "findings",
    responses(
        (status = 200, description = "SSE stream of new findings", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn stream_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let header_last_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok());

    let explicit_start = header_last_id.or(query.after_id);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);

    tokio::spawn(async move {
        let mut cursor_id = match explicit_start {
            Some(id) => id,
            None => sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(id) FROM findings")
                .fetch_one(&state.pool)
                .await
                .ok()
                .flatten()
                .unwrap_or(0),
        };

        // Flush an initial SSE frame immediately so browser EventSource fires `onopen` right away.
        let init_ev = Event::default()
            .comment("connected")
            .retry(Duration::from_secs(3));
        if tx.send(Ok(init_ev)).await.is_err() {
            return;
        }

        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let rows: Vec<StreamFindingRow> = match sqlx::query_as(
                "SELECT id, ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence FROM findings WHERE id > ? ORDER BY id ASC LIMIT 50",
            )
            .bind(cursor_id)
            .fetch_all(&state.pool)
            .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            for row in rows {
                cursor_id = row.id;
                let finding = Finding {
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
                    evidence: serde_json::from_str(&row.evidence)
                        .unwrap_or(serde_json::Value::Null),
                };

                if let Ok(ev) = Event::default()
                    .id(finding.id.to_string())
                    .event("finding")
                    .json_data(&finding)
                    && tx.send(Ok(ev)).await.is_err()
                {
                    return;
                }
            }
        }
    });

    Sse::new(ReceiverStream::new(rx)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
