use std::collections::BTreeSet;

use arch_fos_common::{
    ApiErrorBody, EntityTimelineResponse, Severity, TimelineEntitiesResponse, TimelineEntityRef,
    TimelineEntry, TimelineQuery,
};
use axum::Json;
use axum::extract::{Query, State};
use serde_json::json;

use crate::routes::{ApiError, AppState, normalize_limit};

#[derive(sqlx::FromRow)]
struct TimelineEventRow {
    ts: i64,
    #[sqlx(rename = "type")]
    event_type: String,
    severity: String,
    source: String,
    payload: String,
}

#[derive(sqlx::FromRow)]
struct TimelineFindingRow {
    ts: i64,
    rule_id: String,
    severity: String,
    status: String,
    title: String,
    summary: String,
    evidence: String,
}

#[derive(sqlx::FromRow)]
struct TimelineListenerRow {
    ts: i64,
    protocol: String,
    local_addr: String,
    local_port: i64,
    pid: Option<i64>,
    process_name: Option<String>,
    package_name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct TimelineFlowRow {
    ts: i64,
    pid: Option<i64>,
    comm: String,
    dst_ip: String,
    dst_port: i64,
    protocol: String,
    bytes_tx: i64,
    bytes_rx: i64,
    packets: i64,
}

#[derive(sqlx::FromRow)]
struct TimelineDnsRow {
    ts: i64,
    comm: String,
    qname: String,
    qtype: String,
    rcode: i64,
    entropy: f64,
}

/// Returns a unified chronological timeline correlating events, findings, listeners, flows, and DNS
/// for a single package, service, process, or persistence entity (US-24).
#[utoipa::path(
    get,
    path = "/api/v1/timeline",
    tag = "timeline",
    params(TimelineQuery),
    responses(
        (status = 200, description = "Correlated entity timeline", body = EntityTimelineResponse),
        (status = 400, description = "Invalid query parameter", body = ApiErrorBody),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn get_entity_timeline(
    State(state): State<AppState>,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<EntityTimelineResponse>, ApiError> {
    let entity_type = query.entity_type.trim().to_string();
    let entity_id = query.entity_id.trim().to_string();
    if entity_type.is_empty() || entity_id.is_empty() {
        return Err(ApiError::bad_request(
            "entity_type and entity_id must be non-empty",
        ));
    }

    let limit = normalize_limit(query.limit);
    let mut entries = Vec::new();

    // 1. Events
    let events: Vec<TimelineEventRow> = sqlx::query_as(
        "SELECT ts, type, severity, source, payload FROM events WHERE entity_type = ? AND entity_id = ? ORDER BY ts DESC LIMIT ?",
    )
    .bind(&entity_type)
    .bind(&entity_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    for ev in events {
        let payload: serde_json::Value =
            serde_json::from_str(&ev.payload).unwrap_or(serde_json::Value::Null);
        entries.push(TimelineEntry {
            ts: ev.ts,
            kind: "event".to_string(),
            severity: Severity::parse(&ev.severity).unwrap_or(Severity::Info),
            source: ev.source,
            title: format!("Evento: {}", ev.event_type),
            summary: payload.to_string(),
            details: payload,
        });
    }

    // 2. Findings
    let findings: Vec<TimelineFindingRow> = sqlx::query_as(
        "SELECT ts, rule_id, severity, status, title, summary, evidence FROM findings WHERE entity_type = ? AND entity_id = ? ORDER BY ts DESC LIMIT ?",
    )
    .bind(&entity_type)
    .bind(&entity_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    for f in findings {
        entries.push(TimelineEntry {
            ts: f.ts,
            kind: "finding".to_string(),
            severity: Severity::parse(&f.severity).unwrap_or(Severity::Info),
            source: f.rule_id,
            title: format!("[{}] {}", f.status, f.title),
            summary: f.summary,
            details: serde_json::from_str(&f.evidence).unwrap_or(serde_json::Value::Null),
        });
    }

    // 3. Listeners (match by entity_id, package_name, or process_name)
    let listeners: Vec<TimelineListenerRow> = sqlx::query_as(
        "SELECT ts, protocol, local_addr, local_port, pid, process_name, package_name FROM listeners WHERE entity_id = ? OR package_name = ? OR process_name = ? ORDER BY ts DESC LIMIT ?",
    )
    .bind(&entity_id)
    .bind(&entity_id)
    .bind(&entity_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    for l in listeners {
        entries.push(TimelineEntry {
            ts: l.ts,
            kind: "listener".to_string(),
            severity: if l.local_addr == "0.0.0.0" || l.local_addr == "::" {
                Severity::Medium
            } else {
                Severity::Info
            },
            source: "sock_diag".to_string(),
            title: format!(
                "Puerto en escucha {}:{} ({})",
                l.local_addr, l.local_port, l.protocol
            ),
            summary: format!(
                "Proceso {} (PID {}) • Paquete {}",
                l.process_name.as_deref().unwrap_or("?"),
                l.pid.map_or_else(|| "?".to_string(), |p| p.to_string()),
                l.package_name.as_deref().unwrap_or("desconocido")
            ),
            details: json!({
                "protocol": l.protocol,
                "local_addr": l.local_addr,
                "local_port": l.local_port,
                "pid": l.pid,
                "process_name": l.process_name,
                "package_name": l.package_name,
            }),
        });
    }

    // 4. Network flows (match comm or entity_id)
    let flows: Vec<TimelineFlowRow> = sqlx::query_as(
        "SELECT ts, pid, comm, dst_ip, dst_port, protocol, bytes_tx, bytes_rx, packets FROM flows_1m WHERE comm = ? OR entity_id = ? ORDER BY ts DESC LIMIT ?",
    )
    .bind(&entity_id)
    .bind(&entity_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    for fl in flows {
        entries.push(TimelineEntry {
            ts: fl.ts,
            kind: "flow".to_string(),
            severity: Severity::Info,
            source: "flows_1m".to_string(),
            title: format!("Conexión {} → {}:{}", fl.comm, fl.dst_ip, fl.dst_port),
            summary: format!(
                "{} • TX {} B / RX {} B ({} paquetes)",
                fl.protocol, fl.bytes_tx, fl.bytes_rx, fl.packets
            ),
            details: json!({
                "pid": fl.pid,
                "dst_ip": fl.dst_ip,
                "dst_port": fl.dst_port,
                "protocol": fl.protocol,
                "bytes_tx": fl.bytes_tx,
                "bytes_rx": fl.bytes_rx,
            }),
        });
    }

    // 5. DNS queries (match comm or package_name)
    let dns_rows: Vec<TimelineDnsRow> = sqlx::query_as(
        "SELECT ts, comm, qname, qtype, rcode, entropy FROM dns_queries WHERE comm = ? OR package_name = ? ORDER BY ts DESC LIMIT ?",
    )
    .bind(&entity_id)
    .bind(&entity_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    for d in dns_rows {
        entries.push(TimelineEntry {
            ts: d.ts,
            kind: "dns".to_string(),
            severity: if d.rcode == 3 || d.entropy >= 3.6 {
                Severity::Medium
            } else {
                Severity::Info
            },
            source: "dns".to_string(),
            title: format!("DNS {} ({}) por {}", d.qname, d.qtype, d.comm),
            summary: format!("rcode={} • entropía={:.2}", d.rcode, d.entropy),
            details: json!({
                "qname": d.qname,
                "qtype": d.qtype,
                "rcode": d.rcode,
                "entropy": d.entropy,
            }),
        });
    }

    entries.sort_by_key(|e| std::cmp::Reverse(e.ts));
    entries.truncate(usize::try_from(limit).unwrap_or(50));

    Ok(Json(EntityTimelineResponse {
        entity_type,
        entity_id,
        entries,
    }))
}

/// Lists known entities from findings, events, and processes for timeline selection (US-24).
#[utoipa::path(
    get,
    path = "/api/v1/timeline/entities",
    tag = "timeline",
    responses(
        (status = 200, description = "Discoverable entities", body = TimelineEntitiesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_timeline_entities(
    State(state): State<AppState>,
) -> Result<Json<TimelineEntitiesResponse>, ApiError> {
    let mut set: BTreeSet<(String, String)> = BTreeSet::new();

    let finding_ents: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT entity_type, entity_id FROM findings ORDER BY id DESC LIMIT 40",
    )
    .fetch_all(&state.pool)
    .await?;
    for pair in finding_ents {
        set.insert(pair);
    }

    let event_ents: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT entity_type, entity_id FROM events ORDER BY id DESC LIMIT 40",
    )
    .fetch_all(&state.pool)
    .await?;
    for pair in event_ents {
        set.insert(pair);
    }

    let flow_comms: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT comm FROM flows_1m ORDER BY id DESC LIMIT 25")
            .fetch_all(&state.pool)
            .await?;
    for (comm,) in flow_comms {
        set.insert(("process".to_string(), comm));
    }

    let entities = set
        .into_iter()
        .map(|(entity_type, entity_id)| TimelineEntityRef {
            entity_type,
            entity_id,
        })
        .collect();

    Ok(Json(TimelineEntitiesResponse { entities }))
}
