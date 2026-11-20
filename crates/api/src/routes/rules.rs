use arch_fos_common::{ApiErrorBody, Rule, RulesPage, Severity};
use axum::Json;
use axum::extract::State;

use crate::routes::{ApiError, AppState};

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: String,
    name: String,
    description: String,
    severity: String,
    enabled: i64,
    config: String,
    updated_at: i64,
    mitre_attack: Option<String>,
    source_file: Option<String>,
}

/// Lists active YAML Sigma detection rules and their MITRE ATT&CK mappings (US-29).
#[utoipa::path(
    get,
    path = "/api/v1/rules",
    tag = "rules",
    responses(
        (status = 200, description = "Configured detection rules", body = RulesPage),
        (status = 401, description = "Unauthorized", body = ApiErrorBody),
    )
)]
pub async fn list_rules(State(state): State<AppState>) -> Result<Json<RulesPage>, ApiError> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, name, description, severity, enabled, config, updated_at, mitre_attack, source_file FROM rules ORDER BY id ASC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|r| Rule {
            id: r.id,
            name: r.name,
            description: r.description,
            severity: Severity::parse(&r.severity).unwrap_or(Severity::Info),
            enabled: r.enabled != 0,
            config: serde_json::from_str(&r.config).unwrap_or(serde_json::Value::Null),
            updated_at: r.updated_at,
            mitre_attack: r
                .mitre_attack
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            source_file: r.source_file,
        })
        .collect();

    Ok(Json(RulesPage {
        items,
        next_cursor: None,
        has_more: false,
    }))
}
