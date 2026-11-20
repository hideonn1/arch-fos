use serde::{Deserialize, Serialize};

use crate::models::{FindingStatus, Severity};

/// Commands sent from the unprivileged API or CLI to the sole-writer collector over Unix socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CollectorCommand {
    UpdateFindingStatus {
        finding_id: i64,
        status: FindingStatus,
        actor: String,
        note: String,
    },
    CreateSuppression {
        rule_id: String,
        entity_type: String,
        entity_id: String,
        reason: String,
        actor: String,
        expires_at: Option<i64>,
    },
    DeleteSuppression {
        suppression_id: i64,
        actor: String,
    },
    RecordHookEvent {
        event_type: String,
        severity: Severity,
        entity_id: String,
        payload: serde_json::Value,
    },
}

/// Response returned by the collector control Unix socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CollectorResponse {
    Ok { id: Option<i64> },
    NotFound { message: String },
    Error { message: String },
}
