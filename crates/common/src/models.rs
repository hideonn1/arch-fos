use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Severity level shared across events, findings, and rules.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns the canonical lowercase string representation stored in SQLite.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parses a severity from its canonical lowercase string representation.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Lifecycle status of a security or operational finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    New,
    Acknowledged,
    Ignored,
    Resolved,
}

impl FindingStatus {
    /// Returns the canonical lowercase string representation stored in SQLite.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Acknowledged => "acknowledged",
            Self::Ignored => "ignored",
            Self::Resolved => "resolved",
        }
    }

    /// Parses a finding status from its canonical lowercase string representation.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "new" => Some(Self::New),
            "acknowledged" => Some(Self::Acknowledged),
            "ignored" => Some(Self::Ignored),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// Reason a package is installed in the local ALPM database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstallReason {
    Explicit,
    Dependency,
}

impl InstallReason {
    /// Returns the canonical lowercase string representation stored in SQLite.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Dependency => "dependency",
        }
    }

    /// Parses an install reason from its canonical lowercase string representation.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "explicit" => Some(Self::Explicit),
            "dependency" => Some(Self::Dependency),
            _ => None,
        }
    }
}

/// Raw event emitted by the collector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Event {
    pub id: i64,
    /// Unix timestamp in milliseconds.
    pub ts: i64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub severity: Severity,
    pub source: String,
    pub entity_type: String,
    pub entity_id: String,
    pub payload: serde_json::Value,
}

/// Event input before persistence (without assigned row ID).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewEvent {
    pub ts: i64,
    pub event_type: String,
    pub severity: Severity,
    pub source: String,
    pub entity_type: String,
    pub entity_id: String,
    pub payload: serde_json::Value,
}

/// Security or system finding produced by deterministic rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Finding {
    pub id: i64,
    /// Creation timestamp in Unix milliseconds.
    pub ts: i64,
    /// Last update timestamp in Unix milliseconds.
    pub updated_at: i64,
    pub rule_id: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub entity_type: String,
    pub entity_id: String,
    pub title: String,
    pub summary: String,
    pub evidence: serde_json::Value,
}

/// Installed package metadata captured from ALPM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub repo: Option<String>,
    pub is_foreign: bool,
    /// Install date in Unix milliseconds (if available from ALPM).
    pub install_date: Option<i64>,
    pub reason: InstallReason,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub files: Vec<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
}

/// Systemd unit and cgroup consumption snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Service {
    pub unit_name: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub cpu_usage_ns: i64,
    pub memory_bytes: i64,
    pub io_read_bytes: i64,
    pub io_write_bytes: i64,
    pub last_seen_at: i64,
}

/// Listening socket attributed to a process and owning package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Listener {
    pub id: i64,
    pub ts: i64,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: i64,
    pub pid: Option<i64>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub package_name: Option<String>,
    pub entity_type: String,
    pub entity_id: String,
}

/// Network flow aggregated per minute and process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Flow1m {
    pub id: i64,
    /// Minute bucket start timestamp in Unix milliseconds.
    pub bucket_ts: i64,
    pub ts: i64,
    pub pid: Option<i64>,
    pub uid: Option<i64>,
    pub comm: String,
    pub exe_path: Option<String>,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
    pub protocol: String,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub packets: i64,
    pub entity_type: String,
    pub entity_id: String,
}

/// Rule configuration stored in the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub updated_at: i64,
    pub mitre_attack: Option<serde_json::Value>,
    pub source_file: Option<String>,
}

/// Suppression rule excluding a `(rule_id, entity_type, entity_id)` tuple until optional expiration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Suppression {
    pub id: i64,
    pub rule_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Audit log record tracking finding state transitions and suppression actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingAuditEntry {
    pub id: i64,
    pub finding_id: i64,
    pub actor: String,
    pub action: String,
    pub old_status: Option<String>,
    pub new_status: Option<String>,
    pub note: String,
    pub ts: i64,
}

/// Self-health metrics reported by the collector daemon (US-30).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CollectorHealth {
    pub last_heartbeat_at: i64,
    pub cpu_time_ms: i64,
    pub rss_bytes: i64,
    pub db_size_bytes: i64,
    pub last_ingest_latency_ms: i64,
    pub status: String,
}

/// Captured DNS query attributed to a process and package (US-17).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DnsQuery {
    pub id: i64,
    pub ts: i64,
    pub pid: Option<i64>,
    pub uid: Option<i64>,
    pub comm: String,
    pub exe_path: Option<String>,
    pub package_name: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub rcode: i64,
    pub entropy: f64,
}

/// Sync status for an external threat intelligence feed (US-18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreatFeedStatus {
    pub feed_name: String,
    pub indicator_count: i64,
    pub last_synced_at: Option<i64>,
}

/// Unified chronological entry in an entity timeline (US-24).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TimelineEntry {
    pub ts: i64,
    /// `event` | `finding` | `listener` | `flow` | `dns`
    pub kind: String,
    pub severity: Severity,
    pub source: String,
    pub title: String,
    pub summary: String,
    pub details: serde_json::Value,
}

/// Reference to a discoverable entity for timeline inspection (US-24).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TimelineEntityRef {
    pub entity_type: String,
    pub entity_id: String,
}

/// Approval lifecycle state for a suggested remediation command (US-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
}

impl ActionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Cited Arch Wiki passage returned by local RAG (US-27).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RagSource {
    pub title: String,
    pub url: String,
    pub section: String,
    pub snippet: String,
    pub score: f64,
}

/// Validated LLM explanation for a security finding (US-26).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct LlmExplanation {
    pub finding_id: i64,
    pub finding_hash: String,
    pub model: String,
    pub summary: String,
    pub risk: String,
    pub suggested_actions: Vec<String>,
    pub references: Vec<String>,
    pub rag_sources: Vec<RagSource>,
    pub cached: bool,
    pub created_at: i64,
}

/// Human-reviewed remediation command in `pending`/`approved`/`rejected` state (US-28).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SuggestedAction {
    pub id: i64,
    pub finding_id: i64,
    pub command: String,
    pub rationale: String,
    pub status: ActionStatus,
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_roundtrip() {
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(sev.as_str()), Some(sev));
        }
        assert_eq!(Severity::parse("unknown"), None);
    }

    #[test]
    fn finding_status_roundtrip() {
        for status in [
            FindingStatus::New,
            FindingStatus::Acknowledged,
            FindingStatus::Ignored,
            FindingStatus::Resolved,
        ] {
            assert_eq!(FindingStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(FindingStatus::parse("open"), None);
    }

    #[test]
    fn install_reason_roundtrip() {
        assert_eq!(
            InstallReason::parse(InstallReason::Explicit.as_str()),
            Some(InstallReason::Explicit)
        );
        assert_eq!(
            InstallReason::parse(InstallReason::Dependency.as_str()),
            Some(InstallReason::Dependency)
        );
        assert_eq!(InstallReason::parse("other"), None);
    }
}
