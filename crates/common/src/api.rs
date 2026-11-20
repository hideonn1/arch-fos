use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::models::{
    DnsQuery, Event, Finding, FindingAuditEntry, FindingStatus, Flow1m, Listener, Package, Rule,
    Service, Severity, Suppression, ThreatFeedStatus, TimelineEntityRef, TimelineEntry,
};

/// Macro to generate concrete cursor-paginated response structs with distinct OpenAPI schemas.
macro_rules! define_cursor_page {
    ($name:ident, $item:ty) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
        pub struct $name {
            pub items: Vec<$item>,
            pub next_cursor: Option<String>,
            pub has_more: bool,
        }
    };
}

define_cursor_page!(FindingsPage, Finding);
define_cursor_page!(EventsPage, Event);
define_cursor_page!(PackagesPage, Package);
define_cursor_page!(ServicesPage, Service);
define_cursor_page!(FlowsPage, Flow1m);
define_cursor_page!(ListenersPage, Listener);
define_cursor_page!(SuppressionsPage, Suppression);
define_cursor_page!(DnsQueriesPage, DnsQuery);
define_cursor_page!(RulesPage, Rule);

/// Query parameters for cursor-paginated endpoints with common filters.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct TimeEntityFilterQuery {
    /// Opaque pagination cursor returned by the previous page.
    pub cursor: Option<String>,
    /// Maximum number of items to return (default 50, max 200).
    pub limit: Option<u32>,
    /// Filter by severity (`info`, `low`, `medium`, `high`, `critical`).
    pub severity: Option<Severity>,
    /// Filter by finding status (`new`, `acknowledged`, `ignored`, `resolved`).
    pub status: Option<FindingStatus>,
    /// Start timestamp inclusive (Unix milliseconds).
    pub from: Option<i64>,
    /// End timestamp inclusive (Unix milliseconds).
    pub to: Option<i64>,
    /// Filter by entity type (e.g. `package`, `service`, `process`).
    pub entity_type: Option<String>,
    /// Filter by entity identifier.
    pub entity_id: Option<String>,
}

/// Query parameters for package inventory listing.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct PackageFilterQuery {
    /// Opaque pagination cursor (package name).
    pub cursor: Option<String>,
    /// Maximum number of items to return (default 50, max 200).
    pub limit: Option<u32>,
    /// Case-insensitive substring filter on package name or description.
    pub q: Option<String>,
    /// Filter only foreign (AUR / local) packages when true.
    pub foreign_only: Option<bool>,
    /// Filter by exact repository name (e.g. `core`, `extra`).
    pub repo: Option<String>,
}

/// Query parameters for services listing.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ServiceFilterQuery {
    /// Opaque pagination cursor (unit name).
    pub cursor: Option<String>,
    /// Maximum number of items to return (default 50, max 200).
    pub limit: Option<u32>,
    /// Filter by active state (e.g. `active`, `inactive`, `failed`).
    pub active_state: Option<String>,
}

/// Health check response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub db_read_only: bool,
}

/// Login request using the local API token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub token: String,
}

/// Current authentication session status and CSRF token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuthStatus {
    pub authenticated: bool,
    pub csrf_token: Option<String>,
}

/// Finding count grouped by severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeverityCounts {
    pub info: i64,
    pub low: i64,
    pub medium: i64,
    pub high: i64,
    pub critical: i64,
}

/// Finding count grouped by status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StatusCounts {
    pub new: i64,
    pub acknowledged: i64,
    pub ignored: i64,
    pub resolved: i64,
}

/// Package inventory summary metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackageSummary {
    pub total: i64,
    pub official: i64,
    pub foreign: i64,
    pub explicit: i64,
    pub dependency: i64,
    pub pending_cve_packages: i64,
    pub last_sync_ts: Option<i64>,
}

/// Top network process entry in the summary dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopProcessTraffic {
    pub comm: String,
    pub exe_path: Option<String>,
    pub total_tx_bytes: i64,
    pub total_rx_bytes: i64,
    pub total_bytes: i64,
}

/// Top resource-consuming service entry in the summary dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopServiceUsage {
    pub unit_name: String,
    pub active_state: String,
    pub cpu_usage_ns: i64,
    pub memory_bytes: i64,
}

/// Time-series bucket for dashboard charts (`uPlot`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TimeSeriesPoint {
    /// Bucket timestamp in Unix seconds (directly usable by uPlot).
    pub ts_sec: i64,
    pub events_count: i64,
    pub findings_count: i64,
    pub bytes_total: i64,
}

/// Overview summary payload returned by `GET /api/v1/summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OverviewSummary {
    pub total_events: i64,
    pub total_findings: i64,
    pub findings_by_severity: SeverityCounts,
    pub findings_by_status: StatusCounts,
    pub packages: PackageSummary,
    pub top_processes: Vec<TopProcessTraffic>,
    pub top_services: Vec<TopServiceUsage>,
    pub time_series: Vec<TimeSeriesPoint>,
}

/// Standard API error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorBody {
    pub error: String,
    pub message: String,
}

/// Request body to update a finding's status (US-23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateFindingRequest {
    pub status: FindingStatus,
    pub note: Option<String>,
}

/// Request body to create a suppression rule (US-23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateSuppressionRequest {
    pub rule_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub reason: Option<String>,
    /// Optional expiration timestamp in Unix milliseconds.
    pub expires_at: Option<i64>,
}

/// Response containing audit history for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingAuditResponse {
    pub items: Vec<FindingAuditEntry>,
}

/// Generic confirmation response for write commands forwarded to the collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MutationAck {
    pub ok: bool,
    pub id: Option<i64>,
}

/// Summary of configured threat intelligence feeds and last sync timestamps (US-18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreatIntelStatusResponse {
    pub feeds: Vec<ThreatFeedStatus>,
    pub total_indicators: i64,
}

/// Query parameters for entity timeline correlation (US-24).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct TimelineQuery {
    pub entity_type: String,
    pub entity_id: String,
    pub limit: Option<u32>,
}

/// Chronological correlated timeline for a package, service, process, or other entity (US-24).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EntityTimelineResponse {
    pub entity_type: String,
    pub entity_id: String,
    pub entries: Vec<TimelineEntry>,
}

/// List of entities with recent telemetry for quick timeline selection (US-24).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TimelineEntitiesResponse {
    pub entities: Vec<TimelineEntityRef>,
}
