use arch_fos_common::{
    ApiErrorBody, AuthStatus, CollectorHealth, CreateSuppressionRequest, DnsQueriesPage, DnsQuery,
    EntityTimelineResponse, Event, EventsPage, Finding, FindingAuditEntry, FindingAuditResponse,
    FindingStatus, FindingsPage, Flow1m, FlowsPage, HealthResponse, InstallReason, Listener,
    ListenersPage, LoginRequest, MutationAck, OverviewSummary, Package, PackageSummary,
    PackagesPage, Rule, RulesPage, Service, ServicesPage, Severity, SeverityCounts, StatusCounts,
    Suppression, SuppressionsPage, ThreatFeedStatus, ThreatIntelStatusResponse, TimeSeriesPoint,
    TimelineEntitiesResponse, TimelineEntityRef, TimelineEntry, TopProcessTraffic, TopServiceUsage,
    UpdateFindingRequest,
};
use axum::Json;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Arch Forward Observations System API",
        version = "0.1.0",
        description = "Local unprivileged read-only REST API for Arch Linux security telemetry, package inventory, and system findings.",
        license(name = "MIT")
    ),
    paths(
        crate::routes::health::health_check,
        crate::routes::health::collector_health,
        crate::routes::auth::auth_me,
        crate::routes::auth::auth_login,
        crate::routes::auth::auth_logout,
        crate::routes::summary::get_summary,
        crate::routes::findings::list_findings,
        crate::routes::findings::update_finding_status,
        crate::routes::findings::list_finding_audit,
        crate::routes::stream::stream_findings,
        crate::routes::suppressions::list_suppressions,
        crate::routes::suppressions::create_suppression,
        crate::routes::suppressions::delete_suppression,
        crate::routes::events::list_events,
        crate::routes::packages::list_packages,
        crate::routes::services::list_services,
        crate::routes::listeners::list_listeners,
        crate::routes::flows::list_flows,
        crate::routes::dns::list_dns_queries,
        crate::routes::threat_intel::threat_intel_status,
        crate::routes::rules::list_rules,
        crate::routes::timeline::get_entity_timeline,
        crate::routes::timeline::list_timeline_entities,
    ),
    components(schemas(
        ApiErrorBody,
        AuthStatus,
        CollectorHealth,
        CreateSuppressionRequest,
        DnsQuery,
        DnsQueriesPage,
        EntityTimelineResponse,
        Event,
        EventsPage,
        Finding,
        FindingAuditEntry,
        FindingAuditResponse,
        FindingStatus,
        FindingsPage,
        Flow1m,
        FlowsPage,
        HealthResponse,
        InstallReason,
        Listener,
        ListenersPage,
        LoginRequest,
        MutationAck,
        OverviewSummary,
        Package,
        PackageSummary,
        PackagesPage,
        Rule,
        RulesPage,
        Service,
        ServicesPage,
        Severity,
        SeverityCounts,
        StatusCounts,
        Suppression,
        SuppressionsPage,
        ThreatFeedStatus,
        ThreatIntelStatusResponse,
        TimeSeriesPoint,
        TimelineEntitiesResponse,
        TimelineEntityRef,
        TimelineEntry,
        TopProcessTraffic,
        TopServiceUsage,
        UpdateFindingRequest,
    ))
)]
pub struct ApiDoc;

/// Serializes the OpenAPI document to pretty-printed JSON.
pub fn openapi_json_pretty() -> Result<String, serde_json::Error> {
    ApiDoc::openapi().to_pretty_json()
}

/// Serves the OpenAPI specification at `/api/v1/openapi.json`.
pub async fn serve_openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
