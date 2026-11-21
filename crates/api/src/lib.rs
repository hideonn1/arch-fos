pub mod auth;
pub mod config;
pub mod db;
pub mod llm;
pub mod openapi;
pub mod rag;
pub mod routes;

use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode, Uri};
use axum::middleware;
use axum::routing::{delete, get, patch, post};
use rust_embed::RustEmbed;
use tower_http::services::{ServeDir, ServeFile};

use crate::auth::{require_auth, security_headers};
use crate::openapi::serve_openapi_json;
use crate::routes::AppState;
use crate::routes::ai::{
    explain_finding, list_suggested_actions, review_suggested_action, search_wiki_rag,
};
use crate::routes::auth::{auth_login, auth_logout, auth_me};
use crate::routes::dns::list_dns_queries;
use crate::routes::events::list_events;
use crate::routes::findings::{list_finding_audit, list_findings, update_finding_status};
use crate::routes::flows::list_flows;
use crate::routes::health::{collector_health, health_check};
use crate::routes::listeners::list_listeners;
use crate::routes::packages::list_packages;
use crate::routes::rules::list_rules;
use crate::routes::services::list_services;
use crate::routes::stream::stream_findings;
use crate::routes::summary::get_summary;
use crate::routes::suppressions::{create_suppression, delete_suppression, list_suppressions};
use crate::routes::threat_intel::threat_intel_status;
use crate::routes::timeline::{get_entity_timeline, list_timeline_entities};

/// Frontend SPA assets compiled into the binary for single-binary distribution (US-25).
#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct EmbeddedWebAssets;

/// Builds the complete Axum router with authentication, CSRF, security headers, and embedded SPA.
pub fn build_router(state: AppState, static_dir: Option<&Path>) -> Router {
    let protected_api = Router::new()
        .route("/summary", get(get_summary))
        .route("/health/collector", get(collector_health))
        .route("/findings", get(list_findings))
        .route("/findings/{id}", patch(update_finding_status))
        .route("/findings/{id}/audit", get(list_finding_audit))
        .route("/findings/{id}/explain", post(explain_finding))
        .route("/actions", get(list_suggested_actions))
        .route("/actions/{id}", patch(review_suggested_action))
        .route("/wiki/search", get(search_wiki_rag))
        .route(
            "/suppressions",
            get(list_suppressions).post(create_suppression),
        )
        .route("/suppressions/{id}", delete(delete_suppression))
        .route("/events", get(list_events))
        .route("/packages", get(list_packages))
        .route("/services", get(list_services))
        .route("/listeners", get(list_listeners))
        .route("/flows", get(list_flows))
        .route("/dns", get(list_dns_queries))
        .route("/threat-intel/status", get(threat_intel_status))
        .route("/rules", get(list_rules))
        .route("/timeline", get(get_entity_timeline))
        .route("/timeline/entities", get(list_timeline_entities))
        .route("/stream", get(stream_findings))
        .route("/auth/logout", post(auth_logout))
        .route_layer(middleware::from_fn_with_state(
            state.auth.clone(),
            require_auth,
        ));

    let public_api = Router::new()
        .route("/health", get(health_check))
        .route("/openapi.json", get(serve_openapi_json))
        .route("/auth/me", get(auth_me))
        .route("/auth/login", post(auth_login));

    let api_router = public_api.merge(protected_api);
    let mut app = Router::new().nest("/api/v1", api_router);

    if let Some(dir) = static_dir
        && dir.is_dir()
    {
        let index_file = dir.join("index.html");
        let serve = ServeDir::new(dir).fallback(ServeFile::new(index_file));
        app = app.fallback_service(serve);
    } else {
        app = app.fallback(serve_embedded_spa);
    }

    app.layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn serve_embedded_spa(uri: Uri) -> Response<Body> {
    let raw_path = uri.path().trim_start_matches('/');
    if raw_path.starts_with("api/") {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap_or_default();
    }

    let candidate = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if let Some(asset) = EmbeddedWebAssets::get(candidate) {
        return build_asset_response(candidate, asset.data.into_owned());
    }

    if let Some(index) = EmbeddedWebAssets::get("index.html") {
        return build_asset_response("index.html", index.data.into_owned());
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("frontend assets not embedded"))
        .unwrap_or_default()
}

fn build_asset_response(path: &str, bytes: Vec<u8>) -> Response<Body> {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, mime.as_ref())
        .body(Body::from(bytes))
        .unwrap_or_default()
}
