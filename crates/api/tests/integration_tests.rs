use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arch_fos_api::auth::AuthState;
use arch_fos_api::build_router;
use arch_fos_api::db::open_readonly_pool;
use arch_fos_api::routes::AppState;
use arch_fos_common::{
    AuthStatus, CollectorCommand, CollectorHealth, CollectorResponse, DnsQueriesPage,
    EntityTimelineResponse, EventsPage, FindingAuditResponse, FindingsPage, FlowsPage,
    ListenersPage, MutationAck, OverviewSummary, PackagesPage, RulesPage, ServicesPage,
    SuppressionsPage, ThreatIntelStatusResponse, TimelineEntitiesResponse,
};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower::ServiceExt;

fn temp_db_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("arch_fos_it_{name}_{nanos}.db"))
}

async fn setup_writer_db(path: &std::path::Path) -> SqlitePool {
    let dsn = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&dsn)
        .expect("dsn")
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect writer");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate first");
    // Verify idempotency (US-02)
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate second idempotent");
    pool
}

fn cleanup_db(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

async fn json_body<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("parse json body")
}

async fn login(app: &axum::Router, token: &str) -> (String, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"token":"{token}"}}"#)))
        .expect("req");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie header")
        .to_str()
        .expect("utf8 cookie")
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let cookie_pair = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();

    let status: AuthStatus = json_body(resp).await;
    assert!(status.authenticated);
    let csrf = status.csrf_token.expect("csrf token");
    (cookie_pair, csrf)
}

#[tokio::test]
async fn readonly_db_enforced_and_auth_csrf_csp_work() {
    let db_path = temp_db_path("auth_ro");
    let writer = setup_writer_db(&db_path).await;
    writer.close().await;

    let ro_pool = open_readonly_pool(&db_path).await.expect("open ro");
    let write_attempt = sqlx::query(
        "INSERT INTO rules (id, name, description, severity, enabled, config, updated_at) VALUES ('r1', 'n', 'd', 'info', 1, '{}', 1)",
    )
    .execute(&ro_pool)
    .await;
    assert!(
        write_attempt.is_err(),
        "API read-only pool must reject writes"
    );

    let state = AppState {
        pool: ro_pool,
        auth: AuthState::new("super-secret-local-token".to_string()),
        collector_socket: PathBuf::from("/nonexistent/collector.sock"),
    };
    let app = build_router(state, None);

    // Unauthenticated request -> 401 + security headers
    let unauth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        unauth_resp
            .headers()
            .contains_key("content-security-policy")
    );
    assert_eq!(
        unauth_resp
            .headers()
            .get(header::X_FRAME_OPTIONS)
            .unwrap()
            .to_str()
            .unwrap(),
        "DENY"
    );
    assert_eq!(
        unauth_resp
            .headers()
            .get("referrer-policy")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-referrer"
    );

    // Cross-origin login rejected -> 403
    let evil_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"token":"super-secret-local-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evil_login.status(), StatusCode::FORBIDDEN);

    // Invalid token -> 401
    let bad_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"token":"wrong-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_login.status(), StatusCode::UNAUTHORIZED);

    // Valid login
    let (cookie, csrf) = login(&app, "super-secret-local-token").await;

    // Logout without CSRF -> 403
    let logout_no_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_no_csrf.status(), StatusCode::FORBIDDEN);

    // Logout with CSRF -> 200 and session invalidated
    let logout_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_ok.status(), StatusCode::OK);

    let after_logout = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/summary")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);

    cleanup_db(&db_path);
}

#[tokio::test]
async fn pagination_filters_and_openapi_endpoints() {
    let db_path = temp_db_path("endpoints");
    let writer = setup_writer_db(&db_path).await;

    for i in 1..=5_i64 {
        let sev = if i % 2 == 0 { "high" } else { "low" };
        sqlx::query(
            "INSERT INTO findings (ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence) VALUES (?, ?, ?, ?, 'new', 'package', ?, ?, 'sum', '{}')",
        )
        .bind(1_700_000_000_000 + i * 1000)
        .bind(1_700_000_000_000 + i * 1000)
        .bind(format!("rule_{i}"))
        .bind(sev)
        .bind(format!("pkg-{i}"))
        .bind(format!("Finding {i}"))
        .execute(&writer)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO events (ts, type, severity, source, entity_type, entity_id, payload) VALUES (?, 'pkg_test', ?, 'test', 'package', ?, '{}')",
        )
        .bind(1_700_000_000_000 + i * 1000)
        .bind(sev)
        .bind(format!("pkg-{i}"))
        .execute(&writer)
        .await
        .unwrap();
    }

    sqlx::query(
        "INSERT INTO packages (name, version, repo, is_foreign, install_date, reason, description, size_bytes, files, first_seen_at, last_seen_at) VALUES ('aur-pkg', '1.0-1', NULL, 1, 1700000000000, 'explicit', 'AUR tool', 100, '[\"usr/bin/aur\"]', 1000, 1000), ('core-pkg', '2.0-1', 'core', 0, 1700000000000, 'dependency', 'Core lib', 200, '[]', 1000, 1000)",
    )
    .execute(&writer)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO services (unit_name, active_state, sub_state, unit_file_state, cpu_usage_ns, memory_bytes, io_read_bytes, io_write_bytes, last_seen_at) VALUES ('sshd.service', 'active', 'running', 'enabled', 5000, 4096, 0, 0, 1000)",
    )
    .execute(&writer)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO flows_1m (bucket_ts, ts, pid, uid, comm, exe_path, src_ip, dst_ip, dst_port, protocol, bytes_tx, bytes_rx, packets, entity_type, entity_id) VALUES (1700000040000, 1700000041000, 123, 1000, 'curl', '/usr/bin/curl', '127.0.0.1', '1.1.1.1', 443, 'tcp', 1024, 2048, 10, 'process', '123')",
    )
    .execute(&writer)
    .await
    .unwrap();

    writer.close().await;

    let ro_pool = open_readonly_pool(&db_path).await.unwrap();
    let app = build_router(
        AppState {
            pool: ro_pool,
            auth: AuthState::new("tok".to_string()),
            collector_socket: PathBuf::from("/nonexistent/collector.sock"),
        },
        None,
    );

    let (cookie, _) = login(&app, "tok").await;

    // Cursor pagination on events (limit=2)
    let page1_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?limit=2")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page1: EventsPage = json_body(page1_resp).await;
    assert_eq!(page1.items.len(), 2);
    assert!(page1.has_more);
    let cursor = page1.next_cursor.unwrap();

    let page2_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/events?limit=2&cursor={cursor}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page2: EventsPage = json_body(page2_resp).await;
    assert_eq!(page2.items.len(), 2);
    assert!(page2.items[0].id < page1.items[1].id);

    // Filter findings by severity=high
    let high_findings_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings?severity=high")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let high_findings: FindingsPage = json_body(high_findings_resp).await;
    assert_eq!(high_findings.items.len(), 2);

    // Filter packages by foreign_only=true
    let pkgs_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/packages?foreign_only=true")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let pkgs: PackagesPage = json_body(pkgs_resp).await;
    assert_eq!(pkgs.items.len(), 1);
    assert_eq!(pkgs.items[0].name, "aur-pkg");

    // Services and flows endpoints
    let svcs_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/services")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let svcs: ServicesPage = json_body(svcs_resp).await;
    assert_eq!(svcs.items.len(), 1);

    let flows_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/flows")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let flows: FlowsPage = json_body(flows_resp).await;
    assert_eq!(flows.items.len(), 1);

    // OpenAPI spec
    let openapi_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(openapi_resp.status(), StatusCode::OK);
    let openapi_json: serde_json::Value = json_body(openapi_resp).await;
    assert!(openapi_json["paths"]["/api/v1/findings"].is_object());
    assert!(openapi_json["paths"]["/api/v1/packages"].is_object());
    assert!(openapi_json["paths"]["/api/v1/summary"].is_object());

    cleanup_db(&db_path);
}

#[tokio::test]
async fn summary_and_events_handle_100k_events_under_1s() {
    let db_path = temp_db_path("100k_perf");
    let writer = setup_writer_db(&db_path).await;

    let mut tx = writer.begin().await.unwrap();
    let base_ts = 1_700_000_000_000_i64;
    for i in 0..100_000_i64 {
        sqlx::query(
            "INSERT INTO events (ts, type, severity, source, entity_type, entity_id, payload) VALUES (?, 'net_flow', 'info', 'bench', 'process', '1', '{}')",
        )
        .bind(base_ts + (i % 600) * 60_000)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    writer.close().await;

    let ro_pool = open_readonly_pool(&db_path).await.unwrap();
    let app = build_router(
        AppState {
            pool: ro_pool,
            auth: AuthState::new("bench-tok".to_string()),
            collector_socket: PathBuf::from("/nonexistent/collector.sock"),
        },
        None,
    );
    let (cookie, _) = login(&app, "bench-tok").await;

    let start = Instant::now();
    let summary_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/summary")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(summary_resp.status(), StatusCode::OK);
    let summary: OverviewSummary = json_body(summary_resp).await;
    assert_eq!(summary.total_events, 100_000);
    assert!(!summary.time_series.is_empty());

    let events_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?limit=50")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(events_resp.status(), StatusCode::OK);
    let events: EventsPage = json_body(events_resp).await;
    assert_eq!(events.items.len(), 50);

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 1000,
        "100k events summary+page took {}ms (expected < 1000ms)",
        elapsed.as_millis()
    );

    cleanup_db(&db_path);
}

#[tokio::test]
async fn finding_management_suppressions_and_audit_work_over_ipc() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let db_path = temp_db_path("us23_ipc");
    let sock_path = std::env::temp_dir().join(format!(
        "arch_fos_it_sock_{}.sock",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&sock_path);

    let writer = setup_writer_db(&db_path).await;
    sqlx::query(
        "INSERT INTO findings (ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence) VALUES (1000, 1000, 'aur_low_votes', 'low', 'new', 'package', 'demo-aur', 'Low votes', 'sum', '{}')",
    )
    .execute(&writer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO listeners (ts, protocol, local_addr, local_port, pid, process_name, exe_path, package_name, entity_type, entity_id) VALUES (1000, 'tcp', '127.0.0.1', 8420, 42, 'arch-fos-api', '/usr/bin/arch-fos-api', 'arch-fos', 'listener', 'tcp:127.0.0.1:8420')",
    )
    .execute(&writer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO collector_health (id, last_heartbeat_at, cpu_time_ms, rss_bytes, db_size_bytes, last_ingest_latency_ms, status) VALUES (1, 1700000000000, 120, 10485760, 65536, 45, 'healthy')",
    )
    .execute(&writer)
    .await
    .unwrap();

    // Minimal sole-writer Unix socket loop using the writer pool
    let listener = UnixListener::bind(&sock_path).unwrap();
    let writer_clone = writer.clone();
    let ipc_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let pool = writer_clone.clone();
            tokio::spawn(async move {
                let (reader, mut w) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let cmd: CollectorCommand = serde_json::from_str(&line).unwrap();
                    let resp = match cmd {
                        CollectorCommand::UpdateFindingStatus {
                            finding_id,
                            status,
                            actor,
                            note,
                        } => {
                            let (old_status,): (String,) =
                                sqlx::query_as("SELECT status FROM findings WHERE id = ?")
                                    .bind(finding_id)
                                    .fetch_one(&pool)
                                    .await
                                    .unwrap();
                            sqlx::query(
                                "UPDATE findings SET status = ?, updated_at = 2000 WHERE id = ?",
                            )
                            .bind(status.as_str())
                            .bind(finding_id)
                            .execute(&pool)
                            .await
                            .unwrap();
                            sqlx::query("INSERT INTO finding_audit_log (finding_id, actor, action, old_status, new_status, note, ts) VALUES (?, ?, 'status_change', ?, ?, ?, 2000)")
                                .bind(finding_id)
                                .bind(actor)
                                .bind(old_status)
                                .bind(status.as_str())
                                .bind(note)
                                .execute(&pool)
                                .await
                                .unwrap();
                            CollectorResponse::Ok {
                                id: Some(finding_id),
                            }
                        }
                        CollectorCommand::CreateSuppression {
                            rule_id,
                            entity_type,
                            entity_id,
                            reason,
                            actor,
                            expires_at,
                        } => {
                            sqlx::query("INSERT INTO suppressions (rule_id, entity_type, entity_id, reason, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 2000, ?)")
                                .bind(rule_id)
                                .bind(entity_type)
                                .bind(entity_id)
                                .bind(reason)
                                .bind(actor)
                                .bind(expires_at)
                                .execute(&pool)
                                .await
                                .unwrap();
                            CollectorResponse::Ok { id: Some(1) }
                        }
                        CollectorCommand::DeleteSuppression { suppression_id, .. } => {
                            sqlx::query("DELETE FROM suppressions WHERE id = ?")
                                .bind(suppression_id)
                                .execute(&pool)
                                .await
                                .unwrap();
                            CollectorResponse::Ok {
                                id: Some(suppression_id),
                            }
                        }
                        CollectorCommand::RecordHookEvent { .. } => {
                            CollectorResponse::Ok { id: None }
                        }
                    };
                    let out = serde_json::to_string(&resp).unwrap();
                    w.write_all(out.as_bytes()).await.unwrap();
                    w.write_all(b"\n").await.unwrap();
                    w.flush().await.unwrap();
                }
            });
        }
    });

    let ro_pool = open_readonly_pool(&db_path).await.unwrap();
    let app = build_router(
        AppState {
            pool: ro_pool,
            auth: AuthState::new("tok23".to_string()),
            collector_socket: sock_path.clone(),
        },
        None,
    );
    let (cookie, csrf) = login(&app, "tok23").await;

    // PATCH /api/v1/findings/1 -> acknowledged
    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/api/v1/findings/1")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"status":"acknowledged","note":"revisando"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch_resp.status(), StatusCode::OK);
    let ack: MutationAck = json_body(patch_resp).await;
    assert!(ack.ok);

    // GET /api/v1/findings/1/audit
    let audit_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings/1/audit")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(audit_resp.status(), StatusCode::OK);
    let audit: FindingAuditResponse = json_body(audit_resp).await;
    assert_eq!(audit.items.len(), 1);
    assert_eq!(audit.items[0].old_status.as_deref(), Some("new"));
    assert_eq!(audit.items[0].new_status.as_deref(), Some("acknowledged"));

    // POST /api/v1/suppressions
    let sup_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/suppressions")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"rule_id":"aur_low_votes","entity_type":"package","entity_id":"demo-aur","reason":"esperado"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sup_resp.status(), StatusCode::OK);

    // GET /api/v1/suppressions
    let list_sup_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/suppressions")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sups: SuppressionsPage = json_body(list_sup_resp).await;
    assert_eq!(sups.items.len(), 1);
    assert_eq!(sups.items[0].rule_id, "aur_low_votes");

    // DELETE /api/v1/suppressions/1
    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/suppressions/1")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::OK);

    // GET /api/v1/listeners & /api/v1/health/collector
    let listeners_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/listeners")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listeners: ListenersPage = json_body(listeners_resp).await;
    assert_eq!(listeners.items.len(), 1);

    let health_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health/collector")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let col_health: CollectorHealth = json_body(health_resp).await;
    assert_eq!(col_health.status, "healthy");

    ipc_task.abort();
    writer.close().await;
    let _ = std::fs::remove_file(&sock_path);
    cleanup_db(&db_path);
}

#[tokio::test]
async fn sse_stream_dns_and_threat_intel_endpoints_work() {
    let db_path = temp_db_path("hito3_sse");
    let writer = setup_writer_db(&db_path).await;

    sqlx::query(
        "INSERT INTO dns_queries (ts, pid, uid, comm, exe_path, package_name, qname, qtype, rcode, entropy) VALUES (1700000000000, 42, 1000, 'curl', '/usr/bin/curl', 'curl', 'x9k2m8p4q7z0w3.evil.example', 'A', 3, 3.8)",
    )
    .execute(&writer)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO threat_indicators (indicator, indicator_type, feed, threat_label, updated_at) VALUES ('198.51.100.77', 'ip', 'feodo_tracker', 'Botnet', 1700000000000)",
    )
    .execute(&writer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO feed_cache (feed_name, etag, last_synced_at, payload) VALUES ('feodo_tracker', '\"e1\"', 1700000005000, '')",
    )
    .execute(&writer)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO findings (ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence) VALUES (1000, 1000, 'threat_intel_match', 'critical', 'new', 'process', 'curl', 'Threat match', 'sum', '{}')",
    )
    .execute(&writer)
    .await
    .unwrap();
    writer.close().await;

    let ro_pool = open_readonly_pool(&db_path).await.unwrap();
    let app = build_router(
        AppState {
            pool: ro_pool,
            auth: AuthState::new("tok3".to_string()),
            collector_socket: PathBuf::from("/nonexistent.sock"),
        },
        None,
    );
    let (cookie, _) = login(&app, "tok3").await;

    let dns_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/dns")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let dns: DnsQueriesPage = json_body(dns_resp).await;
    assert_eq!(dns.items.len(), 1);
    assert_eq!(dns.items[0].qname, "x9k2m8p4q7z0w3.evil.example");

    let ti_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/threat-intel/status")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ti: ThreatIntelStatusResponse = json_body(ti_resp).await;
    assert_eq!(ti.total_indicators, 1);
    assert_eq!(ti.feeds[0].last_synced_at, Some(1700000005000));

    // SSE stream with Last-Event-ID: 0 receives finding id=1
    let sse_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/stream")
                .header(header::COOKIE, &cookie)
                .header("last-event-id", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let content_type = sse_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(content_type.contains("text/event-stream"));

    let mut body = sse_resp.into_body();
    let mut found_event = false;
    for _ in 0..4 {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(3), body.frame())
            .await
            .expect("sse frame timeout")
            .expect("frame some")
            .expect("frame ok");
        let data = frame.into_data().expect("sse data bytes");
        let text = String::from_utf8_lossy(&data);
        if text.contains("event: finding") && text.contains("threat_intel_match") {
            found_event = true;
            break;
        }
    }
    assert!(found_event, "expected SSE finding event frame");

    cleanup_db(&db_path);
}

#[tokio::test]
async fn timeline_rules_and_embedded_spa_work() {
    let db_path = temp_db_path("hito4_timeline");
    let writer = setup_writer_db(&db_path).await;

    sqlx::query(
        "INSERT INTO events (ts, type, severity, source, entity_type, entity_id, payload) VALUES (1000, 'package_installed', 'info', 'collector:alpm', 'package', 'openssh', '{\"version\":\"9.9-1\"}')",
    )
    .execute(&writer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO listeners (ts, protocol, local_addr, local_port, pid, process_name, exe_path, package_name, entity_type, entity_id) VALUES (2000, 'tcp', '0.0.0.0', 22, 123, 'sshd', '/usr/bin/sshd', 'openssh', 'listener', 'tcp:0.0.0.0:22')",
    )
    .execute(&writer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO findings (ts, updated_at, rule_id, severity, status, entity_type, entity_id, title, summary, evidence) VALUES (3000, 3000, 'sigma_unowned_suid_added', 'critical', 'new', 'package', 'openssh', 'Suid check', 'sum', '{}')",
    )
    .execute(&writer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO rules (id, name, description, severity, enabled, config, updated_at, mitre_attack, source_file) VALUES ('sigma_unowned_suid_added', 'Unowned SUID', 'desc', 'critical', 1, '{}', 1000, '{\"technique_id\":\"T1548.001\"}', 'unowned_suid.yml')",
    )
    .execute(&writer)
    .await
    .unwrap();
    writer.close().await;

    let ro_pool = open_readonly_pool(&db_path).await.unwrap();
    let app = build_router(
        AppState {
            pool: ro_pool,
            auth: AuthState::new("tok4".to_string()),
            collector_socket: PathBuf::from("/nonexistent.sock"),
        },
        None,
    );

    // Embedded SPA served at / even with static_dir=None (US-25)
    let spa_resp = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(spa_resp.status(), StatusCode::OK);
    let spa_bytes = spa_resp.into_body().collect().await.unwrap().to_bytes();
    let spa_html = String::from_utf8_lossy(&spa_bytes);
    assert!(spa_html.contains("<div id=\"root\"></div>"));

    let (cookie, _) = login(&app, "tok4").await;

    let ents_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/timeline/entities")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ents: TimelineEntitiesResponse = json_body(ents_resp).await;
    assert!(ents.entities.iter().any(|e| e.entity_id == "openssh"));

    let tl_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/timeline?entity_type=package&entity_id=openssh")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let tl: EntityTimelineResponse = json_body(tl_resp).await;
    assert_eq!(tl.entries.len(), 3);
    assert_eq!(tl.entries[0].kind, "finding");
    assert_eq!(tl.entries[1].kind, "listener");
    assert_eq!(tl.entries[2].kind, "event");

    let rules_resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/rules")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let rules: RulesPage = json_body(rules_resp).await;
    assert_eq!(rules.items.len(), 1);
    assert_eq!(
        rules.items[0].mitre_attack.as_ref().unwrap()["technique_id"],
        "T1548.001"
    );

    cleanup_db(&db_path);
}
