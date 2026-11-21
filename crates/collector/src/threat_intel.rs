use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arch_fos_common::Severity;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::db::{NewFinding, upsert_finding_respecting_suppression};
use crate::listeners::{load_exe_package_index, resolve_package_for_exe};

const FEODO_IP_FEED_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
const URLHAUS_AUTH_KEY_ENV: &str = "ARCH_FOS_ABUSECH_AUTH_KEY";
const FEED_CACHE_TTL_MS: i64 = 60 * 60 * 1000;

fn urlhaus_keyed_hostfile_url() -> Option<String> {
    let key = std::env::var(URLHAUS_AUTH_KEY_ENV).ok()?;
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!(
        "https://urlhaus-api.abuse.ch/v2/files/exports/{trimmed}/hostfile.txt"
    ))
}

/// Parsed threat intelligence indicator from abuse.ch feeds (US-18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatIndicator {
    pub indicator: String,
    pub indicator_type: String,
    pub feed: String,
    pub threat_label: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ThreatIntelStats {
    pub total_indicators: usize,
    pub critical_matches: usize,
}

/// Parses Feodo Tracker plain-text IP blocklist (`ipblocklist.txt`).
#[must_use]
pub fn parse_feodo_ipblocklist(body: &str) -> Vec<ThreatIndicator> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.parse::<std::net::IpAddr>().is_ok())
        .map(|ip| ThreatIndicator {
            indicator: ip.to_string(),
            indicator_type: "ip".to_string(),
            feed: "feodo_tracker".to_string(),
            threat_label: "Feodo Tracker Botnet C2".to_string(),
        })
        .collect()
}

/// Parses URLhaus hostfile (`127.0.0.1 malicious.example`) into domain/IP indicators.
#[must_use]
pub fn parse_urlhaus_hostfile(body: &str) -> Vec<ThreatIndicator> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _sinkhole = parts.next();
        let Some(host) = parts.next() else {
            continue;
        };
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() || normalized == "localhost" {
            continue;
        }
        let ind_type = if normalized.parse::<std::net::IpAddr>().is_ok() {
            "ip"
        } else {
            "domain"
        };
        out.push(ThreatIndicator {
            indicator: normalized,
            indicator_type: ind_type.to_string(),
            feed: "urlhaus".to_string(),
            threat_label: "URLhaus Malware Distribution".to_string(),
        });
    }
    out
}

#[derive(sqlx::FromRow)]
struct FlowTargetRow {
    comm: String,
    pid: Option<i64>,
    exe_path: Option<String>,
    dst_ip: String,
    dst_port: i64,
}

#[derive(sqlx::FromRow)]
struct DnsTargetRow {
    comm: String,
    pid: Option<i64>,
    exe_path: Option<String>,
    package_name: Option<String>,
    qname: String,
}

/// Refreshes Feodo Tracker and URLhaus feeds with ETag caching and matches recent flows + DNS.
pub async fn run_threat_intel_once(
    pool: &SqlitePool,
    offline: bool,
) -> Result<ThreatIntelStats, Box<dyn std::error::Error + Send + Sync>> {
    let now_ms = current_unix_ms();

    if !offline {
        sync_feed(
            pool,
            "feodo_tracker",
            FEODO_IP_FEED_URL,
            now_ms,
            parse_feodo_ipblocklist,
        )
        .await;
        if let Some(urlhaus_url) = urlhaus_keyed_hostfile_url() {
            sync_feed(
                pool,
                "urlhaus",
                &urlhaus_url,
                now_ms,
                parse_urlhaus_hostfile,
            )
            .await;
        } else {
            tracing::debug!(
                env = URLHAUS_AUTH_KEY_ENV,
                "skipping URLhaus v2 export (set optional abuse.ch Auth-Key env var to enable)"
            );
        }
    }

    let ind_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT indicator, indicator_type, feed, threat_label FROM threat_indicators",
    )
    .fetch_all(pool)
    .await?;

    if ind_rows.is_empty() {
        return Ok(ThreatIntelStats::default());
    }

    let total_indicators = ind_rows.len();
    let mut by_indicator: HashMap<String, Vec<ThreatIndicator>> = HashMap::new();
    for (indicator, indicator_type, feed, threat_label) in ind_rows {
        by_indicator
            .entry(indicator.clone())
            .or_default()
            .push(ThreatIndicator {
                indicator,
                indicator_type,
                feed,
                threat_label,
            });
    }

    let exe_index = load_exe_package_index(pool).await?;
    let window_start = now_ms.saturating_sub(24 * 60 * 60 * 1000);
    let mut matched = 0usize;
    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();

    // 1. Match flows_1m dst_ip against threat indicators
    let flow_rows: Vec<FlowTargetRow> = sqlx::query_as(
        r#"
        SELECT comm, pid, exe_path, dst_ip, dst_port
        FROM flows_1m
        WHERE ts >= ?
        ORDER BY id DESC
        LIMIT 5000
        "#,
    )
    .bind(window_start)
    .fetch_all(pool)
    .await?;

    for row in flow_rows {
        let FlowTargetRow {
            comm,
            pid,
            exe_path,
            dst_ip,
            dst_port,
        } = row;
        if let Some(hits) = by_indicator.get(&dst_ip)
            && seen_pairs.insert((comm.clone(), dst_ip.clone()))
        {
            let pkg = exe_path
                .as_deref()
                .and_then(|e| resolve_package_for_exe(e, &exe_index));
            let hit = &hits[0];
            let finding = NewFinding {
                ts: now_ms,
                rule_id: "threat_intel_match".to_string(),
                severity: Severity::Critical,
                entity_type: "process".to_string(),
                entity_id: comm.clone(),
                title: format!(
                    "Contacto con indicador malicioso {} ({}) desde {}",
                    dst_ip, hit.feed, comm
                ),
                summary: format!(
                    "Proceso {} (paquete: {}) contactó {}:{} listado en {} ({}).",
                    comm,
                    pkg.as_deref().unwrap_or("sin paquete"),
                    dst_ip,
                    dst_port,
                    hit.feed,
                    hit.threat_label
                ),
                evidence: json!({
                    "indicator": dst_ip,
                    "indicator_type": hit.indicator_type,
                    "feed": hit.feed,
                    "threat_label": hit.threat_label,
                    "comm": comm,
                    "pid": pid,
                    "exe_path": exe_path,
                    "package_name": pkg,
                    "dst_port": dst_port,
                }),
            };
            if upsert_finding_respecting_suppression(pool, &finding, now_ms)
                .await
                .unwrap_or(false)
            {
                matched += 1;
            }
        }
    }

    // 2. Match dns_queries qname against threat indicators
    let dns_rows: Vec<DnsTargetRow> = sqlx::query_as(
        r#"
            SELECT comm, pid, exe_path, package_name, qname
            FROM dns_queries
            WHERE ts >= ?
            ORDER BY id DESC
            LIMIT 5000
            "#,
    )
    .bind(window_start)
    .fetch_all(pool)
    .await?;

    for row in dns_rows {
        let DnsTargetRow {
            comm,
            pid,
            exe_path,
            package_name,
            qname,
        } = row;
        let normalized = qname.trim_end_matches('.').to_ascii_lowercase();
        if let Some(hits) = by_indicator.get(&normalized)
            && seen_pairs.insert((comm.clone(), normalized.clone()))
        {
            let pkg = package_name.or_else(|| {
                exe_path
                    .as_deref()
                    .and_then(|e| resolve_package_for_exe(e, &exe_index))
            });
            let hit = &hits[0];
            let finding = NewFinding {
                ts: now_ms,
                rule_id: "threat_intel_match".to_string(),
                severity: Severity::Critical,
                entity_type: "process".to_string(),
                entity_id: comm.clone(),
                title: format!(
                    "Consulta DNS a dominio malicioso {} ({}) desde {}",
                    normalized, hit.feed, comm
                ),
                summary: format!(
                    "Proceso {} (paquete: {}) consultó '{}' listado en {} ({}).",
                    comm,
                    pkg.as_deref().unwrap_or("sin paquete"),
                    normalized,
                    hit.feed,
                    hit.threat_label
                ),
                evidence: json!({
                    "indicator": normalized,
                    "indicator_type": hit.indicator_type,
                    "feed": hit.feed,
                    "threat_label": hit.threat_label,
                    "comm": comm,
                    "pid": pid,
                    "exe_path": exe_path,
                    "package_name": pkg,
                }),
            };
            if upsert_finding_respecting_suppression(pool, &finding, now_ms)
                .await
                .unwrap_or(false)
            {
                matched += 1;
            }
        }
    }

    info!(
        total_indicators,
        critical_matches = matched,
        "threat intelligence match cycle completed"
    );

    Ok(ThreatIntelStats {
        total_indicators,
        critical_matches: matched,
    })
}

async fn sync_feed<F>(pool: &SqlitePool, feed_name: &str, url: &str, now_ms: i64, parser: F)
where
    F: Fn(&str) -> Vec<ThreatIndicator>,
{
    let cached: Option<(Option<String>, i64)> =
        sqlx::query_as("SELECT etag, last_synced_at FROM feed_cache WHERE feed_name = ?")
            .bind(feed_name)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

    if let Some((_, last_synced)) = &cached
        && now_ms.saturating_sub(*last_synced) < FEED_CACHE_TTL_MS
    {
        return;
    }

    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("arch-fos-collector/0.1")
        .build()
    else {
        return;
    };

    let mut req = client.get(url);
    if let Some((Some(etag), _)) = &cached {
        req = req.header(IF_NONE_MATCH, etag);
    }

    match req.send().await {
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_MODIFIED => {
            let _ = sqlx::query("UPDATE feed_cache SET last_synced_at = ? WHERE feed_name = ?")
                .bind(now_ms)
                .bind(feed_name)
                .execute(pool)
                .await;
        }
        Ok(resp) if resp.status().is_success() => {
            let etag = resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let Ok(body) = resp.text().await else {
                return;
            };
            let indicators = parser(&body);
            if let Ok(mut tx) = pool.begin().await {
                let _ = sqlx::query("DELETE FROM threat_indicators WHERE feed = ?")
                    .bind(feed_name)
                    .execute(&mut *tx)
                    .await;
                for ind in indicators.iter().take(50_000) {
                    let _ = sqlx::query(
                        r#"
                        INSERT INTO threat_indicators (indicator, indicator_type, feed, threat_label, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(indicator, feed) DO UPDATE SET
                            threat_label = excluded.threat_label,
                            updated_at = excluded.updated_at
                        "#,
                    )
                    .bind(&ind.indicator)
                    .bind(&ind.indicator_type)
                    .bind(&ind.feed)
                    .bind(&ind.threat_label)
                    .bind(now_ms)
                    .execute(&mut *tx)
                    .await;
                }
                let _ = sqlx::query(
                    r#"
                    INSERT INTO feed_cache (feed_name, etag, last_synced_at, payload)
                    VALUES (?, ?, ?, '')
                    ON CONFLICT(feed_name) DO UPDATE SET
                        etag = excluded.etag,
                        last_synced_at = excluded.last_synced_at
                    "#,
                )
                .bind(feed_name)
                .bind(etag)
                .bind(now_ms)
                .execute(&mut *tx)
                .await;
                let _ = tx.commit().await;
            }
        }
        Ok(resp) => {
            warn!(feed = feed_name, status = %resp.status(), "threat feed returned non-success status");
        }
        Err(err) => {
            let safe_err = err.without_url();
            warn!(feed = feed_name, error = %safe_err, "failed to sync threat feed");
        }
    }
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_writer_pool;

    #[test]
    fn parses_feodo_and_urlhaus_feeds() {
        let feodo = "# comment\n192.0.2.55\nnot-an-ip\n198.51.100.12\n";
        let f_inds = parse_feodo_ipblocklist(feodo);
        assert_eq!(f_inds.len(), 2);
        assert_eq!(f_inds[0].indicator, "192.0.2.55");

        let urlhaus = "# URLhaus\n127.0.0.1 evil-c2.example\n127.0.0.1 localhost\n";
        let u_inds = parse_urlhaus_hostfile(urlhaus);
        assert_eq!(u_inds.len(), 1);
        assert_eq!(u_inds[0].indicator, "evil-c2.example");
        assert_eq!(u_inds[0].indicator_type, "domain");
    }

    #[tokio::test]
    async fn matches_flow_and_dns_to_critical_finding_with_package() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("arch_fos_ti_{nanos}.db"));
        let pool = open_writer_pool(&path).await.unwrap();
        let now_ms = current_unix_ms();

        sqlx::query(
            "INSERT INTO packages (name, version, repo, is_foreign, reason, size_bytes, files, first_seen_at, last_seen_at) VALUES ('curl', '8.0-1', 'core', 0, 'explicit', 100, '[\"usr/bin/curl\"]', ?, ?)",
        )
        .bind(now_ms)
        .bind(now_ms)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO threat_indicators (indicator, indicator_type, feed, threat_label, updated_at) VALUES ('198.51.100.99', 'ip', 'feodo_tracker', 'Botnet C2', ?)",
        )
        .bind(now_ms)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO flows_1m (bucket_ts, ts, pid, uid, comm, exe_path, src_ip, dst_ip, dst_port, protocol, bytes_tx, bytes_rx, packets, entity_type, entity_id) VALUES (?, ?, 500, 1000, 'curl', '/usr/bin/curl', '10.0.0.2', '198.51.100.99', 4444, 'tcp', 100, 0, 1, 'process', 'curl:500')",
        )
        .bind(now_ms)
        .bind(now_ms)
        .execute(&pool)
        .await
        .unwrap();

        let stats = run_threat_intel_once(&pool, true).await.unwrap();
        assert_eq!(stats.critical_matches, 1);

        let (sev, evidence): (String, String) = sqlx::query_as(
            "SELECT severity, evidence FROM findings WHERE rule_id = 'threat_intel_match'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sev, "critical");
        assert!(evidence.contains("\"package_name\":\"curl\""));

        pool.close().await;
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
