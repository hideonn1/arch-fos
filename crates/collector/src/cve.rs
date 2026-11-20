use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arch_fos_common::Severity;
use reqwest::header::{ETAG, IF_NONE_MATCH, LAST_MODIFIED};
use serde::Deserialize;
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::db::{NewFinding, upsert_finding_respecting_suppression};

const SECURITY_TRACKER_URL: &str = "https://security.archlinux.org/issues/all.json";
const FEED_NAME: &str = "arch-security-tracker";

/// Minimal subset of an Arch Security Tracker advisory group entry (`issues/all.json`).
#[derive(Debug, Clone, Deserialize)]
pub struct ArchAdvisoryGroup {
    pub name: String,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub affected: String,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CveRunStats {
    pub advisories_loaded: usize,
    pub findings_created: usize,
    pub cache_hit_304: bool,
}

/// Maps Arch Security Tracker severity strings to internal `Severity`.
#[must_use]
pub fn map_arch_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Matches installed packages against Arch Security Tracker advisories using `alpm::vercmp`.
/// Only flags packages whose installed version is strictly older than `fixed` (US-09).
#[must_use]
pub fn match_advisories_against_packages(
    advisories: &[ArchAdvisoryGroup],
    installed_versions: &HashMap<String, String>,
    now_ms: i64,
) -> Vec<NewFinding> {
    let mut findings = Vec::new();

    for adv in advisories {
        let Some(ref fixed_ver) = adv.fixed else {
            continue;
        };
        if fixed_ver.trim().is_empty() {
            continue;
        }

        let severity = map_arch_severity(&adv.severity);
        for pkg_name in &adv.packages {
            let Some(installed_ver) = installed_versions.get(pkg_name) else {
                continue;
            };

            if alpm::vercmp(installed_ver.as_str(), fixed_ver.as_str()) == Ordering::Less {
                let cve_label = if adv.issues.is_empty() {
                    adv.name.clone()
                } else {
                    adv.issues.join(", ")
                };
                findings.push(NewFinding {
                    ts: now_ms,
                    rule_id: format!("cve:{}", adv.name),
                    severity,
                    entity_type: "package".to_string(),
                    entity_id: pkg_name.clone(),
                    title: format!("{pkg_name} {installed_ver} vulnerable ({cve_label})"),
                    summary: format!(
                        "Instalado {installed_ver}; versión corregida: {fixed_ver} (estado: {}, severidad: {}).",
                        adv.status, adv.severity
                    ),
                    evidence: json!({
                        "advisory": adv.name,
                        "cves": adv.issues,
                        "status": adv.status,
                        "arch_severity": adv.severity,
                        "installed_version": installed_ver,
                        "affected_version": adv.affected,
                        "fixed_version": fixed_ver,
                    }),
                });
            }
        }
    }

    findings
}

/// Syncs `security.archlinux.org/issues/all.json` with `If-None-Match` ETag caching and evaluates CVEs.
pub async fn run_cve_check_once(
    pool: &SqlitePool,
    offline: bool,
) -> Result<CveRunStats, Box<dyn std::error::Error + Send + Sync>> {
    let now_ms = current_unix_ms();
    let cached: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT etag, payload FROM feed_cache WHERE feed_name = ?")
            .bind(FEED_NAME)
            .fetch_optional(pool)
            .await?;

    let (cached_etag, cached_payload) = cached.unwrap_or((None, String::new()));
    let mut cache_hit_304 = false;

    let payload_json = if offline {
        if cached_payload.is_empty() {
            return Ok(CveRunStats::default());
        }
        cached_payload
    } else {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("arch-fos-collector/0.1")
            .build()?;

        let mut req = client.get(SECURITY_TRACKER_URL);
        if let Some(ref etag) = cached_etag {
            req = req.header(IF_NONE_MATCH, etag);
        }

        match req.send().await {
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_MODIFIED => {
                cache_hit_304 = true;
                sqlx::query("UPDATE feed_cache SET last_synced_at = ? WHERE feed_name = ?")
                    .bind(now_ms)
                    .bind(FEED_NAME)
                    .execute(pool)
                    .await?;
                cached_payload
            }
            Ok(resp) if resp.status().is_success() => {
                let new_etag = resp
                    .headers()
                    .get(ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let new_last_mod = resp
                    .headers()
                    .get(LAST_MODIFIED)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let body = resp.text().await?;

                sqlx::query(
                    r#"
                    INSERT INTO feed_cache (feed_name, etag, last_modified, last_synced_at, payload)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(feed_name) DO UPDATE SET
                        etag = excluded.etag,
                        last_modified = excluded.last_modified,
                        last_synced_at = excluded.last_synced_at,
                        payload = excluded.payload
                    "#,
                )
                .bind(FEED_NAME)
                .bind(new_etag)
                .bind(new_last_mod)
                .bind(now_ms)
                .bind(&body)
                .execute(pool)
                .await?;
                body
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Arch Security Tracker returned non-success status");
                if cached_payload.is_empty() {
                    return Ok(CveRunStats::default());
                }
                cached_payload
            }
            Err(err) => {
                warn!(error = %err, "failed to reach Arch Security Tracker; using cached feed if available");
                if cached_payload.is_empty() {
                    return Ok(CveRunStats::default());
                }
                cached_payload
            }
        }
    };

    if payload_json.trim().is_empty() {
        return Ok(CveRunStats {
            cache_hit_304,
            ..Default::default()
        });
    }

    let advisories: Vec<ArchAdvisoryGroup> = serde_json::from_str(&payload_json)?;
    let pkg_rows: Vec<(String, String)> =
        sqlx::query_as("SELECT name, version FROM packages WHERE is_foreign = 0")
            .fetch_all(pool)
            .await?;
    let installed_map: HashMap<String, String> = pkg_rows.into_iter().collect();

    let candidates = match_advisories_against_packages(&advisories, &installed_map, now_ms);
    let mut created = 0usize;
    for f in &candidates {
        if upsert_finding_respecting_suppression(pool, f, now_ms).await? {
            created += 1;
        }
    }

    info!(
        advisories = advisories.len(),
        findings_created = created,
        cache_hit_304,
        "CVE check completed"
    );

    Ok(CveRunStats {
        advisories_loaded: advisories.len(),
        findings_created: created,
        cache_hit_304,
    })
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

    #[test]
    fn vercmp_only_flags_packages_older_than_fixed_version() {
        let advisories = vec![
            ArchAdvisoryGroup {
                name: "AVG-9999".to_string(),
                packages: vec!["openssl".to_string(), "curl".to_string()],
                status: "Fixed".to_string(),
                severity: "High".to_string(),
                affected: "3.3.0-1".to_string(),
                fixed: Some("3.4.0-1".to_string()),
                issues: vec!["CVE-2026-0001".to_string()],
            },
            ArchAdvisoryGroup {
                name: "AVG-8888".to_string(),
                packages: vec!["bash".to_string()],
                status: "Vulnerable".to_string(),
                severity: "Critical".to_string(),
                affected: "5.2.37-1".to_string(),
                fixed: None,
                issues: vec!["CVE-2026-0002".to_string()],
            },
        ];

        let mut installed = HashMap::new();
        installed.insert("openssl".to_string(), "3.3.2-1".to_string()); // < 3.4.0-1 -> vulnerable
        installed.insert("curl".to_string(), "3.4.0-1".to_string()); // == 3.4.0-1 -> safe
        installed.insert("bash".to_string(), "5.2.37-1".to_string()); // no fixed version -> skipped

        let findings = match_advisories_against_packages(&advisories, &installed, 1000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_id, "openssl");
        assert_eq!(findings[0].rule_id, "cve:AVG-9999");
        assert_eq!(findings[0].severity, Severity::High);
    }
}
