use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arch_fos_common::Severity;
use serde::Deserialize;
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::db::{NewFinding, upsert_finding_respecting_suppression};

const AUR_RPC_V5_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
const AUR_CACHE_TTL_MS: i64 = 6 * 60 * 60 * 1000;

/// Subset of AUR RPC v5 package record fields used for reputation rules (US-11).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurPackageInfo {
    pub name: String,
    pub version: String,
    pub maintainer: Option<String>,
    #[serde(default)]
    pub num_votes: i64,
    #[serde(default)]
    pub popularity: f64,
    pub first_submitted: Option<i64>,
    pub last_modified: Option<i64>,
    pub out_of_date: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AurRpcResponse {
    #[serde(default)]
    results: Vec<AurPackageInfo>,
}

/// Previous AUR snapshot loaded from SQLite `aur_cache`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedAurState {
    pub maintainer: Option<String>,
    pub was_orphan: bool,
    pub fetched_at: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct AurThresholds {
    pub low_votes: i64,
    pub recent_days: i64,
    pub outdated_days: i64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AurRunStats {
    pub foreign_packages: usize,
    pub queried_packages: usize,
    pub findings_created: usize,
}

/// Evaluates all 5 US-11 AUR reputation heuristics for a single package.
#[must_use]
pub fn evaluate_aur_package(
    info: &AurPackageInfo,
    previous: Option<&CachedAurState>,
    thresholds: AurThresholds,
    now_ms: i64,
) -> Vec<NewFinding> {
    let now_sec = now_ms / 1000;
    let mut findings = Vec::new();

    if let Some(prev) = previous {
        // 1. Adopted after orphan state
        if prev.was_orphan && info.maintainer.is_some() {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "aur_adopted_after_orphan".to_string(),
                severity: Severity::High,
                entity_type: "package".to_string(),
                entity_id: info.name.clone(),
                title: format!("Paquete AUR {} adoptado tras estar huérfano", info.name),
                summary: format!(
                    "Nuevo mantenedor '{}' adoptó un paquete previamente huérfano.",
                    info.maintainer.as_deref().unwrap_or("desconocido")
                ),
                evidence: json!({
                    "previous_maintainer": prev.maintainer,
                    "new_maintainer": info.maintainer,
                    "version": info.version,
                }),
            });
        } else if prev.maintainer.is_some()
            && info.maintainer.is_some()
            && prev.maintainer != info.maintainer
        {
            // 2. Maintainer changed from last seen
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "aur_maintainer_changed".to_string(),
                severity: Severity::Medium,
                entity_type: "package".to_string(),
                entity_id: info.name.clone(),
                title: format!("Cambio de mantenedor en AUR: {}", info.name),
                summary: format!(
                    "Mantenedor cambió de '{}' a '{}'.",
                    prev.maintainer.as_deref().unwrap_or("ninguno"),
                    info.maintainer.as_deref().unwrap_or("ninguno")
                ),
                evidence: json!({
                    "previous_maintainer": prev.maintainer,
                    "new_maintainer": info.maintainer,
                    "version": info.version,
                }),
            });
        }
    }

    // 3. Low NumVotes
    if info.num_votes < thresholds.low_votes {
        findings.push(NewFinding {
            ts: now_ms,
            rule_id: "aur_low_votes".to_string(),
            severity: Severity::Low,
            entity_type: "package".to_string(),
            entity_id: info.name.clone(),
            title: format!(
                "Paquete AUR con pocos votos: {} ({})",
                info.name, info.num_votes
            ),
            summary: format!(
                "{} tiene {} votos (umbral configurado: {}).",
                info.name, info.num_votes, thresholds.low_votes
            ),
            evidence: json!({
                "num_votes": info.num_votes,
                "threshold": thresholds.low_votes,
                "popularity": info.popularity,
                "maintainer": info.maintainer,
            }),
        });
    }

    // 4. Recent FirstSubmitted
    if let Some(submitted_sec) = info.first_submitted {
        let age_secs = now_sec.saturating_sub(submitted_sec);
        let threshold_secs = thresholds.recent_days * 24 * 60 * 60;
        if age_secs >= 0 && age_secs < threshold_secs {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "aur_recently_submitted".to_string(),
                severity: Severity::Medium,
                entity_type: "package".to_string(),
                entity_id: info.name.clone(),
                title: format!("Paquete AUR reciente: {}", info.name),
                summary: format!(
                    "{} fue enviado al AUR hace {} días (umbral: {} días).",
                    info.name,
                    age_secs / 86_400,
                    thresholds.recent_days
                ),
                evidence: json!({
                    "first_submitted": submitted_sec,
                    "age_days": age_secs / 86_400,
                    "threshold_days": thresholds.recent_days,
                }),
            });
        }
    }

    // 5. Prolonged OutOfDate
    if let Some(ood_sec) = info.out_of_date {
        let ood_age_secs = now_sec.saturating_sub(ood_sec);
        let threshold_secs = thresholds.outdated_days * 24 * 60 * 60;
        if ood_age_secs >= threshold_secs {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "aur_prolonged_out_of_date".to_string(),
                severity: Severity::Low,
                entity_type: "package".to_string(),
                entity_id: info.name.clone(),
                title: format!("Paquete AUR desactualizado prolongadamente: {}", info.name),
                summary: format!(
                    "{} lleva marcado OutOfDate {} días (umbral: {} días).",
                    info.name,
                    ood_age_secs / 86_400,
                    thresholds.outdated_days
                ),
                evidence: json!({
                    "out_of_date": ood_sec,
                    "outdated_days": ood_age_secs / 86_400,
                    "threshold_days": thresholds.outdated_days,
                }),
            });
        }
    }

    findings
}

/// Queries AUR RPC v5 in rate-limited batches for foreign packages and evaluates reputation rules.
pub async fn run_aur_reputation_once(
    pool: &SqlitePool,
    thresholds: AurThresholds,
    offline: bool,
) -> Result<AurRunStats, Box<dyn std::error::Error + Send + Sync>> {
    let foreign_rows: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM packages WHERE is_foreign = 1 ORDER BY name ASC")
            .fetch_all(pool)
            .await?;
    let foreign_names: Vec<String> = foreign_rows.into_iter().map(|(n,)| n).collect();

    if foreign_names.is_empty() || offline {
        return Ok(AurRunStats {
            foreign_packages: foreign_names.len(),
            ..Default::default()
        });
    }

    let now_ms = current_unix_ms();
    let cached_rows: Vec<(String, Option<String>, i64, i64)> =
        sqlx::query_as("SELECT package_name, maintainer, was_orphan, fetched_at FROM aur_cache")
            .fetch_all(pool)
            .await?;
    let cached_map: HashMap<String, CachedAurState> = cached_rows
        .into_iter()
        .map(|(name, maintainer, was_orphan, fetched_at)| {
            (
                name,
                CachedAurState {
                    maintainer,
                    was_orphan: was_orphan != 0,
                    fetched_at,
                },
            )
        })
        .collect();

    // Only query packages whose cache expired or wasn't fetched yet.
    let stale_names: Vec<String> = foreign_names
        .iter()
        .filter(|name| {
            cached_map
                .get(*name)
                .is_none_or(|c| now_ms.saturating_sub(c.fetched_at) >= AUR_CACHE_TTL_MS)
        })
        .cloned()
        .collect();

    if stale_names.is_empty() {
        return Ok(AurRunStats {
            foreign_packages: foreign_names.len(),
            queried_packages: 0,
            findings_created: 0,
        });
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("arch-fos-collector/0.1")
        .build()?;

    let mut queried = 0usize;
    let mut created = 0usize;

    // Batch up to 50 packages per RPC call with rate limit (500ms between batches).
    for (idx, chunk) in stale_names.chunks(50).enumerate() {
        if idx > 0 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let params: Vec<(&str, &str)> = chunk.iter().map(|n| ("arg[]", n.as_str())).collect();
        let resp = match client.get(AUR_RPC_V5_URL).query(&params).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(status = %r.status(), "AUR RPC v5 returned non-success status");
                continue;
            }
            Err(err) => {
                warn!(error = %err, "failed to reach AUR RPC v5");
                break;
            }
        };

        let parsed: AurRpcResponse = match resp.json().await {
            Ok(p) => p,
            Err(err) => {
                warn!(error = %err, "invalid AUR RPC v5 JSON response");
                continue;
            }
        };

        for info in parsed.results {
            queried += 1;
            let prev = cached_map.get(&info.name);
            let findings = evaluate_aur_package(&info, prev, thresholds, now_ms);
            for f in &findings {
                if upsert_finding_respecting_suppression(pool, f, now_ms).await? {
                    created += 1;
                }
            }

            let is_orphan = i64::from(info.maintainer.is_none());
            sqlx::query(
                r#"
                INSERT INTO aur_cache (
                    package_name, maintainer, was_orphan, num_votes, popularity,
                    first_submitted, last_modified, out_of_date, version, fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(package_name) DO UPDATE SET
                    maintainer = excluded.maintainer,
                    was_orphan = excluded.was_orphan,
                    num_votes = excluded.num_votes,
                    popularity = excluded.popularity,
                    first_submitted = excluded.first_submitted,
                    last_modified = excluded.last_modified,
                    out_of_date = excluded.out_of_date,
                    version = excluded.version,
                    fetched_at = excluded.fetched_at
                "#,
            )
            .bind(&info.name)
            .bind(&info.maintainer)
            .bind(is_orphan)
            .bind(info.num_votes)
            .bind(info.popularity)
            .bind(info.first_submitted)
            .bind(info.last_modified)
            .bind(info.out_of_date)
            .bind(&info.version)
            .bind(now_ms)
            .execute(pool)
            .await?;
        }
    }

    info!(
        foreign_packages = foreign_names.len(),
        queried_packages = queried,
        findings_created = created,
        "AUR reputation check completed"
    );

    Ok(AurRunStats {
        foreign_packages: foreign_names.len(),
        queried_packages: queried,
        findings_created: created,
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
    fn evaluates_all_five_aur_reputation_signals() {
        let now_sec = 1_700_000_000_i64;
        let now_ms = now_sec * 1000;
        let thresholds = AurThresholds {
            low_votes: 10,
            recent_days: 30,
            outdated_days: 90,
        };

        let info_adopted = AurPackageInfo {
            name: "sketchy-aur".to_string(),
            version: "1.0-2".to_string(),
            maintainer: Some("newguy".to_string()),
            num_votes: 2,
            popularity: 0.1,
            first_submitted: Some(now_sec - 5 * 86_400),
            last_modified: Some(now_sec),
            out_of_date: Some(now_sec - 120 * 86_400),
        };
        let prev_orphan = CachedAurState {
            maintainer: None,
            was_orphan: true,
            fetched_at: now_ms - 10_000,
        };

        let findings = evaluate_aur_package(&info_adopted, Some(&prev_orphan), thresholds, now_ms);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"aur_adopted_after_orphan"));
        assert!(rules.contains(&"aur_low_votes"));
        assert!(rules.contains(&"aur_recently_submitted"));
        assert!(rules.contains(&"aur_prolonged_out_of_date"));

        let prev_other = CachedAurState {
            maintainer: Some("old_maintainer".to_string()),
            was_orphan: false,
            fetched_at: now_ms - 10_000,
        };
        let findings2 = evaluate_aur_package(&info_adopted, Some(&prev_other), thresholds, now_ms);
        assert!(
            findings2
                .iter()
                .any(|f| f.rule_id == "aur_maintainer_changed")
        );
    }
}
