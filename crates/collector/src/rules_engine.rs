use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::{NewEvent, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::db::{NewFinding, upsert_finding_respecting_suppression};

/// Optional MITRE ATT&CK mapping attached to a Sigma-style YAML rule (US-29).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreAttackMapping {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleLogSource {
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleDetection {
    #[serde(default)]
    pub selection: HashMap<String, serde_json::Value>,
}

/// Sigma-inspired YAML rule loaded dynamically from `rules/*.yml` (US-29).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub mitre_attack: Option<MitreAttackMapping>,
    pub logsource: Option<RuleLogSource>,
    pub detection: RuleDetection,
}

const fn default_true() -> bool {
    true
}

/// Hot-reloading rule store tracking YAML file modification times.
#[derive(Debug, Default)]
pub struct HotRuleStore {
    rules_dir: PathBuf,
    file_mtimes: HashMap<PathBuf, SystemTime>,
    pub rules: Vec<(String, SigmaRule)>,
}

impl HotRuleStore {
    #[must_use]
    pub fn new(rules_dir: PathBuf) -> Self {
        Self {
            rules_dir,
            file_mtimes: HashMap::new(),
            rules: Vec::new(),
        }
    }

    /// Checks `rules_dir` for added, modified, or removed `*.yml`/`*.yaml` files.
    /// Returns `true` if rules were reloaded.
    pub fn reload_if_changed(&mut self) -> bool {
        if !self.rules_dir.is_dir() {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(&self.rules_dir) else {
            return false;
        };

        let mut current_mtimes = HashMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !path.is_file() || !matches!(ext, "yml" | "yaml") {
                continue;
            }
            if let Ok(meta) = entry.metadata()
                && let Ok(mtime) = meta.modified()
            {
                current_mtimes.insert(path, mtime);
            }
        }

        if current_mtimes == self.file_mtimes {
            return false;
        }

        let mut loaded = Vec::new();
        let mut sorted_paths: Vec<PathBuf> = current_mtimes.keys().cloned().collect();
        sorted_paths.sort();

        for path in sorted_paths {
            match std::fs::read_to_string(&path) {
                Ok(content) => match yaml_serde::from_str::<SigmaRule>(&content) {
                    Ok(rule) => {
                        let name = path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown.yml")
                            .to_string();
                        loaded.push((name, rule));
                    }
                    Err(err) => {
                        warn!(file = %path.display(), error = %err, "failed to parse Sigma YAML rule");
                    }
                },
                Err(err) => {
                    warn!(file = %path.display(), error = %err, "failed to read Sigma YAML rule");
                }
            }
        }

        self.file_mtimes = current_mtimes;
        self.rules = loaded;
        info!(count = self.rules.len(), dir = %self.rules_dir.display(), "hot-reloaded YAML rules");
        true
    }
}

/// Evaluates a single `NewEvent` against all enabled Sigma rules.
#[must_use]
pub fn evaluate_event_against_rules(
    rules: &[(String, SigmaRule)],
    event: &NewEvent,
    now_ms: i64,
) -> Vec<NewFinding> {
    let mut findings = Vec::new();

    for (source_file, rule) in rules {
        if !rule.enabled || rule.detection.selection.is_empty() {
            continue;
        }
        if event_matches_selection(event, &rule.detection.selection) {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: rule.id.clone(),
                severity: rule.severity,
                entity_type: event.entity_type.clone(),
                entity_id: event.entity_id.clone(),
                title: rule.title.clone(),
                summary: rule.description.clone(),
                evidence: json!({
                    "event_type": event.event_type,
                    "source": event.source,
                    "source_file": source_file,
                    "mitre_attack": rule.mitre_attack,
                    "payload": event.payload,
                }),
            });
        }
    }

    findings
}

fn event_matches_selection(
    event: &NewEvent,
    selection: &HashMap<String, serde_json::Value>,
) -> bool {
    for (field, expected) in selection {
        let actual: Option<serde_json::Value> = match field.as_str() {
            "event_type" => Some(serde_json::Value::String(event.event_type.clone())),
            "severity" => Some(serde_json::Value::String(
                event.severity.as_str().to_string(),
            )),
            "source" => Some(serde_json::Value::String(event.source.clone())),
            "entity_type" => Some(serde_json::Value::String(event.entity_type.clone())),
            "entity_id" => Some(serde_json::Value::String(event.entity_id.clone())),
            _ => {
                let key = field.strip_prefix("payload.").unwrap_or(field.as_str());
                lookup_json_path(&event.payload, key).cloned()
            }
        };

        let Some(actual_val) = actual else {
            return false;
        };
        if !value_matches(&actual_val, expected) {
            return false;
        }
    }
    true
}

fn lookup_json_path<'a>(val: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = val;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn value_matches(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    if let Some(arr) = expected.as_array() {
        return arr.iter().any(|item| item == actual);
    }
    actual == expected
}

/// Syncs hot-reloaded YAML rules into the SQLite `rules` table and evaluates new events.
pub async fn sync_and_evaluate_rules(
    pool: &SqlitePool,
    store: &mut HotRuleStore,
    recent_events: &[NewEvent],
) -> Result<usize, sqlx::Error> {
    let now_ms = current_unix_ms();
    if store.reload_if_changed() {
        let mut tx = pool.begin().await?;
        for (source_file, rule) in &store.rules {
            let mitre_json = rule
                .mitre_attack
                .as_ref()
                .and_then(|m| serde_json::to_string(m).ok());
            let config_json =
                serde_json::to_string(&rule.detection).unwrap_or_else(|_| "{}".into());

            sqlx::query(
                r#"
                INSERT INTO rules (id, name, description, severity, enabled, config, updated_at, mitre_attack, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    severity = excluded.severity,
                    enabled = excluded.enabled,
                    config = excluded.config,
                    updated_at = excluded.updated_at,
                    mitre_attack = excluded.mitre_attack,
                    source_file = excluded.source_file
                "#,
            )
            .bind(&rule.id)
            .bind(&rule.title)
            .bind(&rule.description)
            .bind(rule.severity.as_str())
            .bind(i64::from(rule.enabled))
            .bind(config_json)
            .bind(now_ms)
            .bind(mitre_json)
            .bind(source_file)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    }

    let mut created = 0usize;
    for ev in recent_events {
        let matched = evaluate_event_against_rules(&store.rules, ev, now_ms);
        for f in &matched {
            if upsert_finding_respecting_suppression(pool, f, now_ms)
                .await
                .unwrap_or(false)
            {
                created += 1;
            }
        }
    }
    Ok(created)
}

#[allow(dead_code)]
fn _path_exists(p: &Path) -> bool {
    p.exists()
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
    fn hot_reloads_yaml_rules_and_matches_events_with_mitre_mapping() {
        let dir = std::env::temp_dir().join(format!(
            "arch_fos_rules_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let rule_yaml = r#"
id: sigma_aur_foreign_install
title: Instalación de paquete AUR/foráneo
description: Se instaló un paquete fuera de los repositorios oficiales.
severity: medium
enabled: true
mitre_attack:
  tactic: Execution
  technique_id: T1059
  technique_name: Command and Scripting Interpreter
logsource:
  category: packages
detection:
  selection:
    event_type: package_installed
    payload.is_foreign: true
"#;
        std::fs::write(dir.join("aur_install.yml"), rule_yaml).unwrap();

        let mut store = HotRuleStore::new(dir.clone());
        assert!(store.reload_if_changed());
        assert_eq!(store.rules.len(), 1);
        assert!(!store.reload_if_changed()); // No change -> false

        let ev = NewEvent {
            ts: 1000,
            event_type: "package_installed".to_string(),
            severity: Severity::Low,
            source: "collector:alpm".to_string(),
            entity_type: "package".to_string(),
            entity_id: "evil-aur".to_string(),
            payload: json!({ "is_foreign": true, "version": "1.0-1" }),
        };

        let findings = evaluate_event_against_rules(&store.rules, &ev, 2000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "sigma_aur_foreign_install");
        assert_eq!(
            findings[0].evidence["mitre_attack"]["technique_id"],
            "T1059"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
