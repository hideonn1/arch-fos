use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::Severity;
use serde_json::json;
use sqlx::SqlitePool;
use tracing::warn;
use zbus::{OwnedObjectPath, OwnedVariant};

use crate::db::{NewFinding, upsert_finding_respecting_suppression};

/// Snapshot of a systemd service unit and its cgroup metrics (US-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub unit_name: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub cpu_usage_ns: i64,
    pub memory_bytes: i64,
    pub io_read_bytes: i64,
    pub io_write_bytes: i64,
    /// Active start timestamp in Unix milliseconds (`ActiveEnterTimestamp` / 1000).
    pub active_enter_ms: Option<i64>,
}

/// Summary of a services inventory collection pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServicesRunStats {
    pub total_services: usize,
    pub unused_findings: usize,
    pub dbus_available: bool,
}

type SystemdUnitEntry = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// Reads systemd service units and cgroup resource counters via D-Bus (`org.freedesktop.systemd1`).
pub async fn collect_systemd_services() -> Result<Vec<ServiceSnapshot>, zbus::Error> {
    let conn = zbus::Connection::system().await?;
    let manager = zbus::Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await?;

    let units: Vec<SystemdUnitEntry> = manager.call("ListUnits", &()).await?;
    let mut snapshots = Vec::new();

    for (name, _desc, _load_state, active_state, sub_state, _following, unit_path, _, _, _) in units
    {
        if !name.ends_with(".service") {
            continue;
        }

        let props_proxy = zbus::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            unit_path.as_str(),
            "org.freedesktop.DBus.Properties",
        )
        .await?;

        let unit_props: HashMap<String, OwnedVariant> = props_proxy
            .call("GetAll", &("org.freedesktop.systemd1.Unit",))
            .await
            .unwrap_or_default();
        let svc_props: HashMap<String, OwnedVariant> = props_proxy
            .call("GetAll", &("org.freedesktop.systemd1.Service",))
            .await
            .unwrap_or_default();

        let unit_file_state =
            extract_string(&unit_props, "UnitFileState").unwrap_or_else(|| "unknown".to_string());
        let active_enter_us = extract_u64(&unit_props, "ActiveEnterTimestamp");
        let active_enter_ms = active_enter_us
            .filter(|&v| v > 0)
            .map(|v| i64::try_from(v / 1000).unwrap_or(i64::MAX));

        let cpu_usage_ns = normalize_cgroup_counter(extract_u64(&svc_props, "CPUUsageNSec"));
        let memory_bytes = normalize_cgroup_counter(extract_u64(&svc_props, "MemoryCurrent"));
        let io_read_bytes = normalize_cgroup_counter(extract_u64(&svc_props, "IOReadBytes"));
        let io_write_bytes = normalize_cgroup_counter(extract_u64(&svc_props, "IOWriteBytes"));

        snapshots.push(ServiceSnapshot {
            unit_name: name,
            active_state,
            sub_state,
            unit_file_state,
            cpu_usage_ns,
            memory_bytes,
            io_read_bytes,
            io_write_bytes,
            active_enter_ms,
        });
    }

    Ok(snapshots)
}

/// Evaluates `unused_service` findings for enabled, active services idle for >= `unused_days`.
#[must_use]
pub fn detect_unused_services(
    services: &[ServiceSnapshot],
    previous_cpu_by_unit: &HashMap<String, i64>,
    units_with_listeners: &HashSet<String>,
    unused_days: u64,
    now_ms: i64,
) -> Vec<NewFinding> {
    let min_age_ms = i64::try_from(unused_days).unwrap_or(7) * 24 * 60 * 60 * 1000;
    let mut findings = Vec::new();

    for svc in services {
        if svc.unit_file_state != "enabled" || svc.active_state != "active" {
            continue;
        }
        let Some(enter_ms) = svc.active_enter_ms else {
            continue;
        };
        if now_ms.saturating_sub(enter_ms) < min_age_ms {
            continue;
        }

        let unit_stem = svc.unit_name.trim_end_matches(".service");
        if units_with_listeners.contains(&svc.unit_name) || units_with_listeners.contains(unit_stem)
        {
            continue;
        }

        let cpu_delta_ns = previous_cpu_by_unit
            .get(&svc.unit_name)
            .map_or(svc.cpu_usage_ns, |prev| {
                svc.cpu_usage_ns.saturating_sub(*prev)
            });

        // Consider idle if delta CPU is under 10ms over snapshot and IO is zero.
        let low_cpu = cpu_delta_ns < 10_000_000;
        let low_io = svc.io_read_bytes == 0 && svc.io_write_bytes == 0;
        if low_cpu && low_io {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "unused_service".to_string(),
                severity: Severity::Low,
                entity_type: "service".to_string(),
                entity_id: svc.unit_name.clone(),
                title: format!("Servicio sin actividad aparente: {}", svc.unit_name),
                summary: format!(
                    "El servicio {} está enabled y activo desde hace >= {} días sin puertos en escucha ni actividad relevante.",
                    svc.unit_name, unused_days
                ),
                evidence: json!({
                    "unit_name": svc.unit_name,
                    "unit_file_state": svc.unit_file_state,
                    "active_state": svc.active_state,
                    "memory_bytes": svc.memory_bytes,
                    "cpu_usage_ns": svc.cpu_usage_ns,
                    "cpu_delta_ns": cpu_delta_ns,
                }),
            });
        }
    }

    findings
}

/// Runs a services inventory cycle, handling unavailable D-Bus (e.g., containers) gracefully.
pub async fn run_services_once(
    pool: &SqlitePool,
    unused_days: u64,
) -> Result<ServicesRunStats, sqlx::Error> {
    let services = match collect_systemd_services().await {
        Ok(list) => list,
        Err(err) => {
            warn!(error = %err, "systemd D-Bus unavailable; skipping services inventory");
            return Ok(ServicesRunStats {
                total_services: 0,
                unused_findings: 0,
                dbus_available: false,
            });
        }
    };

    let now_ms = current_unix_ms();

    let prev_rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT unit_name, cpu_usage_ns FROM services")
            .fetch_all(pool)
            .await?;
    let previous_cpu: HashMap<String, i64> = prev_rows.into_iter().collect();

    let listener_procs: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT DISTINCT process_name FROM listeners WHERE process_name IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    let active_procs: HashSet<String> = listener_procs.into_iter().filter_map(|(p,)| p).collect();

    let mut tx = pool.begin().await?;
    for svc in &services {
        sqlx::query(
            r#"
            INSERT INTO services (
                unit_name, active_state, sub_state, unit_file_state,
                cpu_usage_ns, memory_bytes, io_read_bytes, io_write_bytes, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(unit_name) DO UPDATE SET
                active_state = excluded.active_state,
                sub_state = excluded.sub_state,
                unit_file_state = excluded.unit_file_state,
                cpu_usage_ns = excluded.cpu_usage_ns,
                memory_bytes = excluded.memory_bytes,
                io_read_bytes = excluded.io_read_bytes,
                io_write_bytes = excluded.io_write_bytes,
                last_seen_at = excluded.last_seen_at
            "#,
        )
        .bind(&svc.unit_name)
        .bind(&svc.active_state)
        .bind(&svc.sub_state)
        .bind(&svc.unit_file_state)
        .bind(svc.cpu_usage_ns)
        .bind(svc.memory_bytes)
        .bind(svc.io_read_bytes)
        .bind(svc.io_write_bytes)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    let findings =
        detect_unused_services(&services, &previous_cpu, &active_procs, unused_days, now_ms);
    let mut created = 0usize;
    for finding in &findings {
        if let Ok(true) = upsert_finding_respecting_suppression(pool, finding, now_ms).await {
            created += 1;
        }
    }

    Ok(ServicesRunStats {
        total_services: services.len(),
        unused_findings: created,
        dbus_available: true,
    })
}

fn normalize_cgroup_counter(val: Option<u64>) -> i64 {
    match val {
        None | Some(u64::MAX) => 0,
        Some(v) => i64::try_from(v).unwrap_or(i64::MAX),
    }
}

fn extract_string(map: &HashMap<String, OwnedVariant>, key: &str) -> Option<String> {
    let val = map.get(key)?;
    String::try_from(val.clone()).ok()
}

fn extract_u64(map: &HashMap<String, OwnedVariant>, key: &str) -> Option<u64> {
    let val = map.get(key)?;
    u64::try_from(val.clone()).ok()
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
    fn unused_service_rule_flags_idle_enabled_service_and_skips_active_listener() {
        let now = 1_700_000_000_000_i64;
        let ten_days_ago = now - 10 * 24 * 60 * 60 * 1000;

        let services = vec![
            ServiceSnapshot {
                unit_name: "cups.service".to_string(),
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                unit_file_state: "enabled".to_string(),
                cpu_usage_ns: 1_000_000,
                memory_bytes: 16 * 1024 * 1024,
                io_read_bytes: 0,
                io_write_bytes: 0,
                active_enter_ms: Some(ten_days_ago),
            },
            ServiceSnapshot {
                unit_name: "sshd.service".to_string(),
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
                unit_file_state: "enabled".to_string(),
                cpu_usage_ns: 50_000_000,
                memory_bytes: 8 * 1024 * 1024,
                io_read_bytes: 0,
                io_write_bytes: 0,
                active_enter_ms: Some(ten_days_ago),
            },
        ];

        let mut listeners = HashSet::new();
        listeners.insert("sshd".to_string());

        let mut prev_cpu = HashMap::new();
        prev_cpu.insert("cups.service".to_string(), 1_000_000);

        let findings = detect_unused_services(&services, &prev_cpu, &listeners, 7, now);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "unused_service");
        assert_eq!(findings[0].entity_id, "cups.service");
    }
}
