use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::{NewEvent, Severity};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tracing::info;

use crate::db::{NewFinding, insert_events, upsert_finding_respecting_suppression};

const SOURCE_PERSISTENCE: &str = "collector:persistence";

/// Persistence artifact snapshot with SHA-256 hash and owning package (`unowned` if none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceEntry {
    pub category: String,
    pub path: String,
    pub sha256: String,
    pub package_name: String,
    pub mode: i64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PersistenceRunStats {
    pub total_entries: usize,
    pub findings_created: usize,
}

/// Scans all 8 US-08 persistence surfaces under `root` (`/` in production, temp dir in tests).
pub fn scan_persistence_entries(
    root: &Path,
    file_to_pkg: &HashMap<String, String>,
) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    let mut push_file = |category: &str, abs_path: &Path| {
        if !abs_path.is_file() {
            return;
        }
        let rel = abs_path
            .strip_prefix(root)
            .unwrap_or(abs_path)
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        let display_path = format!("/{rel}");
        if !seen.insert((category.to_string(), display_path.clone())) {
            return;
        }
        let Ok(sha256) = sha256_file(abs_path) else {
            return;
        };
        let mode = std::fs::symlink_metadata(abs_path)
            .map(|m| i64::from(m.permissions().mode() & 0o7777))
            .unwrap_or(0);
        let package_name = file_to_pkg
            .get(&rel)
            .cloned()
            .unwrap_or_else(|| "unowned".to_string());

        entries.push(PersistenceEntry {
            category: category.to_string(),
            path: display_path,
            sha256,
            package_name,
            mode,
        });
    };

    // 1 & 2. Systemd units and timers
    for dir in [
        root.join("etc/systemd/system"),
        root.join("usr/local/lib/systemd/system"),
    ] {
        visit_dir_files(&dir, 2, &mut |p| {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "timer" {
                push_file("systemd_timer", p);
            } else if matches!(ext, "service" | "socket" | "path" | "mount") {
                push_file("systemd_unit", p);
            }
        });
    }
    visit_dir_files(&root.join("usr/lib/systemd/system"), 1, &mut |p| {
        if p.extension().and_then(|e| e.to_str()) == Some("timer") {
            push_file("systemd_timer", p);
        }
    });

    // 3. Crontabs
    push_file("crontab", &root.join("etc/crontab"));
    for cron_dir in [
        "etc/cron.d",
        "etc/cron.daily",
        "etc/cron.hourly",
        "etc/cron.weekly",
        "etc/cron.monthly",
        "var/spool/cron",
    ] {
        visit_dir_files(&root.join(cron_dir), 2, &mut |p| push_file("crontab", p));
    }

    // 4. XDG autostart & per-user ~/.config/autostart + shell RCs + user systemd units
    visit_dir_files(&root.join("etc/xdg/autostart"), 1, &mut |p| {
        push_file("autostart", p);
    });
    for home_dir in collect_user_homes(root) {
        visit_dir_files(&home_dir.join(".config/autostart"), 1, &mut |p| {
            push_file("autostart", p);
        });
        visit_dir_files(&home_dir.join(".config/systemd/user"), 2, &mut |p| {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "timer" {
                push_file("systemd_timer", p);
            } else if matches!(ext, "service" | "socket" | "path") {
                push_file("systemd_unit", p);
            }
        });
        for rc in [
            ".bashrc",
            ".zshrc",
            ".profile",
            ".bash_profile",
            ".zprofile",
        ] {
            push_file("shell_rc", &home_dir.join(rc));
        }
    }

    // 5. Global shell RCs
    for rc in ["etc/profile", "etc/bash.bashrc", "etc/zsh/zshrc"] {
        push_file("shell_rc", &root.join(rc));
    }

    // 6. LD_PRELOAD & ld.so.conf.d
    push_file("ld_preload", &root.join("etc/ld.so.preload"));
    visit_dir_files(&root.join("etc/ld.so.conf.d"), 1, &mut |p| {
        push_file("ld_preload", p);
    });

    // 7. Kernel modules (persistent configs)
    for kdir in ["etc/modules-load.d", "etc/modprobe.d"] {
        visit_dir_files(&root.join(kdir), 1, &mut |p| {
            push_file("kernel_module", p);
        });
    }

    // 8. SUID/SGID binaries in standard system bin directories
    for bin_dir in ["usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin"] {
        visit_dir_files(&root.join(bin_dir), 1, &mut |p| {
            if let Ok(meta) = std::fs::symlink_metadata(p)
                && meta.is_file()
                && (meta.permissions().mode() & 0o6000) != 0
            {
                push_file("suid_sgid", p);
            }
        });
    }

    // 7b. Live /proc/modules fingerprint (after closure borrows end)
    if let Ok(proc_mods) = std::fs::read_to_string(root.join("proc/modules")) {
        let mut mod_lines: Vec<&str> = proc_mods
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        mod_lines.sort_unstable();
        let digest = sha256_bytes(mod_lines.join("\n").as_bytes());
        entries.push(PersistenceEntry {
            category: "kernel_module".to_string(),
            path: "/proc/modules".to_string(),
            sha256: digest,
            package_name: "kernel".to_string(),
            mode: 0o444,
        });
    }

    entries
}

/// Computes diff between previous and current persistence snapshots, emitting findings & events.
#[must_use]
pub fn compute_persistence_diff(
    previous: &[PersistenceEntry],
    current: &[PersistenceEntry],
    now_ms: i64,
) -> (Vec<NewFinding>, Vec<NewEvent>) {
    let is_initial = previous.is_empty();
    let prev_map: HashMap<(&str, &str), &PersistenceEntry> = previous
        .iter()
        .map(|e| ((e.category.as_str(), e.path.as_str()), e))
        .collect();
    let curr_set: HashSet<(&str, &str)> = current
        .iter()
        .map(|e| (e.category.as_str(), e.path.as_str()))
        .collect();

    let mut findings = Vec::new();
    let mut events = Vec::new();

    if is_initial {
        events.push(NewEvent {
            ts: now_ms,
            event_type: "persistence_baseline_initialized".to_string(),
            severity: Severity::Info,
            source: SOURCE_PERSISTENCE.to_string(),
            entity_type: "system".to_string(),
            entity_id: "persistence".to_string(),
            payload: json!({ "total_entries": current.len() }),
        });

        // Flag immediate high-risk persistence indicators even on baseline init
        for entry in current {
            if entry.path == "/etc/ld.so.preload" {
                findings.push(NewFinding {
                    ts: now_ms,
                    rule_id: "persistence_ld_preload".to_string(),
                    severity: Severity::Critical,
                    entity_type: "persistence".to_string(),
                    entity_id: entry.path.clone(),
                    title: "Archivo /etc/ld.so.preload presente en el sistema".to_string(),
                    summary: format!(
                        "Se detectó {} (sha256: {}, paquete: {}).",
                        entry.path, entry.sha256, entry.package_name
                    ),
                    evidence: json!({
                        "category": entry.category,
                        "path": entry.path,
                        "sha256": entry.sha256,
                        "package_name": entry.package_name,
                    }),
                });
            }
            if entry.category == "suid_sgid" && entry.package_name == "unowned" {
                findings.push(NewFinding {
                    ts: now_ms,
                    rule_id: "persistence_unowned_suid".to_string(),
                    severity: Severity::High,
                    entity_type: "persistence".to_string(),
                    entity_id: entry.path.clone(),
                    title: format!("Binario SUID/SGID sin paquete dueño: {}", entry.path),
                    summary: format!(
                        "{} tiene permisos SUID/SGID ({:o}) y no pertenece a ningún paquete de pacman.",
                        entry.path, entry.mode
                    ),
                    evidence: json!({
                        "category": entry.category,
                        "path": entry.path,
                        "sha256": entry.sha256,
                        "package_name": entry.package_name,
                        "mode": format!("{:o}", entry.mode),
                    }),
                });
            }
        }
        return (findings, events);
    }

    for curr in current {
        match prev_map.get(&(curr.category.as_str(), curr.path.as_str())) {
            None => {
                let severity = if curr.package_name == "unowned"
                    || curr.category == "ld_preload"
                    || curr.category == "suid_sgid"
                {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(NewFinding {
                    ts: now_ms,
                    rule_id: "persistence_added".to_string(),
                    severity,
                    entity_type: "persistence".to_string(),
                    entity_id: curr.path.clone(),
                    title: format!("Nueva persistencia ({}) en {}", curr.category, curr.path),
                    summary: format!(
                        "Ruta: {} | SHA-256: {} | Paquete: {}",
                        curr.path, curr.sha256, curr.package_name
                    ),
                    evidence: json!({
                        "category": curr.category,
                        "path": curr.path,
                        "sha256": curr.sha256,
                        "package_name": curr.package_name,
                        "mode": format!("{:o}", curr.mode),
                    }),
                });
                events.push(NewEvent {
                    ts: now_ms,
                    event_type: "persistence_change".to_string(),
                    severity,
                    source: SOURCE_PERSISTENCE.to_string(),
                    entity_type: "persistence".to_string(),
                    entity_id: curr.path.clone(),
                    payload: json!({
                        "change": "added",
                        "category": curr.category,
                        "path": curr.path,
                        "sha256": curr.sha256,
                        "package_name": curr.package_name,
                    }),
                });
            }
            Some(prev) if prev.sha256 != curr.sha256 => {
                let severity = if curr.category == "ld_preload" || curr.category == "suid_sgid" {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(NewFinding {
                    ts: now_ms,
                    rule_id: "persistence_modified".to_string(),
                    severity,
                    entity_type: "persistence".to_string(),
                    entity_id: curr.path.clone(),
                    title: format!(
                        "Persistencia modificada ({}) en {}",
                        curr.category, curr.path
                    ),
                    summary: format!(
                        "SHA-256 cambió de {} a {} (paquete: {}).",
                        prev.sha256, curr.sha256, curr.package_name
                    ),
                    evidence: json!({
                        "category": curr.category,
                        "path": curr.path,
                        "previous_sha256": prev.sha256,
                        "sha256": curr.sha256,
                        "package_name": curr.package_name,
                    }),
                });
                events.push(NewEvent {
                    ts: now_ms,
                    event_type: "persistence_change".to_string(),
                    severity,
                    source: SOURCE_PERSISTENCE.to_string(),
                    entity_type: "persistence".to_string(),
                    entity_id: curr.path.clone(),
                    payload: json!({
                        "change": "modified",
                        "category": curr.category,
                        "path": curr.path,
                        "previous_sha256": prev.sha256,
                        "sha256": curr.sha256,
                        "package_name": curr.package_name,
                    }),
                });
            }
            _ => {}
        }
    }

    for prev in previous {
        if !curr_set.contains(&(prev.category.as_str(), prev.path.as_str())) {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "persistence_removed".to_string(),
                severity: Severity::Low,
                entity_type: "persistence".to_string(),
                entity_id: prev.path.clone(),
                title: format!(
                    "Persistencia eliminada ({}) en {}",
                    prev.category, prev.path
                ),
                summary: format!(
                    "Se eliminó {} (SHA-256 previo: {}, paquete: {}).",
                    prev.path, prev.sha256, prev.package_name
                ),
                evidence: json!({
                    "category": prev.category,
                    "path": prev.path,
                    "previous_sha256": prev.sha256,
                    "package_name": prev.package_name,
                }),
            });
        }
    }

    (findings, events)
}

/// Runs a persistence baseline scan, diffs against SQLite, and persists updates/findings/events.
pub async fn run_persistence_once(
    pool: &SqlitePool,
    root_dir: &str,
) -> Result<(PersistenceRunStats, Vec<NewEvent>), sqlx::Error> {
    let pkg_rows: Vec<(String, String)> = sqlx::query_as("SELECT name, files FROM packages")
        .fetch_all(pool)
        .await?;
    let mut file_to_pkg = HashMap::new();
    for (pkg_name, files_json) in pkg_rows {
        if let Ok(files) = serde_json::from_str::<Vec<String>>(&files_json) {
            for f in files {
                file_to_pkg.entry(f).or_insert_with(|| pkg_name.clone());
            }
        }
    }

    let root = PathBuf::from(root_dir);
    let current =
        tokio::task::spawn_blocking(move || scan_persistence_entries(&root, &file_to_pkg))
            .await
            .unwrap_or_default();

    let prev_rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT category, path, sha256, package_name, mode FROM persistence_baseline",
    )
    .fetch_all(pool)
    .await?;
    let previous: Vec<PersistenceEntry> = prev_rows
        .into_iter()
        .map(
            |(category, path, sha256, package_name, mode)| PersistenceEntry {
                category,
                path,
                sha256,
                package_name,
                mode,
            },
        )
        .collect();

    let now_ms = current_unix_ms();
    let (findings, events) = compute_persistence_diff(&previous, &current, now_ms);

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM persistence_baseline")
        .execute(&mut *tx)
        .await?;
    for entry in &current {
        sqlx::query(
            r#"
            INSERT INTO persistence_baseline (
                category, path, sha256, package_name, mode, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&entry.category)
        .bind(&entry.path)
        .bind(&entry.sha256)
        .bind(&entry.package_name)
        .bind(entry.mode)
        .bind(now_ms)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    let mut created = 0usize;
    for f in &findings {
        if upsert_finding_respecting_suppression(pool, f, now_ms)
            .await
            .unwrap_or(false)
        {
            created += 1;
        }
    }
    let _ = insert_events(pool, &events).await;

    info!(
        total_entries = current.len(),
        findings_created = created,
        "persistence baseline scan completed"
    );

    Ok((
        PersistenceRunStats {
            total_entries: current.len(),
            findings_created: created,
        },
        events,
    ))
}

fn collect_user_homes(root: &Path) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    let root_home = root.join("root");
    if root_home.is_dir() {
        homes.push(root_home);
    }
    if let Ok(entries) = std::fs::read_dir(root.join("home")) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                homes.push(entry.path());
            }
        }
    }
    homes
}

fn visit_dir_files<F>(dir: &Path, max_depth: usize, cb: &mut F)
where
    F: FnMut(&Path),
{
    if max_depth == 0 || !dir.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            visit_dir_files(&path, max_depth - 1, cb);
        } else if path.is_file() {
            cb(&path);
        }
    }
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
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
    fn scans_synthetic_persistence_and_detects_added_modified_removed() {
        let root = std::env::temp_dir().join(format!(
            "arch_fos_persist_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        std::fs::create_dir_all(root.join("home/hideon/.config/autostart")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();

        let unit = root.join("etc/systemd/system/custom.service");
        std::fs::write(&unit, "[Service]\nExecStart=/bin/true\n").unwrap();

        let autostart = root.join("home/hideon/.config/autostart/evil.desktop");
        std::fs::write(&autostart, "[Desktop Entry]\nExec=/tmp/x\n").unwrap();

        let suid = root.join("usr/bin/my-suid");
        std::fs::write(&suid, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&suid, std::fs::Permissions::from_mode(0o4755)).unwrap();

        let mut pkg_map = HashMap::new();
        pkg_map.insert(
            "etc/systemd/system/custom.service".to_string(),
            "my-pkg".to_string(),
        );

        let snap1 = scan_persistence_entries(&root, &pkg_map);
        assert!(
            snap1
                .iter()
                .any(|e| e.category == "systemd_unit" && e.package_name == "my-pkg")
        );
        assert!(
            snap1
                .iter()
                .any(|e| e.category == "autostart" && e.package_name == "unowned")
        );
        assert!(
            snap1
                .iter()
                .any(|e| e.category == "suid_sgid" && e.package_name == "unowned")
        );

        let (init_findings, _) = compute_persistence_diff(&[], &snap1, 1000);
        assert!(
            init_findings
                .iter()
                .any(|f| f.rule_id == "persistence_unowned_suid")
        );

        // Modify unit & add ld.so.preload & remove autostart
        std::fs::write(&unit, "[Service]\nExecStart=/tmp/backdoor\n").unwrap();
        std::fs::write(root.join("etc/ld.so.preload"), "/tmp/evil.so\n").unwrap();
        std::fs::remove_file(&autostart).unwrap();

        let snap2 = scan_persistence_entries(&root, &pkg_map);
        let (diff_findings, diff_events) = compute_persistence_diff(&snap1, &snap2, 2000);
        let rules: HashSet<&str> = diff_findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains("persistence_modified"));
        assert!(rules.contains("persistence_added"));
        assert!(rules.contains("persistence_removed"));
        assert!(!diff_events.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }
}
