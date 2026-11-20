use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use alpm::{Alpm, PackageReason, SigLevel};
use arch_fos_common::{InstallReason, NewEvent, Severity};
use serde_json::json;
use thiserror::Error;

use crate::db::{DbError, StoredPackageState, apply_package_snapshot, load_stored_packages};

const SOURCE_ALPM: &str = "collector:alpm";

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("alpm initialization error: {0}")]
    Alpm(#[from] alpm::Error),
    #[error("io error reading sync directory {0}: {1}")]
    Io(String, std::io::Error),
    #[error("database error: {0}")]
    Db(#[from] DbError),
}

/// Snapshot of a single installed package read from ALPM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSnapshot {
    pub name: String,
    pub version: String,
    pub repo: Option<String>,
    pub is_foreign: bool,
    pub install_date: Option<i64>,
    pub reason: InstallReason,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub files: Vec<String>,
}

/// Result of diffing the current ALPM snapshot against stored packages.
#[derive(Debug)]
pub struct PackageDiff<'a> {
    pub upserts: Vec<(&'a PackageSnapshot, i64)>,
    pub unchanged_names: Vec<&'a str>,
    pub removed_names: Vec<String>,
    pub events: Vec<NewEvent>,
    pub installed_count: usize,
    pub removed_count: usize,
    pub upgraded_count: usize,
}

/// Summary returned after running one inventory collection cycle.
#[derive(Debug, Clone)]
pub struct InventoryRunStats {
    pub total_packages: usize,
    pub foreign_packages: usize,
    pub installed: usize,
    pub removed: usize,
    pub upgraded: usize,
    pub elapsed_ms: u128,
    pub events: Vec<NewEvent>,
}

/// Reads the local ALPM database and sync DBs to classify repo vs. foreign packages.
pub fn read_alpm_inventory(
    root_dir: &str,
    pacman_db_path: &str,
) -> Result<Vec<PackageSnapshot>, InventoryError> {
    let alpm = Alpm::new(root_dir, pacman_db_path)?;

    // Register every *.db file in <pacman_db_path>/sync so we know official/configured repos.
    let sync_dir = Path::new(pacman_db_path).join("sync");
    if sync_dir.is_dir() {
        let mut repo_names = Vec::new();
        let entries = std::fs::read_dir(&sync_dir)
            .map_err(|err| InventoryError::Io(sync_dir.display().to_string(), err))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("db")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                repo_names.push(stem.to_string());
            }
        }
        repo_names.sort();
        for repo_name in repo_names {
            let _ = alpm.register_syncdb(repo_name.as_str(), SigLevel::USE_DEFAULT);
        }
    }

    // Build lookup map: package name -> first matching sync repo name.
    let mut repo_by_pkg: HashMap<String, String> = HashMap::new();
    for db in alpm.syncdbs() {
        let repo_name = db.name().to_string();
        for pkg in db.pkgs() {
            repo_by_pkg
                .entry(pkg.name().to_string())
                .or_insert_with(|| repo_name.clone());
        }
    }

    let local_db = alpm.localdb();
    let local_pkgs = local_db.pkgs();
    let mut snapshots = Vec::with_capacity(local_pkgs.len());

    for pkg in local_pkgs {
        let name = pkg.name().to_string();
        let repo = repo_by_pkg.get(&name).cloned();
        let is_foreign = repo.is_none();
        let reason = match pkg.reason() {
            PackageReason::Explicit => InstallReason::Explicit,
            PackageReason::Depend => InstallReason::Dependency,
        };
        let install_date = pkg.install_date().map(|secs| secs * 1000);
        let files = pkg
            .files()
            .files()
            .iter()
            .map(|f| String::from_utf8_lossy(f.name()).into_owned())
            .collect();

        snapshots.push(PackageSnapshot {
            name,
            version: pkg.version().to_string(),
            repo,
            is_foreign,
            install_date,
            reason,
            description: pkg.desc().map(str::to_string),
            size_bytes: pkg.isize(),
            files,
        });
    }

    Ok(snapshots)
}

/// Computes package inventory changes and diff events (`package_installed`, `package_removed`, `package_upgraded`).
pub fn compute_package_diff<'a>(
    previous: &[StoredPackageState],
    current: &'a [PackageSnapshot],
    now_ms: i64,
) -> PackageDiff<'a> {
    let prev_map: HashMap<&str, &StoredPackageState> =
        previous.iter().map(|p| (p.name.as_str(), p)).collect();
    let current_names: HashSet<&str> = current.iter().map(|p| p.name.as_str()).collect();
    let is_initial_baseline = previous.is_empty();

    let mut upserts = Vec::new();
    let mut unchanged_names = Vec::new();
    let mut removed_names = Vec::new();
    let mut events = Vec::new();
    let mut installed_count = 0usize;
    let mut removed_count = 0usize;
    let mut upgraded_count = 0usize;

    for pkg in current {
        match prev_map.get(pkg.name.as_str()) {
            None => {
                upserts.push((pkg, now_ms));
                if !is_initial_baseline {
                    installed_count += 1;
                    events.push(NewEvent {
                        ts: now_ms,
                        event_type: "package_installed".to_string(),
                        severity: if pkg.is_foreign {
                            Severity::Low
                        } else {
                            Severity::Info
                        },
                        source: SOURCE_ALPM.to_string(),
                        entity_type: "package".to_string(),
                        entity_id: pkg.name.clone(),
                        payload: json!({
                            "version": pkg.version,
                            "repo": pkg.repo,
                            "is_foreign": pkg.is_foreign,
                            "reason": pkg.reason.as_str(),
                        }),
                    });
                }
            }
            Some(prev) => {
                let changed = prev.version != pkg.version
                    || prev.repo != pkg.repo
                    || prev.is_foreign != pkg.is_foreign
                    || prev.reason != pkg.reason;

                if changed {
                    upserts.push((pkg, prev.first_seen_at));
                } else {
                    unchanged_names.push(pkg.name.as_str());
                }

                if prev.version != pkg.version {
                    upgraded_count += 1;
                    events.push(NewEvent {
                        ts: now_ms,
                        event_type: "package_upgraded".to_string(),
                        severity: Severity::Info,
                        source: SOURCE_ALPM.to_string(),
                        entity_type: "package".to_string(),
                        entity_id: pkg.name.clone(),
                        payload: json!({
                            "from_version": prev.version,
                            "to_version": pkg.version,
                            "repo": pkg.repo,
                            "is_foreign": pkg.is_foreign,
                        }),
                    });
                }
            }
        }
    }

    for prev in previous {
        if !current_names.contains(prev.name.as_str()) {
            removed_names.push(prev.name.clone());
            removed_count += 1;
            events.push(NewEvent {
                ts: now_ms,
                event_type: "package_removed".to_string(),
                severity: Severity::Info,
                source: SOURCE_ALPM.to_string(),
                entity_type: "package".to_string(),
                entity_id: prev.name.clone(),
                payload: json!({
                    "previous_version": prev.version,
                    "repo": prev.repo,
                    "is_foreign": prev.is_foreign,
                }),
            });
        }
    }

    if is_initial_baseline && !current.is_empty() {
        let foreign_count = current.iter().filter(|p| p.is_foreign).count();
        events.push(NewEvent {
            ts: now_ms,
            event_type: "package_inventory_baseline".to_string(),
            severity: Severity::Info,
            source: SOURCE_ALPM.to_string(),
            entity_type: "system".to_string(),
            entity_id: "pacman".to_string(),
            payload: json!({
                "total_packages": current.len(),
                "foreign_packages": foreign_count,
            }),
        });
    }

    PackageDiff {
        upserts,
        unchanged_names,
        removed_names,
        events,
        installed_count,
        removed_count,
        upgraded_count,
    }
}

/// Runs one full package inventory snapshot and persists the diff to SQLite.
pub async fn run_inventory_once(
    pool: &sqlx::SqlitePool,
    root_dir: &str,
    pacman_db_path: &str,
) -> Result<InventoryRunStats, InventoryError> {
    let start = std::time::Instant::now();
    let root = root_dir.to_string();
    let db = pacman_db_path.to_string();

    // ALPM calls are synchronous FFI; run on blocking pool to keep Tokio runtime responsive.
    let current = tokio::task::spawn_blocking(move || read_alpm_inventory(&root, &db))
        .await
        .map_err(|err| {
            InventoryError::Io("spawn_blocking".to_string(), std::io::Error::other(err))
        })??;

    let previous = load_stored_packages(pool).await?;
    let now_ms = current_unix_ms();
    let diff = compute_package_diff(&previous, &current, now_ms);

    apply_package_snapshot(
        pool,
        &diff.upserts,
        &diff.unchanged_names,
        &diff.removed_names,
        &diff.events,
        now_ms,
    )
    .await?;

    let foreign_packages = current.iter().filter(|p| p.is_foreign).count();

    Ok(InventoryRunStats {
        total_packages: current.len(),
        foreign_packages,
        installed: diff.installed_count,
        removed: diff.removed_count,
        upgraded: diff.upgraded_count,
        elapsed_ms: start.elapsed().as_millis(),
        events: diff.events,
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

    fn sample_snapshot(name: &str, version: &str, is_foreign: bool) -> PackageSnapshot {
        PackageSnapshot {
            name: name.to_string(),
            version: version.to_string(),
            repo: if is_foreign {
                None
            } else {
                Some("core".to_string())
            },
            is_foreign,
            install_date: Some(1_700_000_000_000),
            reason: InstallReason::Explicit,
            description: Some("sample".to_string()),
            size_bytes: 1024,
            files: vec!["usr/bin/sample".to_string()],
        }
    }

    #[test]
    fn initial_baseline_emits_single_baseline_event() {
        let current = vec![
            sample_snapshot("linux", "6.12.1-1", false),
            sample_snapshot("yay-bin", "12.4.2-1", true),
        ];
        let diff = compute_package_diff(&[], &current, 5000);
        assert_eq!(diff.upserts.len(), 2);
        assert_eq!(diff.events.len(), 1);
        assert_eq!(diff.events[0].event_type, "package_inventory_baseline");
        assert_eq!(diff.installed_count, 0);
    }

    #[test]
    fn diff_detects_installed_upgraded_removed_and_unchanged() {
        let previous = vec![
            StoredPackageState {
                name: "linux".to_string(),
                version: "6.12.1-1".to_string(),
                repo: Some("core".to_string()),
                is_foreign: false,
                reason: InstallReason::Explicit,
                first_seen_at: 1000,
            },
            StoredPackageState {
                name: "bash".to_string(),
                version: "5.2.37-1".to_string(),
                repo: Some("core".to_string()),
                is_foreign: false,
                reason: InstallReason::Explicit,
                first_seen_at: 1000,
            },
            StoredPackageState {
                name: "htop".to_string(),
                version: "3.3.0-1".to_string(),
                repo: Some("extra".to_string()),
                is_foreign: false,
                reason: InstallReason::Explicit,
                first_seen_at: 1000,
            },
        ];

        let current = vec![
            sample_snapshot("linux", "6.12.2-1", false),  // upgraded
            sample_snapshot("bash", "5.2.37-1", false),   // unchanged
            sample_snapshot("aur-helper", "1.0-1", true), // installed
        ];

        let diff = compute_package_diff(&previous, &current, 2000);
        assert_eq!(diff.installed_count, 1);
        assert_eq!(diff.upgraded_count, 1);
        assert_eq!(diff.removed_count, 1);
        assert_eq!(diff.unchanged_names, vec!["bash"]);
        assert_eq!(diff.removed_names, vec!["htop"]);

        let event_types: Vec<&str> = diff.events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(event_types.contains(&"package_installed"));
        assert!(event_types.contains(&"package_upgraded"));
        assert!(event_types.contains(&"package_removed"));
    }
}
