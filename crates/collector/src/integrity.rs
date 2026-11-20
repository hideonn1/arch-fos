use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alpm::Alpm;
use arch_fos_common::Severity;
use flate2::read::GzDecoder;
use serde_json::json;
use sqlx::SqlitePool;
use tracing::info;

use crate::db::{NewFinding, upsert_finding_respecting_suppression};
use crate::persistence::sha256_file;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtreeFileExpectation {
    pub rel_path: String,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IntegrityRunStats {
    pub packages_checked: usize,
    pub files_verified: usize,
    pub mismatches_found: usize,
}

/// Parses a gzipped ALPM `mtree` file, extracting expected SHA-256 digests for regular files.
pub fn parse_mtree_file(mtree_path: &Path) -> Result<Vec<MtreeFileExpectation>, std::io::Error> {
    let file = File::open(mtree_path)?;
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);

    let mut default_type = String::from("file");
    let mut entries = Vec::new();

    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/set ") {
            for tok in rest.split_whitespace() {
                if let Some(t) = tok.strip_prefix("type=") {
                    default_type = t.to_string();
                }
            }
            continue;
        }
        if trimmed.starts_with('/') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(raw_path) = parts.next() else {
            continue;
        };
        let rel_path = unescape_mtree_path(raw_path.trim_start_matches("./"));
        if rel_path.starts_with('.') {
            // Skip package metadata (.PKGINFO, .BUILDINFO, .MTREE, .INSTALL)
            continue;
        }

        let mut entry_type = default_type.as_str();
        let mut expected_sha256 = None;

        for tok in parts {
            if let Some(t) = tok.strip_prefix("type=") {
                entry_type = t;
            } else if let Some(digest) = tok.strip_prefix("sha256digest=") {
                expected_sha256 = Some(digest.to_ascii_lowercase());
            }
        }

        if entry_type == "file"
            && let Some(digest) = expected_sha256
        {
            entries.push(MtreeFileExpectation {
                rel_path,
                expected_sha256: digest,
            });
        }
    }

    Ok(entries)
}

/// Verifies integrity of a single package's mtree expectations against disk, skipping `backup` files.
#[must_use]
pub fn verify_package_mtree(
    pkg_name: &str,
    root_dir: &Path,
    expectations: &[MtreeFileExpectation],
    backup_paths: &HashSet<String>,
    now_ms: i64,
) -> (usize, Vec<NewFinding>) {
    let mut verified = 0usize;
    let mut findings = Vec::new();

    for exp in expectations {
        if backup_paths.contains(&exp.rel_path) {
            continue;
        }
        let full_path = root_dir.join(&exp.rel_path);
        if !full_path.is_file() {
            continue;
        }
        verified += 1;
        let Ok(actual_sha256) = sha256_file(&full_path) else {
            continue;
        };
        if actual_sha256 != exp.expected_sha256 {
            let abs_display = format!("/{}", exp.rel_path);
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "package_integrity_mismatch".to_string(),
                severity: Severity::High,
                entity_type: "package".to_string(),
                entity_id: pkg_name.to_string(),
                title: format!("Archivo alterado en paquete {pkg_name}: {abs_display}"),
                summary: format!(
                    "SHA-256 esperado {} vs actual {} (no declarado en backup).",
                    exp.expected_sha256, actual_sha256
                ),
                evidence: json!({
                    "package": pkg_name,
                    "file": abs_display,
                    "expected_sha256": exp.expected_sha256,
                    "actual_sha256": actual_sha256,
                }),
            });
        }
    }

    (verified, findings)
}

/// Equivalent to `pacman -Qkk`: verifies installed package files against ALPM mtree SHA-256 digests,
/// excluding configuration files listed in each package's `backup` array (US-10).
pub async fn run_integrity_check_once(
    pool: &SqlitePool,
    root_dir: &str,
    pacman_db_path: &str,
) -> Result<IntegrityRunStats, Box<dyn std::error::Error + Send + Sync>> {
    let root = root_dir.to_string();
    let db = pacman_db_path.to_string();
    let now_ms = current_unix_ms();

    let (stats, findings) = tokio::task::spawn_blocking(move || {
        let mut stats = IntegrityRunStats::default();
        let mut all_findings = Vec::new();

        let Ok(alpm) = Alpm::new(root.as_str(), db.as_str()) else {
            return (stats, all_findings);
        };
        let root_path = Path::new(&root);
        let local_dir = PathBuf::from(&db).join("local");

        for pkg in alpm.localdb().pkgs() {
            let name = pkg.name();
            let ver = pkg.version().as_str();
            let mtree_path = local_dir.join(format!("{name}-{ver}")).join("mtree");
            if !mtree_path.is_file() {
                continue;
            }
            let Ok(expectations) = parse_mtree_file(&mtree_path) else {
                continue;
            };
            let backup_paths: HashSet<String> = pkg
                .backup()
                .iter()
                .map(|b| b.name().trim_start_matches('/').to_string())
                .collect();

            stats.packages_checked += 1;
            let (verified, pkg_findings) =
                verify_package_mtree(name, root_path, &expectations, &backup_paths, now_ms);
            stats.files_verified += verified;
            all_findings.extend(pkg_findings);
        }

        (stats, all_findings)
    })
    .await?;

    let mut created = 0usize;
    for f in &findings {
        if upsert_finding_respecting_suppression(pool, f, now_ms).await? {
            created += 1;
        }
    }

    info!(
        packages_checked = stats.packages_checked,
        files_verified = stats.files_verified,
        mismatches = findings.len(),
        findings_created = created,
        "package integrity verification (Qkk) completed"
    );

    Ok(IntegrityRunStats {
        packages_checked: stats.packages_checked,
        files_verified: stats.files_verified,
        mismatches_found: findings.len(),
    })
}

fn unescape_mtree_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
            && let Ok(s) = std::str::from_utf8(&bytes[i + 1..i + 4])
            && let Ok(val) = u8::from_str_radix(s, 8)
        {
            out.push(char::from(val));
            i += 4;
            continue;
        }
        out.push(char::from(bytes[i]));
        i += 1;
    }
    out
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
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn verifies_mtree_sha256_and_skips_backup_configs() {
        let dir = std::env::temp_dir().join(format!(
            "arch_fos_mtree_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();

        let good_bin = dir.join("usr/bin/good");
        std::fs::write(&good_bin, b"good-binary").unwrap();
        let good_sha = sha256_file(&good_bin).unwrap();

        let tampered_bin = dir.join("usr/bin/tampered");
        std::fs::write(&tampered_bin, b"tampered-binary").unwrap();

        let backup_cfg = dir.join("etc/demo.conf");
        std::fs::write(&backup_cfg, b"user-edited-config").unwrap();

        let mtree_content = format!(
            "#mtree\n/set type=file uid=0 gid=0 mode=755\n./.PKGINFO time=1 size=10 sha256digest=0000\n./usr/bin/good time=1 size=11 sha256digest={good_sha}\n./usr/bin/tampered time=1 size=10 sha256digest=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n./etc/demo.conf time=1 size=5 sha256digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        );
        let mtree_path = dir.join("mtree");
        let f = File::create(&mtree_path).unwrap();
        let mut gz = GzEncoder::new(f, Compression::default());
        gz.write_all(mtree_content.as_bytes()).unwrap();
        gz.finish().unwrap();

        let expectations = parse_mtree_file(&mtree_path).unwrap();
        assert_eq!(expectations.len(), 3); // .PKGINFO excluded

        let mut backup_set = HashSet::new();
        backup_set.insert("etc/demo.conf".to_string());

        let (verified, findings) =
            verify_package_mtree("demo-pkg", &dir, &expectations, &backup_set, 1000);
        assert_eq!(verified, 2); // backup excluded
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "package_integrity_mismatch");
        assert_eq!(findings[0].evidence["file"], "/usr/bin/tampered");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
