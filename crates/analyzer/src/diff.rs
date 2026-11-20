use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use arch_fos_common::Severity;
use serde::{Deserialize, Serialize};

use crate::pkgbuild::{
    AnalyzerError, contains_skip_token, extract_url_host, extract_urls, is_checksum_var,
    is_source_var,
};

/// Single structured change detected between two PKGBUILD / `.install` versions (US-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFinding {
    pub rule_id: String,
    pub field: String,
    pub severity: Severity,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub message: String,
}

/// Extracted PKGBUILD metadata fields relevant to update security review.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PkgbuildFields {
    pub url: Option<String>,
    pub sources: Vec<String>,
    pub checksums: Vec<String>,
    pub depends: Vec<String>,
    pub install_file: Option<String>,
}

/// Parses tracked fields (`source`, `*sums`, `url`, `depends`, `install`) from a PKGBUILD string.
#[must_use]
pub fn parse_pkgbuild_fields(content: &str) -> PkgbuildFields {
    let mut fields = PkgbuildFields::default();
    let mut logical_lines = Vec::new();
    let mut buf = String::new();
    let mut paren_depth: i32 = 0;

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !buf.is_empty() {
            buf.push(' ');
        }
        buf.push_str(trimmed);
        for ch in trimmed.chars() {
            match ch {
                '(' => paren_depth += 1,
                ')' => paren_depth = (paren_depth - 1).max(0),
                _ => {}
            }
        }
        if paren_depth == 0 {
            logical_lines.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        logical_lines.push(buf);
    }

    for line in logical_lines {
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let key = lhs.trim();
        let val = rhs.trim();

        if key == "url" {
            fields.url = Some(strip_quotes(val));
        } else if key == "install" {
            fields.install_file = Some(strip_quotes(val));
        } else if is_source_var(key) {
            fields.sources.extend(split_array_items(val));
        } else if is_checksum_var(key) {
            fields.checksums.extend(split_array_items(val));
        } else if key == "depends" || key == "makedepends" {
            fields.depends.extend(split_array_items(val));
        }
    }

    fields
}

/// Compares old and new PKGBUILD (and optional `.install`) versions for risky changes.
#[must_use]
pub fn diff_pkgbuild_versions(
    old_pkgbuild: &str,
    new_pkgbuild: &str,
    old_install: Option<&str>,
    new_install: Option<&str>,
) -> Vec<DiffFinding> {
    let old_f = parse_pkgbuild_fields(old_pkgbuild);
    let new_f = parse_pkgbuild_fields(new_pkgbuild);
    let mut findings = Vec::new();

    // 1. Check `url` domain changes
    if old_f.url != new_f.url {
        let old_host = old_f.url.as_deref().and_then(extract_url_host);
        let new_host = new_f.url.as_deref().and_then(extract_url_host);
        let severity = if old_host != new_host {
            Severity::High
        } else {
            Severity::Info
        };
        findings.push(DiffFinding {
            rule_id: "pkgbuild_diff_url_changed".to_string(),
            field: "url".to_string(),
            severity,
            old_value: old_f.url.clone(),
            new_value: new_f.url.clone(),
            message: "Upstream project URL changed between versions".to_string(),
        });
    }

    // 2. Check `source` changes and specifically domain changes (CRITICAL per US-13)
    let old_hosts: BTreeSet<String> = old_f
        .sources
        .iter()
        .flat_map(|s| extract_urls(s))
        .filter_map(|u| extract_url_host(&u))
        .collect();
    let new_hosts: BTreeSet<String> = new_f
        .sources
        .iter()
        .flat_map(|s| extract_urls(s))
        .filter_map(|u| extract_url_host(&u))
        .collect();

    let added_hosts: Vec<String> = new_hosts.difference(&old_hosts).cloned().collect();
    if !added_hosts.is_empty() {
        findings.push(DiffFinding {
            rule_id: "pkgbuild_diff_source_domain_changed".to_string(),
            field: "source".to_string(),
            severity: Severity::Critical,
            old_value: Some(old_hosts.into_iter().collect::<Vec<_>>().join(", ")),
            new_value: Some(added_hosts.join(", ")),
            message: "New or changed source download domain introduced in PKGBUILD update"
                .to_string(),
        });
    } else if old_f.sources != new_f.sources {
        findings.push(DiffFinding {
            rule_id: "pkgbuild_diff_source_changed".to_string(),
            field: "source".to_string(),
            severity: Severity::Info,
            old_value: Some(old_f.sources.join(" ")),
            new_value: Some(new_f.sources.join(" ")),
            message: "Source entries updated (same domain)".to_string(),
        });
    }

    // 3. Check if a `SKIP` checksum was added (CRITICAL per US-13)
    let old_skips = old_f
        .checksums
        .iter()
        .filter(|c| contains_skip_token(c))
        .count();
    let new_skips = new_f
        .checksums
        .iter()
        .filter(|c| contains_skip_token(c))
        .count();
    if new_skips > old_skips {
        findings.push(DiffFinding {
            rule_id: "pkgbuild_diff_skip_checksum_added".to_string(),
            field: "sha256sums".to_string(),
            severity: Severity::Critical,
            old_value: Some(format!("{old_skips} SKIP entries")),
            new_value: Some(format!("{new_skips} SKIP entries")),
            message: "A checksum entry was weakened to 'SKIP' in the new PKGBUILD version"
                .to_string(),
        });
    }

    // 4. Check dependency additions
    let old_deps: BTreeSet<&str> = old_f.depends.iter().map(String::as_str).collect();
    let new_deps: BTreeSet<&str> = new_f.depends.iter().map(String::as_str).collect();
    let added_deps: Vec<&str> = new_deps.difference(&old_deps).copied().collect();
    if !added_deps.is_empty() {
        findings.push(DiffFinding {
            rule_id: "pkgbuild_diff_depends_added".to_string(),
            field: "depends".to_string(),
            severity: Severity::Low,
            old_value: None,
            new_value: Some(added_deps.join(", ")),
            message: "New package dependencies added".to_string(),
        });
    }

    // 5. Check `.install` script additions or changes
    if old_install != new_install {
        let severity = match (old_install, new_install) {
            (None, Some(_)) => Severity::High,
            (Some(_), Some(_)) => Severity::Medium,
            _ => Severity::Info,
        };
        findings.push(DiffFinding {
            rule_id: "pkgbuild_diff_install_changed".to_string(),
            field: ".install".to_string(),
            severity,
            old_value: old_install.map(|s| format!("{} bytes", s.len())),
            new_value: new_install.map(|s| format!("{} bytes", s.len())),
            message: "Install scriptlet (.install) added or modified".to_string(),
        });
    }

    findings
}

/// Diffs two revisions (`from_rev`..`to_rev`) inside a local AUR git repository.
pub fn diff_aur_git_repo(
    repo_dir: &Path,
    from_rev: &str,
    to_rev: &str,
) -> Result<Vec<DiffFinding>, AnalyzerError> {
    let old_pkg = git_show_optional(repo_dir, from_rev, "PKGBUILD")?;
    let new_pkg = git_show_optional(repo_dir, to_rev, "PKGBUILD")?;
    let (Some(old_pkg), Some(new_pkg)) = (old_pkg, new_pkg) else {
        return Err(AnalyzerError::Git(format!(
            "PKGBUILD missing at {from_rev} or {to_rev} in {}",
            repo_dir.display()
        )));
    };

    let old_fields = parse_pkgbuild_fields(&old_pkg);
    let new_fields = parse_pkgbuild_fields(&new_pkg);

    let old_install = match old_fields.install_file.as_deref() {
        Some(name) => git_show_optional(repo_dir, from_rev, name)?,
        None => find_install_in_tree(repo_dir, from_rev)?,
    };
    let new_install = match new_fields.install_file.as_deref() {
        Some(name) => git_show_optional(repo_dir, to_rev, name)?,
        None => find_install_in_tree(repo_dir, to_rev)?,
    };

    Ok(diff_pkgbuild_versions(
        &old_pkg,
        &new_pkg,
        old_install.as_deref(),
        new_install.as_deref(),
    ))
}

fn git_show_optional(
    repo_dir: &Path,
    rev: &str,
    file: &str,
) -> Result<Option<String>, AnalyzerError> {
    let spec = format!("{rev}:{file}");
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("show")
        .arg(&spec)
        .output()
        .map_err(|err| AnalyzerError::Git(err.to_string()))?;

    if out.status.success() {
        Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
    } else {
        Ok(None)
    }
}

fn find_install_in_tree(repo_dir: &Path, rev: &str) -> Result<Option<String>, AnalyzerError> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["ls-tree", "--name-only", rev])
        .output()
        .map_err(|err| AnalyzerError::Git(err.to_string()))?;

    if !out.status.success() {
        return Ok(None);
    }

    let names = String::from_utf8_lossy(&out.stdout);
    let mut sorted: BTreeMap<String, ()> = BTreeMap::new();
    for line in names.lines() {
        if line.ends_with(".install") {
            sorted.insert(line.to_string(), ());
        }
    }
    if let Some((first, _)) = sorted.into_iter().next() {
        return git_show_optional(repo_dir, rev, &first);
    }
    Ok(None)
}

fn strip_quotes(raw: &str) -> String {
    raw.trim().trim_matches(['"', '\'']).to_string()
}

fn split_array_items(raw: &str) -> Vec<String> {
    let inner = raw.trim().trim_start_matches('(').trim_end_matches(')');
    inner
        .split_whitespace()
        .map(|s| s.trim_matches(['"', '\'']).to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
