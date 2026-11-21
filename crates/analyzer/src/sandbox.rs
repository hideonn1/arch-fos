use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::pkgbuild::{AnalyzerConfig, AnalyzerError, ScriptKind, StaticFinding, analyze_script};

/// Sandbox isolation backend for package building (US-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    Bwrap,
    SystemdNspawn,
}

/// Options controlling sandboxed package build and artifact scanning (US-15).
#[derive(Debug, Clone)]
pub struct SandboxBuildOptions {
    pub backend: SandboxBackend,
    pub skip_download: bool,
    pub yara_rules: Option<PathBuf>,
}

impl Default for SandboxBuildOptions {
    fn default() -> Self {
        Self {
            backend: SandboxBackend::Bwrap,
            skip_download: false,
            yara_rules: None,
        }
    }
}

/// Status of an external security scanner invoked on built package artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalScanResult {
    pub tool: String,
    pub status: String,
    pub findings_count: usize,
    pub summary: String,
}

/// Inspected metadata and scriptlets extracted from a built `.pkg.tar.*` artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInspection {
    pub artifact_path: String,
    pub files_count: usize,
    pub install_script_present: bool,
    pub install_script_findings: Vec<StaticFinding>,
    pub pkginfo_excerpt: Vec<String>,
}

/// Complete report returned by `sandbox_build_and_scan` (US-15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxBuildReport {
    pub backend: SandboxBackend,
    pub network_isolated_during_build: bool,
    pub pkgbuild_dir: String,
    pub build_succeeded: bool,
    pub build_log_tail: String,
    pub artifacts: Vec<ArtifactInspection>,
    pub scanner_results: Vec<ExternalScanResult>,
}

/// Builds the argument list for network-isolated `bwrap` or `systemd-nspawn` execution.
#[must_use]
pub fn build_sandbox_command_args(
    backend: SandboxBackend,
    work_dir: &Path,
) -> (String, Vec<String>) {
    let dir_str = work_dir.display().to_string();
    match backend {
        SandboxBackend::Bwrap => (
            "bwrap".to_string(),
            vec![
                "--ro-bind".into(),
                "/usr".into(),
                "/usr".into(),
                "--ro-bind".into(),
                "/etc".into(),
                "/etc".into(),
                "--symlink".into(),
                "usr/bin".into(),
                "/bin".into(),
                "--symlink".into(),
                "usr/lib".into(),
                "/lib".into(),
                "--symlink".into(),
                "usr/lib".into(),
                "/lib64".into(),
                "--dev".into(),
                "/dev".into(),
                "--proc".into(),
                "/proc".into(),
                "--tmpfs".into(),
                "/tmp".into(),
                "--bind".into(),
                dir_str,
                "/build".into(),
                "--chdir".into(),
                "/build".into(),
                "--unshare-net".into(),
                "--die-with-parent".into(),
                "makepkg".into(),
                "--noextract".into(),
                "--nodeps".into(),
                "--force".into(),
                "--noconfirm".into(),
            ],
        ),
        SandboxBackend::SystemdNspawn => (
            "systemd-nspawn".to_string(),
            vec![
                "--private-network".into(),
                "--read-only".into(),
                "--directory=/".into(),
                format!("--bind={dir_str}:/build"),
                "--chdir=/build".into(),
                "makepkg".into(),
                "--noextract".into(),
                "--nodeps".into(),
                "--force".into(),
                "--noconfirm".into(),
            ],
        ),
    }
}

/// Executes a two-phase sandboxed build (download sources -> network-isolated build) and scans
/// resulting `.pkg.tar.*` artifacts for `.INSTALL` scriptlets, YARA/ClamAV, SBOM, and CVEs.
pub fn sandbox_build_and_scan(
    pkgbuild_dir: &Path,
    opts: &SandboxBuildOptions,
) -> Result<SandboxBuildReport, AnalyzerError> {
    let abs_dir = pkgbuild_dir
        .canonicalize()
        .map_err(|err| AnalyzerError::Io(pkgbuild_dir.display().to_string(), err))?;

    // Phase 1: Download & extract sources before cutting off network
    if !opts.skip_download {
        let dl = Command::new("makepkg")
            .current_dir(&abs_dir)
            .args(["--nobuild", "--nodeps", "--noconfirm"])
            .output()
            .map_err(|err| AnalyzerError::Io("makepkg".into(), err))?;
        if !dl.status.success() {
            let stderr = String::from_utf8_lossy(&dl.stderr);
            return Ok(SandboxBuildReport {
                backend: opts.backend,
                network_isolated_during_build: true,
                pkgbuild_dir: abs_dir.display().to_string(),
                build_succeeded: false,
                build_log_tail: tail_lines(&stderr, 30),
                artifacts: Vec::new(),
                scanner_results: Vec::new(),
            });
        }
    }

    // Phase 2: Build inside isolated sandbox with NO network access
    let (program, args) = build_sandbox_command_args(opts.backend, &abs_dir);
    let build_out = Command::new(&program)
        .args(&args)
        .output()
        .map_err(|err| AnalyzerError::Io(program.clone(), err))?;

    let combined_log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&build_out.stdout),
        String::from_utf8_lossy(&build_out.stderr)
    );

    let mut artifacts = Vec::new();
    let mut scanner_results = Vec::new();

    if build_out.status.success() {
        let pkg_files = find_built_pkg_artifacts(&abs_dir);
        let cfg = AnalyzerConfig::default();
        for artifact in &pkg_files {
            if let Ok(insp) = inspect_package_artifact(artifact, &cfg) {
                artifacts.push(insp);
            }
            scanner_results.extend(scan_artifact_with_external_tools(
                artifact,
                opts.yara_rules.as_deref(),
            ));
        }
    }

    Ok(SandboxBuildReport {
        backend: opts.backend,
        network_isolated_during_build: true,
        pkgbuild_dir: abs_dir.display().to_string(),
        build_succeeded: build_out.status.success(),
        build_log_tail: tail_lines(&combined_log, 30),
        artifacts,
        scanner_results,
    })
}

/// Inspects a built `.pkg.tar.*` archive (file list, `.PKGINFO`, and static analysis of `.INSTALL`).
pub fn inspect_package_artifact(
    artifact_path: &Path,
    cfg: &AnalyzerConfig,
) -> Result<ArtifactInspection, AnalyzerError> {
    let list_out = Command::new("tar")
        .arg("-tf")
        .arg(artifact_path)
        .output()
        .map_err(|err| AnalyzerError::Io("tar".into(), err))?;

    if !list_out.status.success() {
        return Err(AnalyzerError::Io(
            artifact_path.display().to_string(),
            std::io::Error::other(String::from_utf8_lossy(&list_out.stderr).to_string()),
        ));
    }

    let listing = String::from_utf8_lossy(&list_out.stdout);
    let files: Vec<&str> = listing.lines().filter(|l| !l.is_empty()).collect();
    let has_install = files.iter().any(|f| *f == ".INSTALL" || *f == "./.INSTALL");
    let has_pkginfo = files.iter().any(|f| *f == ".PKGINFO" || *f == "./.PKGINFO");

    let mut install_findings = Vec::new();
    if has_install {
        let target = if files.contains(&".INSTALL") {
            ".INSTALL"
        } else {
            "./.INSTALL"
        };
        if let Ok(extract) = Command::new("tar")
            .args(["-xOf"])
            .arg(artifact_path)
            .arg(target)
            .output()
            && extract.status.success()
        {
            let script = String::from_utf8_lossy(&extract.stdout);
            if let Ok(found) = analyze_script(".INSTALL", &script, ScriptKind::InstallScript, cfg) {
                install_findings = found;
            }
        }
    }

    let mut pkginfo_excerpt = Vec::new();
    if has_pkginfo {
        let target = if files.contains(&".PKGINFO") {
            ".PKGINFO"
        } else {
            "./.PKGINFO"
        };
        if let Ok(extract) = Command::new("tar")
            .args(["-xOf"])
            .arg(artifact_path)
            .arg(target)
            .output()
            && extract.status.success()
        {
            let text = String::from_utf8_lossy(&extract.stdout);
            for line in text.lines() {
                if line.starts_with("pkgname =")
                    || line.starts_with("pkgver =")
                    || line.starts_with("url =")
                    || line.starts_with("depend =")
                {
                    pkginfo_excerpt.push(line.to_string());
                }
            }
        }
    }

    Ok(ArtifactInspection {
        artifact_path: artifact_path.display().to_string(),
        files_count: files.len(),
        install_script_present: has_install,
        install_script_findings: install_findings,
        pkginfo_excerpt,
    })
}

/// Runs optional host scanners (`yara`, `clamscan`, `syft`, `grype`, `osv-scanner`) on an artifact.
#[must_use]
pub fn scan_artifact_with_external_tools(
    artifact_path: &Path,
    yara_rules: Option<&Path>,
) -> Vec<ExternalScanResult> {
    let mut results = Vec::new();

    // 1. YARA
    if let Some(rules) = yara_rules {
        results.push(run_optional_tool(
            "yara",
            &[
                "-r".to_string(),
                rules.display().to_string(),
                artifact_path.display().to_string(),
            ],
        ));
    } else {
        results.push(ExternalScanResult {
            tool: "yara".to_string(),
            status: "skipped".to_string(),
            findings_count: 0,
            summary: "no --yara-rules path provided".to_string(),
        });
    }

    // 2. ClamAV
    results.push(run_optional_tool(
        "clamscan",
        &["--no-summary".into(), artifact_path.display().to_string()],
    ));

    // 3. SBOM via syft
    results.push(run_optional_tool(
        "syft",
        &[
            "packages".into(),
            artifact_path.display().to_string(),
            "-o".into(),
            "cyclonedx-json".into(),
        ],
    ));

    // 4. Vulnerability scan via grype or osv-scanner
    let grype_res = run_optional_tool(
        "grype",
        &[
            artifact_path.display().to_string(),
            "-o".into(),
            "json".into(),
        ],
    );
    if grype_res.status != "not_installed" {
        results.push(grype_res);
    } else {
        results.push(run_optional_tool(
            "osv-scanner",
            &["scan".into(), artifact_path.display().to_string()],
        ));
    }

    results
}

fn run_optional_tool(tool: &str, args: &[String]) -> ExternalScanResult {
    match Command::new(tool).args(args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines = stdout.lines().filter(|l| !l.trim().is_empty()).count();
            let status = if out.status.success() {
                "completed"
            } else {
                "flagged"
            };
            ExternalScanResult {
                tool: tool.to_string(),
                status: status.to_string(),
                findings_count: if status == "flagged" { lines.max(1) } else { 0 },
                summary: tail_lines(&stdout, 5),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => ExternalScanResult {
            tool: tool.to_string(),
            status: "not_installed".to_string(),
            findings_count: 0,
            summary: format!("{tool} not found in PATH"),
        },
        Err(err) => ExternalScanResult {
            tool: tool.to_string(),
            status: "error".to_string(),
            findings_count: 0,
            summary: err.to_string(),
        },
    }
}

fn find_built_pkg_artifacts(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|s| s.to_str())
                && name.contains(".pkg.tar.")
                && !name.ends_with(".sig")
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn tail_lines(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}
