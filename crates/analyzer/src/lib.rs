//! Static PKGBUILD / `.install` analysis (US-12), AUR git diffing (US-13),
//! and sandboxed package build / artifact inspection (US-15).

pub mod diff;
pub mod pkgbuild;
pub mod sandbox;

pub use diff::{DiffFinding, diff_aur_git_repo, diff_pkgbuild_versions, parse_pkgbuild_fields};
pub use pkgbuild::{
    ALL_STATIC_RULE_IDS, AnalyzerConfig, AnalyzerError, ScriptKind, StaticFinding, analyze_file,
    analyze_script,
};
pub use sandbox::{
    ArtifactInspection, ExternalScanResult, SandboxBackend, SandboxBuildOptions,
    SandboxBuildReport, build_sandbox_command_args, inspect_package_artifact,
    sandbox_build_and_scan, scan_artifact_with_external_tools,
};
