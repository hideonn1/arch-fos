//! Static PKGBUILD / `.install` analysis (US-12) and AUR git diffing (US-13).

pub mod diff;
pub mod pkgbuild;

pub use diff::{DiffFinding, diff_aur_git_repo, diff_pkgbuild_versions, parse_pkgbuild_fields};
pub use pkgbuild::{
    ALL_STATIC_RULE_IDS, AnalyzerConfig, AnalyzerError, ScriptKind, StaticFinding, analyze_file,
    analyze_script,
};
