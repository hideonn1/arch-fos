use std::collections::HashSet;
use std::path::Path;

use arch_fos_common::Severity;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tree_sitter::{Node, Parser};

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("failed to load tree-sitter-bash grammar: {0}")]
    Language(String),
    #[error("failed to parse bash AST")]
    ParseFailed,
    #[error("io error reading {0}: {1}")]
    Io(String, std::io::Error),
    #[error("git command failed: {0}")]
    Git(String),
}

/// Kind of file being analyzed statically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptKind {
    Pkgbuild,
    InstallScript,
}

/// Structured finding emitted by the PKGBUILD / `.install` static analyzer (US-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticFinding {
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    pub severity: Severity,
    pub snippet: String,
    pub message: String,
}

/// Configurable analyzer options (such as trusted source domains).
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub allowed_domains: HashSet<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        let defaults = [
            "archlinux.org",
            "github.com",
            "githubusercontent.com",
            "gitlab.com",
            "gitlab.archlinux.org",
            "codeberg.org",
            "sr.ht",
            "kernel.org",
            "gnu.org",
            "savannah.gnu.org",
            "apache.org",
            "sourceforge.net",
            "pypi.org",
            "files.pythonhosted.org",
            "crates.io",
            "static.crates.io",
            "gnome.org",
            "kde.org",
            "freedesktop.org",
            "x.org",
            "llvm.org",
            "python.org",
            "nodejs.org",
            "rust-lang.org",
            "mozilla.org",
            "openssl.org",
            "zlib.net",
            "tukaani.org",
            "curl.se",
            "sqlite.org",
        ];
        Self {
            allowed_domains: defaults.into_iter().map(str::to_string).collect(),
        }
    }
}

/// All static rule IDs implemented for US-12.
pub const ALL_STATIC_RULE_IDS: &[&str] = &[
    "pkgbuild_curl_pipe_sh",
    "pkgbuild_wget_pipe_sh",
    "pkgbuild_base64_decode",
    "pkgbuild_eval",
    "pkgbuild_skip_checksum",
    "pkgbuild_untrusted_source_domain",
    "pkgbuild_write_outside_pkgdir",
    "install_systemctl_enable",
    "install_network_command",
];

/// Analyzes a file on disk, inferring `Pkgbuild` vs `InstallScript` from its name.
pub fn analyze_file(
    path: &Path,
    cfg: &AnalyzerConfig,
) -> Result<Vec<StaticFinding>, AnalyzerError> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| AnalyzerError::Io(path.display().to_string(), err))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("PKGBUILD");
    let kind = if file_name.ends_with(".install") {
        ScriptKind::InstallScript
    } else {
        ScriptKind::Pkgbuild
    };
    analyze_script(&path.display().to_string(), &content, kind, cfg)
}

/// Analyzes PKGBUILD or `.install` source text with `tree-sitter-bash`.
pub fn analyze_script(
    file_label: &str,
    source: &str,
    kind: ScriptKind,
    cfg: &AnalyzerConfig,
) -> Result<Vec<StaticFinding>, AnalyzerError> {
    let mut parser = Parser::new();
    let language = tree_sitter_bash::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|err| AnalyzerError::Language(err.to_string()))?;

    let tree = parser
        .parse(source, None)
        .ok_or(AnalyzerError::ParseFailed)?;
    let bytes = source.as_bytes();
    let mut findings = Vec::new();

    walk_node(
        tree.root_node(),
        bytes,
        file_label,
        kind,
        cfg,
        &mut findings,
    );

    // Deduplicate identical (rule_id, line) hits if nested AST nodes matched the same line.
    findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.rule_id.cmp(&b.rule_id)));
    findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.line == b.line);
    Ok(findings)
}

fn walk_node(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    kind: ScriptKind,
    cfg: &AnalyzerConfig,
    findings: &mut Vec<StaticFinding>,
) {
    match node.kind() {
        "pipeline" => check_pipeline(node, source, file, findings),
        "command" => check_command(node, source, file, kind, findings),
        "redirected_statement" => check_redirected_statement(node, source, file, kind, findings),
        "variable_assignment" => check_variable_assignment(node, source, file, kind, cfg, findings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_node(child, source, file, kind, cfg, findings);
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

fn line_of(node: Node<'_>) -> usize {
    node.start_position().row + 1
}

fn snippet_of(node: Node<'_>, source: &[u8]) -> String {
    let raw = node_text(node, source).trim();
    let single_line = raw.replace('\n', " ");
    if single_line.len() > 160 {
        format!("{}...", &single_line[..157])
    } else {
        single_line
    }
}

fn command_name_and_args<'a>(node: Node<'_>, source: &'a [u8]) -> (String, Vec<&'a str>) {
    let mut cmd_name = String::new();
    let mut args = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                cmd_name = node_text(child, source).trim().to_string();
            }
            "word" | "string" | "raw_string" | "concatenation" | "simple_expansion"
            | "expansion" => {
                args.push(node_text(child, source).trim());
            }
            _ => {}
        }
    }
    (cmd_name, args)
}

fn is_shell_binary(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    matches!(base, "sh" | "bash" | "zsh" | "dash" | "ksh")
}

fn check_pipeline(node: Node<'_>, source: &[u8], file: &str, findings: &mut Vec<StaticFinding>) {
    let mut commands: Vec<String> = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command" {
            let (name, _) = command_name_and_args(child, source);
            commands.push(name);
        } else if child.kind() == "redirected_statement" {
            let mut inner = child.walk();
            for sub in child.children(&mut inner) {
                if sub.kind() == "command" {
                    let (name, _) = command_name_and_args(sub, source);
                    commands.push(name);
                }
            }
        }
    }

    let has_shell = commands.iter().any(|c| is_shell_binary(c));
    if !has_shell {
        return;
    }

    if commands
        .iter()
        .any(|c| c.rsplit('/').next().unwrap_or(c) == "curl")
    {
        findings.push(StaticFinding {
            rule_id: "pkgbuild_curl_pipe_sh".to_string(),
            file: file.to_string(),
            line: line_of(node),
            severity: Severity::Critical,
            snippet: snippet_of(node, source),
            message: "Remote script downloaded via curl and piped directly to a shell".to_string(),
        });
    }

    if commands
        .iter()
        .any(|c| c.rsplit('/').next().unwrap_or(c) == "wget")
    {
        findings.push(StaticFinding {
            rule_id: "pkgbuild_wget_pipe_sh".to_string(),
            file: file.to_string(),
            line: line_of(node),
            severity: Severity::Critical,
            snippet: snippet_of(node, source),
            message: "Remote script downloaded via wget and piped directly to a shell".to_string(),
        });
    }
}

fn check_command(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    kind: ScriptKind,
    findings: &mut Vec<StaticFinding>,
) {
    let (name, args) = command_name_and_args(node, source);
    let base = name.rsplit('/').next().unwrap_or(&name);

    if base == "eval" {
        findings.push(StaticFinding {
            rule_id: "pkgbuild_eval".to_string(),
            file: file.to_string(),
            line: line_of(node),
            severity: Severity::High,
            snippet: snippet_of(node, source),
            message: "Dynamic execution via 'eval' can conceal malicious payloads".to_string(),
        });
    }

    if base == "base64"
        && args
            .iter()
            .any(|a| *a == "-d" || *a == "--decode" || *a == "-D" || a.starts_with("-d"))
    {
        findings.push(StaticFinding {
            rule_id: "pkgbuild_base64_decode".to_string(),
            file: file.to_string(),
            line: line_of(node),
            severity: Severity::High,
            snippet: snippet_of(node, source),
            message: "Base64 decoding inside build/install script may hide obfuscated commands"
                .to_string(),
        });
    }

    if kind == ScriptKind::InstallScript {
        if base == "systemctl" && args.contains(&"enable") {
            findings.push(StaticFinding {
                rule_id: "install_systemctl_enable".to_string(),
                file: file.to_string(),
                line: line_of(node),
                severity: Severity::Medium,
                snippet: snippet_of(node, source),
                message: "Install script enables systemd unit automatically via 'systemctl enable'"
                    .to_string(),
            });
        }

        if matches!(
            base,
            "curl" | "wget" | "nc" | "ncat" | "socat" | "ssh" | "scp" | "rsync" | "ftp" | "telnet"
        ) {
            findings.push(StaticFinding {
                rule_id: "install_network_command".to_string(),
                file: file.to_string(),
                line: line_of(node),
                severity: Severity::High,
                snippet: snippet_of(node, source),
                message: format!(
                    "Network utility '{base}' invoked inside .install script (runs as root)"
                ),
            });
        }
    }

    if is_shell_binary(base) || matches!(base, "eval" | "source" | ".") {
        let joined = args.join(" ");
        if joined.contains("curl ") || joined.contains("$(curl") || joined.contains("<(curl") {
            findings.push(StaticFinding {
                rule_id: "pkgbuild_curl_pipe_sh".to_string(),
                file: file.to_string(),
                line: line_of(node),
                severity: Severity::Critical,
                snippet: snippet_of(node, source),
                message: "Remote script downloaded via curl and executed in shell/subshell"
                    .to_string(),
            });
        }
        if joined.contains("wget ") || joined.contains("$(wget") || joined.contains("<(wget") {
            findings.push(StaticFinding {
                rule_id: "pkgbuild_wget_pipe_sh".to_string(),
                file: file.to_string(),
                line: line_of(node),
                severity: Severity::Critical,
                snippet: snippet_of(node, source),
                message: "Remote script downloaded via wget and executed in shell/subshell"
                    .to_string(),
            });
        }
    }

    if kind == ScriptKind::Pkgbuild
        && matches!(
            base,
            "cp" | "mv"
                | "install"
                | "tee"
                | "mkdir"
                | "rm"
                | "chmod"
                | "chown"
                | "ln"
                | "touch"
                | "truncate"
                | "curl"
                | "wget"
        )
    {
        // Flag writes targeting system/user paths outside $pkgdir / $srcdir across all arguments.
        let mut target_candidates = args.iter().copied();
        let suspicious = if matches!(base, "cp" | "mv" | "install" | "ln") {
            // For multi-path commands (source -> destination), the destination is the last non-flag argument.
            args.iter()
                .rev()
                .copied()
                .find(|a| !a.starts_with('-'))
                .filter(|t| is_suspicious_external_path(t))
        } else {
            target_candidates.find(|a| !a.starts_with('-') && is_suspicious_external_path(a))
        };
        if let Some(target) = suspicious {
            findings.push(StaticFinding {
                rule_id: "pkgbuild_write_outside_pkgdir".to_string(),
                file: file.to_string(),
                line: line_of(node),
                severity: Severity::Critical,
                snippet: snippet_of(node, source),
                message: format!(
                    "Command '{base}' writes or modifies path outside $pkgdir/$srcdir: {target}"
                ),
            });
        }
    }
}

fn check_redirected_statement(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    kind: ScriptKind,
    findings: &mut Vec<StaticFinding>,
) {
    if kind != ScriptKind::Pkgbuild {
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "file_redirect" {
            let text = node_text(child, source);
            let is_output = text.starts_with('>') || text.contains(">>");
            if !is_output {
                continue;
            }
            let target = text.trim_start_matches(['>', ' ', '&', '1', '2']).trim();
            if is_suspicious_external_path(target) {
                findings.push(StaticFinding {
                    rule_id: "pkgbuild_write_outside_pkgdir".to_string(),
                    file: file.to_string(),
                    line: line_of(child),
                    severity: Severity::Critical,
                    snippet: snippet_of(node, source),
                    message: format!("Output redirection targets path outside $pkgdir: {target}"),
                });
            }
        }
    }
}

fn is_suspicious_external_path(raw: &str) -> bool {
    let unquoted = raw.trim_matches(['"', '\'']);
    if unquoted.contains("$pkgdir")
        || unquoted.contains("${pkgdir}")
        || unquoted.contains("$srcdir")
        || unquoted.contains("${srcdir}")
        || unquoted == "/dev/null"
        || unquoted.starts_with("/dev/std")
    {
        return false;
    }
    let prefixes = [
        "/etc/", "/usr/", "/var/", "/opt/", "/bin/", "/sbin/", "/lib/", "/root/", "/home/", "~/",
        "$HOME/", "${HOME}/",
    ];
    prefixes.iter().any(|p| unquoted.starts_with(p))
}

fn check_variable_assignment(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    kind: ScriptKind,
    cfg: &AnalyzerConfig,
    findings: &mut Vec<StaticFinding>,
) {
    if kind != ScriptKind::Pkgbuild {
        return;
    }

    let mut var_name = String::new();
    let mut value_node = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_name" {
            var_name = node_text(child, source).to_string();
        } else if child.kind() != "=" {
            value_node = Some(child);
        }
    }

    let Some(val_node) = value_node else {
        return;
    };
    let val_text = node_text(val_node, source);

    if is_checksum_var(&var_name) && contains_skip_token(val_text) {
        findings.push(StaticFinding {
            rule_id: "pkgbuild_skip_checksum".to_string(),
            file: file.to_string(),
            line: line_of(node),
            severity: Severity::Medium,
            snippet: snippet_of(node, source),
            message: format!("Checksum verification disabled via 'SKIP' in {var_name}"),
        });
    }

    if is_source_var(&var_name) {
        for url in extract_urls(val_text) {
            if let Some(host) = extract_url_host(&url)
                && !is_domain_allowed(&host, &cfg.allowed_domains)
            {
                findings.push(StaticFinding {
                    rule_id: "pkgbuild_untrusted_source_domain".to_string(),
                    file: file.to_string(),
                    line: line_of(node),
                    severity: Severity::Medium,
                    snippet: snippet_of(node, source),
                    message: format!("Source URL host '{host}' is outside trusted allowlist"),
                });
            }
        }
    }
}

pub(crate) fn is_checksum_var(name: &str) -> bool {
    let base = name.split('_').next().unwrap_or(name);
    matches!(
        base,
        "sha256sums" | "sha512sums" | "md5sums" | "b2sums" | "sha1sums" | "sha384sums"
    )
}

pub(crate) fn is_source_var(name: &str) -> bool {
    name == "source" || name.starts_with("source_")
}

pub(crate) fn contains_skip_token(val: &str) -> bool {
    val.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '\'' | '"'))
        .any(|tok| tok == "SKIP")
}

pub(crate) fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for raw_tok in text.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '\'' | '"')) {
        let tok = raw_tok
            .split("::")
            .last()
            .unwrap_or(raw_tok)
            .trim_start_matches("git+");
        if tok.starts_with("https://") || tok.starts_with("http://") {
            urls.push(tok.to_string());
        }
    }
    urls
}

pub(crate) fn extract_url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_port = rest.split(['/', '?', '#']).next()?;
    let host = if host_port.starts_with('[') {
        host_port.split(']').next()?.trim_start_matches('[')
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

pub(crate) fn is_domain_allowed(host: &str, allowlist: &HashSet<String>) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    allowlist
        .iter()
        .any(|allowed| host == allowed || host.ends_with(&format!(".{allowed}")))
}
