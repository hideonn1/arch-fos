use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arch_fos_analyzer::{
    AnalyzerConfig, SandboxBackend, SandboxBuildOptions, analyze_file, diff_aur_git_repo,
    sandbox_build_and_scan,
};
use arch_fos_common::{CollectorCommand, CollectorResponse, Severity};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
#[command(
    name = "arch-fos",
    version,
    about = "CLI, sandbox builder, wiki indexer & pacman hook for Arch Forward Observations System"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Statically analyze PKGBUILD and .install files (US-12).
    ScanPkgbuild {
        /// Paths to PKGBUILD or .install files.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Output findings as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Diff two revisions of an AUR git repository (US-13).
    DiffPkgbuild {
        /// Path to the local AUR git repository.
        repo: PathBuf,
        #[arg(long, default_value = "HEAD~1")]
        from: String,
        #[arg(long, default_value = "HEAD")]
        to: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Build a PKGBUILD inside a network-isolated sandbox and scan artifacts (US-15).
    SandboxBuild {
        /// Directory containing the PKGBUILD to build.
        pkgbuild_dir: PathBuf,
        /// Sandbox isolation backend (`bwrap` or `nspawn`).
        #[arg(long, value_enum, default_value_t = CliSandboxBackend::Bwrap)]
        backend: CliSandboxBackend,
        /// Skip initial `makepkg --nobuild` source download step.
        #[arg(long, default_value_t = false)]
        skip_download: bool,
        /// Optional YARA rules file or directory to scan built artifacts.
        #[arg(long)]
        yara_rules: Option<PathBuf>,
        /// Output full report as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Index offline Arch Wiki documentation (HTML/Markdown/text) into SQLite RAG store (US-27).
    IndexWiki {
        /// Directory containing offline Arch Wiki files (e.g. /usr/share/doc/arch-wiki/html/en).
        docs_dir: PathBuf,
        /// Path to the writable Arch FOS SQLite database.
        #[arg(
            long,
            env = "ARCH_FOS_DB_PATH",
            default_value = "/var/lib/arch-fos/arch-fos.db"
        )]
        db_path: PathBuf,
        /// Generate dense vector embeddings via local Ollama `/api/embed`.
        #[arg(long, default_value_t = false)]
        embed: bool,
        /// Local Ollama URL for embeddings.
        #[arg(
            long,
            env = "ARCH_FOS_OLLAMA_URL",
            default_value = "http://127.0.0.1:11434"
        )]
        ollama_url: String,
        /// Ollama embedding model name.
        #[arg(
            long,
            env = "ARCH_FOS_OLLAMA_EMBED_MODEL",
            default_value = "nomic-embed-text"
        )]
        embed_model: String,
        /// Maximum number of document files to index (0 = unlimited).
        #[arg(long, default_value_t = 500)]
        max_files: usize,
    },
    /// ALPM PreTransaction hook entrypoint (US-14).
    Hook {
        /// Action mode when findings meet or exceed --threshold.
        #[arg(long, env = "ARCH_FOS_HOOK_MODE", value_enum, default_value_t = HookMode::Warn)]
        mode: HookMode,
        /// Minimum severity to trigger warning or blocking.
        #[arg(long, env = "ARCH_FOS_HOOK_THRESHOLD", value_enum, default_value_t = CliSeverity::High)]
        threshold: CliSeverity,
        /// Explicit bypass flag (also honors ARCH_FOS_BYPASS=1) recorded in audit events.
        #[arg(long, env = "ARCH_FOS_BYPASS", default_value_t = false)]
        bypass: bool,
        /// Read-only path to the Arch FOS SQLite database.
        #[arg(
            long,
            env = "ARCH_FOS_DB_PATH",
            default_value = "/var/lib/arch-fos/arch-fos.db"
        )]
        db_path: PathBuf,
        /// Optional path to collector Unix socket for recording hook/bypass events.
        #[arg(
            long,
            env = "ARCH_FOS_COLLECTOR_SOCK",
            default_value = "/run/arch-fos/collector.sock"
        )]
        collector_socket: PathBuf,
        /// Optional directory containing `<pkg>/PKGBUILD` staging folders to scan statically.
        #[arg(long, env = "ARCH_FOS_PKGBUILDS_DIR")]
        pkgbuilds_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliSandboxBackend {
    Bwrap,
    Nspawn,
}

impl From<CliSandboxBackend> for SandboxBackend {
    fn from(val: CliSandboxBackend) -> Self {
        match val {
            CliSandboxBackend::Bwrap => Self::Bwrap,
            CliSandboxBackend::Nspawn => Self::SystemdNspawn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HookMode {
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<CliSeverity> for Severity {
    fn from(val: CliSeverity) -> Self {
        match val {
            CliSeverity::Info => Self::Info,
            CliSeverity::Low => Self::Low,
            CliSeverity::Medium => Self::Medium,
            CliSeverity::High => Self::High,
            CliSeverity::Critical => Self::Critical,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("arch-fos error: {err}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Commands::ScanPkgbuild { paths, json } => {
            let cfg = AnalyzerConfig::default();
            let mut all = Vec::new();
            for path in paths {
                all.extend(analyze_file(&path, &cfg)?);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&all)?);
            } else if all.is_empty() {
                println!("No static findings detected.");
            } else {
                for f in &all {
                    println!(
                        "[{:?}] {} ({}:{}) - {}",
                        f.severity, f.rule_id, f.file, f.line, f.message
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::DiffPkgbuild {
            repo,
            from,
            to,
            json,
        } => {
            let diffs = diff_aur_git_repo(&repo, &from, &to)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&diffs)?);
            } else if diffs.is_empty() {
                println!("No tracked PKGBUILD/.install changes between {from} and {to}.");
            } else {
                for d in &diffs {
                    println!(
                        "[{:?}] {} ({}) - {}",
                        d.severity, d.rule_id, d.field, d.message
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::SandboxBuild {
            pkgbuild_dir,
            backend,
            skip_download,
            yara_rules,
            json,
        } => {
            let opts = SandboxBuildOptions {
                backend: backend.into(),
                skip_download,
                yara_rules,
            };
            let report = sandbox_build_and_scan(&pkgbuild_dir, &opts)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Sandbox build ({:?}, network isolated: {}): {}",
                    report.backend,
                    report.network_isolated_during_build,
                    if report.build_succeeded {
                        "OK"
                    } else {
                        "FAILED"
                    }
                );
                for art in &report.artifacts {
                    println!(
                        "  Artifact: {} ({} files, .INSTALL: {}, findings: {})",
                        art.artifact_path,
                        art.files_count,
                        art.install_script_present,
                        art.install_script_findings.len()
                    );
                }
                for scan in &report.scanner_results {
                    println!(
                        "  Scanner {}: {} (findings: {})",
                        scan.tool, scan.status, scan.findings_count
                    );
                }
            }
            if report.build_succeeded {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        Commands::IndexWiki {
            docs_dir,
            db_path,
            embed,
            ollama_url,
            embed_model,
            max_files,
        } => {
            let count = index_arch_wiki_dir(
                &docs_dir,
                &db_path,
                embed,
                &ollama_url,
                &embed_model,
                max_files,
            )
            .await?;
            println!(
                "Indexed {count} Arch Wiki chunk(s) into {}",
                db_path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Hook {
            mode,
            threshold,
            bypass,
            db_path,
            collector_socket,
            pkgbuilds_dir,
        } => {
            let mut targets_raw = String::new();
            io::stdin().read_to_string(&mut targets_raw)?;
            let targets: Vec<String> = targets_raw
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();

            if targets.is_empty() {
                return Ok(ExitCode::SUCCESS);
            }

            if bypass {
                eprintln!(
                    "arch-fos hook: explicit bypass active for targets: {}",
                    targets.join(", ")
                );
                let _ = send_collector_event(
                    &collector_socket,
                    CollectorCommand::RecordHookEvent {
                        event_type: "pacman_hook_bypass".to_string(),
                        severity: Severity::Medium,
                        entity_id: targets.join(","),
                        payload: json!({ "targets": targets, "reason": "explicit_bypass" }),
                    },
                )
                .await;
                return Ok(ExitCode::SUCCESS);
            }

            let threshold_sev: Severity = threshold.into();
            let mut alerts: Vec<(String, Severity, String)> = Vec::new();

            if db_path.exists()
                && let Ok(db_alerts) = query_db_findings_for_targets(&db_path, &targets).await
            {
                alerts.extend(db_alerts);
            }

            if let Some(dir) = pkgbuilds_dir.as_deref() {
                let cfg = AnalyzerConfig::default();
                for pkg in &targets {
                    let pkgbuild_path = dir.join(pkg).join("PKGBUILD");
                    if pkgbuild_path.is_file()
                        && let Ok(findings) = analyze_file(&pkgbuild_path, &cfg)
                    {
                        for f in findings {
                            alerts.push((
                                pkg.clone(),
                                f.severity,
                                format!("{}: {}", f.rule_id, f.message),
                            ));
                        }
                    }
                }
            }

            let triggered: Vec<_> = alerts
                .into_iter()
                .filter(|(_, sev, _)| *sev >= threshold_sev)
                .collect();

            if triggered.is_empty() {
                return Ok(ExitCode::SUCCESS);
            }

            let max_sev = triggered
                .iter()
                .map(|(_, s, _)| *s)
                .max()
                .unwrap_or(Severity::Info);

            eprintln!(
                "arch-fos hook ({:?}): {} finding(s) >= {:?}:",
                mode,
                triggered.len(),
                threshold_sev
            );
            for (pkg, sev, msg) in &triggered {
                eprintln!("  - [{sev:?}] {pkg}: {msg}");
            }

            let event_type = match mode {
                HookMode::Warn => "pacman_hook_warned",
                HookMode::Block => "pacman_hook_blocked",
            };
            let _ = send_collector_event(
                &collector_socket,
                CollectorCommand::RecordHookEvent {
                    event_type: event_type.to_string(),
                    severity: max_sev,
                    entity_id: targets.join(","),
                    payload: json!({
                        "mode": format!("{mode:?}").to_lowercase(),
                        "findings_count": triggered.len(),
                    }),
                },
            )
            .await;

            if mode == HookMode::Block {
                eprintln!(
                    "arch-fos hook: blocking transaction (set ARCH_FOS_BYPASS=1 to override)."
                );
                return Ok(ExitCode::from(1));
            }

            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn index_arch_wiki_dir(
    docs_dir: &Path,
    db_path: &Path,
    embed: bool,
    ollama_url: &str,
    embed_model: &str,
    max_files: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    if !docs_dir.is_dir() {
        return Err(format!("docs directory not found: {}", docs_dir.display()).into());
    }

    let dsn = format!("sqlite://{}", db_path.display());
    let opts = SqliteConnectOptions::from_str(&dsn)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;

    let mut files = Vec::new();
    collect_doc_files(docs_dir, &mut files);
    files.sort();
    if max_files > 0 && files.len() > max_files {
        files.truncate(max_files);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);

    let mut total_chunks = 0usize;
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM wiki_chunks")
        .execute(&mut *tx)
        .await?;

    for file in files {
        let Ok(raw) = std::fs::read_to_string(&file) else {
            continue;
        };
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Arch_Wiki");
        let title = stem.replace('_', " ");
        let url = format!("https://wiki.archlinux.org/title/{stem}");
        let plain = if file.extension().and_then(|e| e.to_str()) == Some("html") {
            strip_html_tags(&raw)
        } else {
            raw
        };

        for (idx, chunk) in split_chunks(&plain, 800).into_iter().enumerate() {
            let emb_blob: Option<Vec<u8>> = if embed {
                fetch_embedding(&client, ollama_url, embed_model, &chunk).await
            } else {
                None
            };
            sqlx::query(
                "INSERT INTO wiki_chunks (title, url, section, content, embedding, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&title)
            .bind(&url)
            .bind(format!("section-{}", idx + 1))
            .bind(&chunk)
            .bind(emb_blob)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;
            total_chunks += 1;
        }
    }

    tx.commit().await?;
    Ok(total_chunks)
}

fn collect_doc_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_doc_files(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && matches!(ext, "html" | "md" | "txt")
        {
            out.push(path);
        }
    }
}

fn strip_html_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len() / 2);
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split_chunks(text: &str, max_chars: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + word.len() + 1 > max_chars {
            chunks.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if cur.len() >= 40 {
        chunks.push(cur);
    }
    chunks
}

async fn fetch_embedding(
    client: &reqwest::Client,
    ollama_url: &str,
    model: &str,
    text: &str,
) -> Option<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct EmbedResp {
        #[serde(default)]
        embeddings: Vec<Vec<f32>>,
    }

    let url = format!("{}/api/embed", ollama_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&json!({ "model": model, "input": text }))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: EmbedResp = resp.json().await.ok()?;
    let vec = parsed.embeddings.into_iter().next()?;
    let mut bytes = Vec::with_capacity(vec.len() * 4);
    for v in vec {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    Some(bytes)
}

async fn query_db_findings_for_targets(
    db_path: &Path,
    targets: &[String],
) -> Result<Vec<(String, Severity, String)>, sqlx::Error> {
    let dsn = format!("sqlite://{}", db_path.display());
    let opts = SqliteConnectOptions::from_str(&dsn)?
        .read_only(true)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await?;

    let mut results = Vec::new();
    for target in targets {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT severity, title FROM findings WHERE entity_type = 'package' AND entity_id = ? AND status IN ('new', 'acknowledged')",
        )
        .bind(target)
        .fetch_all(&pool)
        .await?;
        for (sev_str, title) in rows {
            let sev = Severity::parse(&sev_str).unwrap_or(Severity::Info);
            results.push((target.clone(), sev, title));
        }
    }
    Ok(results)
}

async fn send_collector_event(
    socket_path: &Path,
    cmd: CollectorCommand,
) -> Result<CollectorResponse, Box<dyn std::error::Error>> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let payload = serde_json::to_string(&cmd)?;
    writer.write_all(payload.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut lines = BufReader::new(reader).lines();
    if let Some(line) = lines.next_line().await? {
        return Ok(serde_json::from_str(&line)?);
    }
    Ok(CollectorResponse::Ok { id: None })
}
