use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use arch_fos_analyzer::{AnalyzerConfig, analyze_file, diff_aur_git_repo};
use arch_fos_common::{CollectorCommand, CollectorResponse, Severity};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
#[command(
    name = "arch-fos",
    version,
    about = "CLI & pacman hook for Arch Forward Observations System"
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
