use std::path::PathBuf;

use clap::Parser;

/// Privileged collector daemon for Arch Forward Observations System.
#[derive(Debug, Clone, Parser)]
#[command(name = "arch-fos-collector", version, about)]
pub struct CollectorConfig {
    /// Path to the SQLite database file (collector is the sole writer).
    #[arg(
        long,
        env = "ARCH_FOS_DB_PATH",
        default_value = "/var/lib/arch-fos/arch-fos.db"
    )]
    pub db_path: PathBuf,

    /// Unix socket path for receiving finding/suppression mutations from API/CLI.
    #[arg(
        long,
        env = "ARCH_FOS_COLLECTOR_SOCK",
        default_value = "/run/arch-fos/collector.sock"
    )]
    pub control_socket: PathBuf,

    /// Root directory passed to libalpm.
    #[arg(long, env = "ARCH_FOS_ROOT_DIR", default_value = "/")]
    pub root_dir: String,

    /// Pacman database directory passed to libalpm.
    #[arg(
        long,
        env = "ARCH_FOS_PACMAN_DB_PATH",
        default_value = "/var/lib/pacman"
    )]
    pub pacman_db_path: String,

    /// Interval in seconds between collection snapshots.
    #[arg(long, env = "ARCH_FOS_INVENTORY_INTERVAL_SECS", default_value_t = 300)]
    pub interval_secs: u64,

    /// Days without activity before flagging an enabled active service as unused (US-06).
    #[arg(long, env = "ARCH_FOS_UNUSED_SERVICE_DAYS", default_value_t = 7)]
    pub unused_service_days: u64,

    /// Days to keep raw events before summarizing and pruning (US-30).
    #[arg(long, env = "ARCH_FOS_RETENTION_DAYS", default_value_t = 30)]
    pub retention_days: u64,

    /// Minimum AUR vote count threshold before flagging low-vote packages (US-11).
    #[arg(long, env = "ARCH_FOS_AUR_LOW_VOTES", default_value_t = 5)]
    pub aur_low_votes: i64,

    /// Days since FirstSubmitted considered recent for AUR packages (US-11).
    #[arg(long, env = "ARCH_FOS_AUR_RECENT_DAYS", default_value_t = 30)]
    pub aur_recent_days: i64,

    /// Days flagged OutOfDate considered prolonged for AUR packages (US-11).
    #[arg(long, env = "ARCH_FOS_AUR_OUTDATED_DAYS", default_value_t = 90)]
    pub aur_outdated_days: i64,

    /// Initial baseline learning phase duration in days without anomaly alerts (US-19).
    #[arg(long, env = "ARCH_FOS_BASELINE_LEARNING_DAYS", default_value_t = 14)]
    pub baseline_learning_days: u64,

    /// Coefficient-of-variation upper threshold for C2 beaconing detection (US-19).
    #[arg(long, env = "ARCH_FOS_BEACONING_CV", default_value_t = 0.15)]
    pub beaconing_cv_threshold: f64,

    /// Minimum periodic flow samples before flagging beaconing (US-19).
    #[arg(long, env = "ARCH_FOS_BEACONING_MIN_SAMPLES", default_value_t = 6)]
    pub beaconing_min_samples: usize,

    /// Directory containing Sigma-style YAML detection rules hot-reloaded on change (US-29).
    #[arg(long, env = "ARCH_FOS_RULES_DIR", default_value = "./rules")]
    pub rules_dir: PathBuf,

    /// Run full pacman mtree package integrity check (Qkk) during startup/cycles (US-10).
    #[arg(long, env = "ARCH_FOS_CHECK_INTEGRITY", default_value_t = false)]
    pub check_integrity: bool,

    /// Skip external network feeds (Arch Security Tracker & AUR RPC v5).
    #[arg(long, env = "ARCH_FOS_OFFLINE", default_value_t = false)]
    pub offline: bool,

    /// Run a single collection pass, print summary, and exit.
    #[arg(long, default_value_t = false)]
    pub once: bool,
}
