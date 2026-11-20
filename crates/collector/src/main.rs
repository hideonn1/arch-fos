mod aur;
mod baseline;
mod config;
mod cve;
mod db;
mod dns;
mod flows;
mod integrity;
mod inventory;
mod ipc;
mod listeners;
mod persistence;
mod retention;
mod rules_engine;
mod services;
mod threat_intel;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arch_fos_common::NewEvent;
use clap::Parser;
use tokio::signal;
use tracing::{error, info, warn};

use crate::aur::{AurThresholds, run_aur_reputation_once};
use crate::baseline::{BaselineConfig, run_baseline_analysis_once};
use crate::config::CollectorConfig;
use crate::cve::run_cve_check_once;
use crate::db::open_writer_pool;
use crate::dns::{run_dns_analysis_once, spawn_dns_capture};
use crate::flows::{EbpfFlowReceiver, aggregate_flows_into_1m, persist_aggregated_flows};
use crate::integrity::run_integrity_check_once;
use crate::inventory::run_inventory_once;
use crate::ipc::spawn_control_socket;
use crate::listeners::run_listeners_once;
use crate::persistence::run_persistence_once;
use crate::retention::{record_collector_health, run_retention_and_vacuum};
use crate::rules_engine::{HotRuleStore, sync_and_evaluate_rules};
use crate::services::run_services_once;
use crate::threat_intel::run_threat_intel_once;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = CollectorConfig::parse();
    let pool = open_writer_pool(&cfg.db_path).await?;
    info!(db_path = %cfg.db_path.display(), "collector database ready (WAL mode)");

    let mut flow_receiver = EbpfFlowReceiver::start_or_fallback();
    info!(
        capture_mode = flow_receiver.mode.as_str(),
        "flow capture initialized"
    );
    let _dns_handle = if !cfg.once {
        spawn_dns_capture(pool.clone())
    } else {
        None
    };

    let mut rule_store = HotRuleStore::new(cfg.rules_dir.clone());

    let _ipc_handle = if !cfg.once {
        match spawn_control_socket(pool.clone(), &cfg.control_socket).await {
            Ok(h) => {
                info!(socket = %cfg.control_socket.display(), "collector control socket listening");
                Some(h)
            }
            Err(err) => {
                warn!(error = %err, socket = %cfg.control_socket.display(), "failed to bind collector control socket");
                None
            }
        }
    } else {
        None
    };

    run_collection_cycle(&pool, &cfg, &mut flow_receiver, &mut rule_store, true).await;

    if cfg.once {
        return Ok(());
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(10)));
    ticker.tick().await;
    let mut cycle_count = 1u64;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                cycle_count += 1;
                // Run full mtree integrity verification periodically (every 12 cycles or when enabled)
                let run_integrity = cfg.check_integrity && cycle_count.is_multiple_of(12);
                run_collection_cycle(&pool, &cfg, &mut flow_receiver, &mut rule_store, run_integrity).await;
            }
            _ = shutdown_signal() => {
                info!("shutdown signal received, stopping collector");
                let _ = std::fs::remove_file(&cfg.control_socket);
                break;
            }
        }
    }

    Ok(())
}

async fn run_collection_cycle(
    pool: &sqlx::SqlitePool,
    cfg: &CollectorConfig,
    flow_receiver: &mut EbpfFlowReceiver,
    rule_store: &mut HotRuleStore,
    run_integrity: bool,
) {
    let cycle_start = Instant::now();
    let now_ms = current_unix_ms();
    let mut cycle_events: Vec<NewEvent> = Vec::new();

    match run_inventory_once(pool, &cfg.root_dir, &cfg.pacman_db_path).await {
        Ok(stats) => {
            info!(
                total_packages = stats.total_packages,
                foreign_packages = stats.foreign_packages,
                installed = stats.installed,
                removed = stats.removed,
                upgraded = stats.upgraded,
                elapsed_ms = stats.elapsed_ms,
                "package inventory snapshot completed"
            );
            cycle_events.extend(stats.events);
        }
        Err(err) => error!(error = %err, "package inventory snapshot failed"),
    }

    match run_persistence_once(pool, &cfg.root_dir).await {
        Ok((stats, persist_events)) => {
            info!(
                total_entries = stats.total_entries,
                findings_created = stats.findings_created,
                "persistence scan finished"
            );
            cycle_events.extend(persist_events);
        }
        Err(err) => warn!(error = %err, "persistence scan failed"),
    }

    if run_integrity && cfg.check_integrity {
        match run_integrity_check_once(pool, &cfg.root_dir, &cfg.pacman_db_path).await {
            Ok(istats) => info!(
                packages_checked = istats.packages_checked,
                files_verified = istats.files_verified,
                mismatches_found = istats.mismatches_found,
                "integrity verification completed"
            ),
            Err(err) => warn!(error = %err, "package integrity check failed"),
        }
    }

    match run_listeners_once(pool).await {
        Ok(stats) => info!(
            total_listeners = stats.total_listeners,
            new_listeners = stats.new_listeners,
            netlink_available = stats.netlink_available,
            "listeners snapshot completed"
        ),
        Err(err) => error!(error = %err, "listeners snapshot failed"),
    }

    let raw_flows = flow_receiver.collect_pending().await;
    let agg_flows = aggregate_flows_into_1m(&raw_flows);
    if let Err(err) = persist_aggregated_flows(pool, &agg_flows).await {
        error!(error = %err, "failed to persist flows_1m");
    } else {
        info!(
            mode = flow_receiver.mode.as_str(),
            raw_samples = raw_flows.len(),
            aggregated_buckets = agg_flows.len(),
            "network flow aggregation completed"
        );
    }

    match run_dns_analysis_once(pool, now_ms).await {
        Ok(dns_findings) => {
            if dns_findings > 0 {
                info!(dns_findings, "DNS heuristic findings generated");
            }
        }
        Err(err) => warn!(error = %err, "DNS analysis failed"),
    }

    match run_threat_intel_once(pool, cfg.offline).await {
        Ok(stats) => info!(
            total_indicators = stats.total_indicators,
            critical_matches = stats.critical_matches,
            "threat intelligence check finished"
        ),
        Err(err) => warn!(error = %err, "threat intelligence check failed"),
    }

    let baseline_cfg = BaselineConfig {
        learning_days: cfg.baseline_learning_days,
        beaconing_cv_threshold: cfg.beaconing_cv_threshold,
        beaconing_min_samples: cfg.beaconing_min_samples,
    };
    match run_baseline_analysis_once(pool, &agg_flows, baseline_cfg, now_ms).await {
        Ok(anomalies) => {
            if anomalies > 0 {
                info!(anomalies, "network baseline anomaly findings generated");
            }
        }
        Err(err) => warn!(error = %err, "network baseline analysis failed"),
    }

    match run_services_once(pool, cfg.unused_service_days).await {
        Ok(stats) => info!(
            total_services = stats.total_services,
            unused_findings = stats.unused_findings,
            dbus_available = stats.dbus_available,
            "services snapshot completed"
        ),
        Err(err) => error!(error = %err, "services snapshot failed"),
    }

    match run_cve_check_once(pool, cfg.offline).await {
        Ok(stats) => info!(
            advisories_loaded = stats.advisories_loaded,
            findings_created = stats.findings_created,
            cache_hit_304 = stats.cache_hit_304,
            "CVE check cycle finished"
        ),
        Err(err) => warn!(error = %err, "CVE check failed"),
    }

    let aur_thresholds = AurThresholds {
        low_votes: cfg.aur_low_votes,
        recent_days: cfg.aur_recent_days,
        outdated_days: cfg.aur_outdated_days,
    };
    match run_aur_reputation_once(pool, aur_thresholds, cfg.offline).await {
        Ok(stats) => info!(
            foreign_packages = stats.foreign_packages,
            queried_packages = stats.queried_packages,
            findings_created = stats.findings_created,
            "AUR reputation cycle finished"
        ),
        Err(err) => warn!(error = %err, "AUR reputation check failed"),
    }

    // US-29: Hot-reload YAML Sigma rules and evaluate cycle events
    match sync_and_evaluate_rules(pool, rule_store, &cycle_events).await {
        Ok(rule_findings) => {
            if rule_findings > 0 {
                info!(rule_findings, "Sigma YAML rule findings generated");
            }
        }
        Err(err) => warn!(error = %err, "Sigma YAML rule evaluation failed"),
    }

    match run_retention_and_vacuum(pool, cfg.retention_days, now_ms).await {
        Ok(ret) => {
            if ret.pruned_events > 0 {
                info!(
                    pruned_events = ret.pruned_events,
                    summarized_groups = ret.summarized_groups,
                    "retention job pruned expired events"
                );
            }
        }
        Err(err) => warn!(error = %err, "retention job failed"),
    }

    let latency_ms = i64::try_from(cycle_start.elapsed().as_millis()).unwrap_or(i64::MAX);
    let stale_threshold_ms = i64::try_from(cfg.interval_secs.max(10) * 3 * 1000).unwrap_or(900_000);
    if let Err(err) =
        record_collector_health(pool, &cfg.db_path, latency_ms, stale_threshold_ms).await
    {
        warn!(error = %err, "failed to record collector health");
    }
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
