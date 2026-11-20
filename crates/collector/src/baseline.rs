use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use arch_fos_common::Severity;
use serde_json::json;
use sqlx::SqlitePool;

use crate::db::{NewFinding, upsert_finding_respecting_suppression};
use crate::flows::AggregatedFlow1m;

/// 14-day rolling network baseline per process `comm` (US-19).
#[derive(Debug, Clone)]
pub struct ProcessBaseline {
    pub comm: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub known_dst_ips: HashSet<String>,
    pub known_dst_ports: HashSet<i64>,
    pub avg_bytes_per_min: f64,
    pub sample_count: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct BaselineConfig {
    pub learning_days: u64,
    pub beaconing_cv_threshold: f64,
    pub beaconing_min_samples: usize,
}

/// Returns true if `addr` is a non-loopback, non-private public internet IP.
#[must_use]
pub fn is_public_internet_ip(addr: &str) -> bool {
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Evaluates whether a sequence of timestamps (in ms) exhibits periodic beaconing.
/// Returns `Some((mean_interval_ms, cv))` if sample count >= `min_samples` and `CV <= cv_threshold`.
#[must_use]
pub fn detect_beaconing_cv(
    timestamps_ms: &[i64],
    min_samples: usize,
    cv_threshold: f64,
) -> Option<(f64, f64)> {
    if timestamps_ms.len() < min_samples {
        return None;
    }
    let mut sorted = timestamps_ms.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() < min_samples {
        return None;
    }

    let intervals: Vec<f64> = sorted
        .windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|&dt| dt >= 1000.0)
        .collect();
    if intervals.len() + 1 < min_samples {
        return None;
    }

    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals
        .iter()
        .map(|&x| {
            let d = x - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();
    let cv = stddev / mean;

    if cv <= cv_threshold {
        Some((mean, cv))
    } else {
        None
    }
}

/// Evaluates network anomalies against baselines, honoring learning mode (US-19).
#[must_use]
pub fn evaluate_baseline_anomalies(
    baselines: &HashMap<String, ProcessBaseline>,
    recent_flows: &[AggregatedFlow1m],
    history_timestamps: &HashMap<(String, String, i64), Vec<i64>>,
    earliest_system_seen_ms: Option<i64>,
    cfg: BaselineConfig,
    now_ms: i64,
) -> Vec<NewFinding> {
    let learning_window_ms = i64::try_from(cfg.learning_days).unwrap_or(14) * 86_400_000;
    let in_learning_mode = earliest_system_seen_ms
        .is_none_or(|start| now_ms.saturating_sub(start) < learning_window_ms);

    if in_learning_mode {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen_alerts: HashSet<(String, String)> = HashSet::new();

    for flow in recent_flows {
        if !is_public_internet_ip(&flow.dst_ip) {
            continue;
        }

        match baselines.get(&flow.comm) {
            None => {
                if seen_alerts.insert(("net_first_outbound_process".to_string(), flow.comm.clone()))
                {
                    findings.push(NewFinding {
                        ts: now_ms,
                        rule_id: "net_first_outbound_process".to_string(),
                        severity: Severity::Medium,
                        entity_type: "process".to_string(),
                        entity_id: flow.comm.clone(),
                        title: format!("Proceso sin historial previo sale a internet: {}", flow.comm),
                        summary: format!(
                            "{} inició conexión saliente a {}:{} ({}) sin historial en el baseline de 14 días.",
                            flow.comm, flow.dst_ip, flow.dst_port, flow.protocol
                        ),
                        evidence: json!({
                            "comm": flow.comm,
                            "exe_path": flow.exe_path,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "protocol": flow.protocol,
                        }),
                    });
                }
            }
            Some(base) => {
                if !base.known_dst_ports.contains(&flow.dst_port)
                    && seen_alerts.insert((
                        "net_new_destination_port".to_string(),
                        format!("{}:{}", flow.comm, flow.dst_port),
                    ))
                {
                    findings.push(NewFinding {
                        ts: now_ms,
                        rule_id: "net_new_destination_port".to_string(),
                        severity: Severity::Low,
                        entity_type: "process".to_string(),
                        entity_id: flow.comm.clone(),
                        title: format!(
                            "Puerto de destino inusual {} para {}",
                            flow.dst_port, flow.comm
                        ),
                        summary: format!(
                            "{} se conectó al puerto {} ({}) no visto en su baseline.",
                            flow.comm, flow.dst_port, flow.dst_ip
                        ),
                        evidence: json!({
                            "comm": flow.comm,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "known_ports_count": base.known_dst_ports.len(),
                        }),
                    });
                }
            }
        }
    }

    for ((comm, dst_ip, dst_port), timestamps) in history_timestamps {
        if !is_public_internet_ip(dst_ip) {
            continue;
        }
        if let Some((mean_ms, cv)) = detect_beaconing_cv(
            timestamps,
            cfg.beaconing_min_samples,
            cfg.beaconing_cv_threshold,
        ) && seen_alerts.insert((
            "net_beaconing_detected".to_string(),
            format!("{comm}:{dst_ip}:{dst_port}"),
        )) {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "net_beaconing_detected".to_string(),
                severity: Severity::High,
                entity_type: "process".to_string(),
                entity_id: comm.clone(),
                title: format!("Posible beaconing en {comm} hacia {dst_ip}:{dst_port}"),
                summary: format!(
                    "Intervalo periódico detectado cada {:.1}s (CV={:.3}, muestras={}).",
                    mean_ms / 1000.0,
                    cv,
                    timestamps.len()
                ),
                evidence: json!({
                    "comm": comm,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "mean_interval_ms": mean_ms,
                    "coefficient_of_variation": cv,
                    "samples": timestamps.len(),
                }),
            });
        }
    }

    findings
}

/// Updates 14-day process baselines and runs anomaly detection on newly aggregated flows.
pub async fn run_baseline_analysis_once(
    pool: &SqlitePool,
    new_flows: &[AggregatedFlow1m],
    cfg: BaselineConfig,
    now_ms: i64,
) -> Result<usize, sqlx::Error> {
    let rows: Vec<(String, i64, i64, String, String, f64, i64)> = sqlx::query_as(
        "SELECT comm, first_seen_at, last_seen_at, known_dst_ips, known_dst_ports, avg_bytes_per_min, sample_count FROM process_network_baselines",
    )
    .fetch_all(pool)
    .await?;

    let mut baselines = HashMap::new();
    let mut earliest_seen: Option<i64> = None;

    for (comm, first_seen, last_seen, ips_json, ports_json, avg_bytes, samples) in rows {
        earliest_seen = Some(earliest_seen.map_or(first_seen, |e| e.min(first_seen)));
        let known_dst_ips: HashSet<String> = serde_json::from_str::<Vec<String>>(&ips_json)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let known_dst_ports: HashSet<i64> = serde_json::from_str::<Vec<i64>>(&ports_json)
            .unwrap_or_default()
            .into_iter()
            .collect();
        baselines.insert(
            comm.clone(),
            ProcessBaseline {
                comm,
                first_seen_at: first_seen,
                last_seen_at: last_seen,
                known_dst_ips,
                known_dst_ports,
                avg_bytes_per_min: avg_bytes,
                sample_count: samples,
            },
        );
    }

    // Gather last 14 days of flow timestamps for beaconing evaluation.
    let window_14d = now_ms.saturating_sub(14 * 86_400_000);
    let hist_rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT comm, dst_ip, dst_port, bucket_ts FROM flows_1m WHERE ts >= ? ORDER BY bucket_ts ASC LIMIT 20000",
    )
    .bind(window_14d)
    .fetch_all(pool)
    .await?;

    let mut history_ts: HashMap<(String, String, i64), Vec<i64>> = HashMap::new();
    for (comm, dst_ip, dst_port, bucket_ts) in hist_rows {
        history_ts
            .entry((comm, dst_ip, dst_port))
            .or_default()
            .push(bucket_ts);
    }

    let findings = evaluate_baseline_anomalies(
        &baselines,
        new_flows,
        &history_ts,
        earliest_seen,
        cfg,
        now_ms,
    );

    let mut created = 0usize;
    for f in &findings {
        if upsert_finding_respecting_suppression(pool, f, now_ms)
            .await
            .unwrap_or(false)
        {
            created += 1;
        }
    }

    // Update process baselines with newly observed flows (capped sets for bounded JSON size).
    for flow in new_flows {
        let entry = baselines
            .entry(flow.comm.clone())
            .or_insert_with(|| ProcessBaseline {
                comm: flow.comm.clone(),
                first_seen_at: now_ms,
                last_seen_at: now_ms,
                known_dst_ips: HashSet::new(),
                known_dst_ports: HashSet::new(),
                avg_bytes_per_min: 0.0,
                sample_count: 0,
            });
        if entry.known_dst_ips.len() < 512 {
            entry.known_dst_ips.insert(flow.dst_ip.clone());
        }
        if entry.known_dst_ports.len() < 256 {
            entry.known_dst_ports.insert(flow.dst_port);
        }
        let total_bytes = (flow.bytes_tx + flow.bytes_rx) as f64;
        let next_n = (entry.sample_count + 1) as f64;
        entry.avg_bytes_per_min =
            ((entry.avg_bytes_per_min * entry.sample_count as f64) + total_bytes) / next_n;
        entry.sample_count += 1;
        entry.last_seen_at = now_ms;
    }

    let mut tx = pool.begin().await?;
    for base in baselines.values() {
        let ips_vec: Vec<&str> = base.known_dst_ips.iter().map(String::as_str).collect();
        let ports_vec: Vec<i64> = base.known_dst_ports.iter().copied().collect();
        let ips_json = serde_json::to_string(&ips_vec).unwrap_or_else(|_| "[]".to_string());
        let ports_json = serde_json::to_string(&ports_vec).unwrap_or_else(|_| "[]".to_string());

        sqlx::query(
            r#"
            INSERT INTO process_network_baselines (
                comm, first_seen_at, last_seen_at, known_dst_ips, known_dst_ports, avg_bytes_per_min, sample_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(comm) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                known_dst_ips = excluded.known_dst_ips,
                known_dst_ports = excluded.known_dst_ports,
                avg_bytes_per_min = excluded.avg_bytes_per_min,
                sample_count = excluded.sample_count
            "#,
        )
        .bind(&base.comm)
        .bind(base.first_seen_at)
        .bind(base.last_seen_at)
        .bind(ips_json)
        .bind(ports_json)
        .bind(base.avg_bytes_per_min)
        .bind(base.sample_count)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beaconing_detects_regular_intervals_and_ignores_jittery_traffic() {
        let regular: Vec<i64> = (0..8).map(|i| 1_700_000_000_000 + i * 60_000).collect();
        let res = detect_beaconing_cv(&regular, 6, 0.15);
        assert!(res.is_some());
        let (mean, cv) = res.unwrap();
        assert!((mean - 60_000.0).abs() < 1.0);
        assert!(cv < 0.01);

        let jittery = vec![
            1_700_000_000_000,
            1_700_000_010_000,
            1_700_000_300_000,
            1_700_000_305_000,
            1_700_001_000_000,
            1_700_001_020_000,
        ];
        assert!(detect_beaconing_cv(&jittery, 6, 0.15).is_none());
    }

    #[test]
    fn learning_mode_suppresses_anomaly_alerts_then_post_learning_alerts_fire() {
        let now_ms = 1_700_000_000_000_i64;
        let cfg = BaselineConfig {
            learning_days: 14,
            beaconing_cv_threshold: 0.15,
            beaconing_min_samples: 6,
        };

        let flows = vec![
            AggregatedFlow1m {
                bucket_ts: now_ms,
                ts: now_ms,
                pid: Some(10),
                uid: Some(1000),
                comm: "unknown-bin".to_string(),
                exe_path: None,
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "8.8.8.8".to_string(),
                dst_port: 443,
                protocol: "tcp".to_string(),
                bytes_tx: 100,
                bytes_rx: 0,
                packets: 1,
            },
            AggregatedFlow1m {
                bucket_ts: now_ms,
                ts: now_ms,
                pid: Some(11),
                uid: Some(1000),
                comm: "known-app".to_string(),
                exe_path: None,
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                dst_port: 9999, // new port
                protocol: "tcp".to_string(),
                bytes_tx: 100,
                bytes_rx: 0,
                packets: 1,
            },
        ];

        let mut baselines = HashMap::new();
        let mut known_ports = HashSet::new();
        known_ports.insert(443);
        baselines.insert(
            "known-app".to_string(),
            ProcessBaseline {
                comm: "known-app".to_string(),
                first_seen_at: now_ms - 20 * 86_400_000,
                last_seen_at: now_ms - 60_000,
                known_dst_ips: HashSet::new(),
                known_dst_ports: known_ports,
                avg_bytes_per_min: 100.0,
                sample_count: 100,
            },
        );

        let history = HashMap::new();

        // Still inside 14-day learning window -> 0 alerts
        let learning_alerts = evaluate_baseline_anomalies(
            &baselines,
            &flows,
            &history,
            Some(now_ms - 2 * 86_400_000),
            cfg,
            now_ms,
        );
        assert!(learning_alerts.is_empty());

        // Past 14-day learning window -> alerts fire
        let active_alerts = evaluate_baseline_anomalies(
            &baselines,
            &flows,
            &history,
            Some(now_ms - 20 * 86_400_000),
            cfg,
            now_ms,
        );
        let rules: HashSet<&str> = active_alerts.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains("net_first_outbound_process"));
        assert!(rules.contains("net_new_destination_port"));
    }
}
