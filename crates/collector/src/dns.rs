use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::Severity;
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::db::{NewFinding, upsert_finding_respecting_suppression};

/// Parsed DNS query/response metadata attributed to a process (US-17).
#[derive(Debug, Clone, PartialEq)]
pub struct DnsQueryRecord {
    pub ts: i64,
    pub pid: Option<i64>,
    pub uid: Option<i64>,
    pub comm: String,
    pub exe_path: Option<String>,
    pub package_name: Option<String>,
    pub qname: String,
    pub qtype: String,
    /// DNS response code (`0` = NOERROR, `3` = NXDOMAIN).
    pub rcode: i64,
    pub entropy: f64,
}

/// Computes Shannon entropy (bits per character) of a domain label or query string.
#[must_use]
pub fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = input.as_bytes();
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Parses a standard UDP DNS packet payload (RFC 1035) into `(qname, qtype, rcode)`.
#[must_use]
pub fn parse_dns_wire_packet(pkt: &[u8]) -> Option<(String, String, i64)> {
    if pkt.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rcode = i64::from(flags & 0x000f);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();
    while pos < pkt.len() {
        let len = usize::from(pkt[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        // Reject compression pointers in question section or truncated labels
        if (len & 0xc0) != 0 || pos + len > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
    }

    if labels.is_empty() || pos + 4 > pkt.len() {
        return None;
    }
    let qtype_code = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let qtype = match qtype_code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
    .to_string();

    Some((labels.join("."), qtype, rcode))
}

/// Extracts the registrable base domain (last two labels) and leftmost subdomain portion.
#[must_use]
pub fn split_base_domain(qname: &str) -> (String, String) {
    let trimmed = qname.trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() <= 2 {
        return (trimmed.clone(), String::new());
    }
    let base = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    let sub = parts[..parts.len() - 2].join(".");
    (base, sub)
}

/// Evaluates DGA & DNS exfiltration heuristics across recent DNS queries (US-17).
#[must_use]
pub fn evaluate_dns_heuristics(queries: &[DnsQueryRecord], now_ms: i64) -> Vec<NewFinding> {
    let mut findings = Vec::new();
    let mut proc_stats: HashMap<&str, (usize, usize)> = HashMap::new();
    let mut subdomains_by_base: HashMap<String, (HashSet<String>, String)> = HashMap::new();

    for q in queries {
        let (base_domain, sub) = split_base_domain(&q.qname);
        let label_for_entropy = if sub.is_empty() {
            base_domain.as_str()
        } else {
            sub.as_str()
        };
        let entropy = if q.entropy > 0.0 {
            q.entropy
        } else {
            shannon_entropy(label_for_entropy)
        };

        // 1. High entropy subdomain (DGA / encoded exfil)
        if label_for_entropy.len() >= 12 && entropy >= 3.6 {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "dns_high_entropy".to_string(),
                severity: Severity::High,
                entity_type: "domain".to_string(),
                entity_id: q.qname.clone(),
                title: format!("Consulta DNS con alta entropía: {}", q.qname),
                summary: format!(
                    "Proceso {} consultó '{}' (entropía {:.2}, posible DGA o exfiltración).",
                    q.comm, q.qname, entropy
                ),
                evidence: json!({
                    "qname": q.qname,
                    "entropy": entropy,
                    "comm": q.comm,
                    "pid": q.pid,
                    "package_name": q.package_name,
                }),
            });
        }

        // 2. Excessive domain length (>= 55 chars)
        if q.qname.len() >= 55 {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "dns_excessive_length".to_string(),
                severity: Severity::Medium,
                entity_type: "domain".to_string(),
                entity_id: q.qname.clone(),
                title: format!("Nombre DNS excesivamente largo ({} chars)", q.qname.len()),
                summary: format!(
                    "Proceso {} consultó '{}' ({} bytes).",
                    q.comm,
                    q.qname,
                    q.qname.len()
                ),
                evidence: json!({
                    "qname": q.qname,
                    "length": q.qname.len(),
                    "comm": q.comm,
                    "pid": q.pid,
                }),
            });
        }

        // Track NXDOMAIN rate per process
        let stat = proc_stats.entry(q.comm.as_str()).or_default();
        stat.0 += 1;
        if q.rcode == 3 {
            stat.1 += 1;
        }

        // Track unique subdomains per base domain
        if !sub.is_empty() {
            let entry = subdomains_by_base
                .entry(base_domain)
                .or_insert_with(|| (HashSet::new(), q.comm.clone()));
            entry.0.insert(sub);
        }
    }

    // 3. High NXDOMAIN rate per process (>= 30% with >= 10 queries)
    for (comm, (total, nxdomain)) in proc_stats {
        if total >= 10 && (nxdomain as f64 / total as f64) >= 0.30 {
            let rate = (nxdomain as f64 / total as f64) * 100.0;
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "dns_high_nxdomain_rate".to_string(),
                severity: Severity::High,
                entity_type: "process".to_string(),
                entity_id: comm.to_string(),
                title: format!("Alta tasa de NXDOMAIN en {comm} ({rate:.0}%)"),
                summary: format!(
                    "{comm} tuvo {nxdomain} respuestas NXDOMAIN de {total} consultas ({rate:.1}%)."
                ),
                evidence: json!({
                    "comm": comm,
                    "total_queries": total,
                    "nxdomain_count": nxdomain,
                    "nxdomain_rate_pct": rate,
                }),
            });
        }
    }

    // 4. Unique subdomains volume per base domain (>= 25 unique subdomains)
    for (base, (subs, sample_comm)) in subdomains_by_base {
        if subs.len() >= 25 {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "dns_subdomain_explosion".to_string(),
                severity: Severity::High,
                entity_type: "domain".to_string(),
                entity_id: base.clone(),
                title: format!(
                    "Explosión de subdominios únicos bajo {base} ({})",
                    subs.len()
                ),
                summary: format!(
                    "Se observaron {} subdominios únicos bajo {} (proceso ejemplo: {}).",
                    subs.len(),
                    base,
                    sample_comm
                ),
                evidence: json!({
                    "base_domain": base,
                    "unique_subdomains": subs.len(),
                    "sample_comm": sample_comm,
                }),
            });
        }
    }

    findings
}

#[derive(sqlx::FromRow)]
struct DnsQueryRow {
    ts: i64,
    pid: Option<i64>,
    uid: Option<i64>,
    comm: String,
    exe_path: Option<String>,
    package_name: Option<String>,
    qname: String,
    qtype: String,
    rcode: i64,
    entropy: f64,
}

/// Evaluates DNS heuristics on recent queries stored in `dns_queries` (last 15 minutes).
pub async fn run_dns_analysis_once(pool: &SqlitePool, now_ms: i64) -> Result<usize, sqlx::Error> {
    let window_start = now_ms.saturating_sub(15 * 60 * 1000);
    let rows: Vec<DnsQueryRow> = sqlx::query_as(
        r#"
        SELECT ts, pid, uid, comm, exe_path, package_name, qname, qtype, rcode, entropy
        FROM dns_queries
        WHERE ts >= ?
        ORDER BY id DESC
        LIMIT 5000
        "#,
    )
    .bind(window_start)
    .fetch_all(pool)
    .await?;

    let records: Vec<DnsQueryRecord> = rows
        .into_iter()
        .map(|r| DnsQueryRecord {
            ts: r.ts,
            pid: r.pid,
            uid: r.uid,
            comm: r.comm,
            exe_path: r.exe_path,
            package_name: r.package_name,
            qname: r.qname,
            qtype: r.qtype,
            rcode: r.rcode,
            entropy: r.entropy,
        })
        .collect();

    if records.is_empty() {
        return Ok(0);
    }

    let findings = evaluate_dns_heuristics(&records, now_ms);
    let mut created = 0usize;
    for f in &findings {
        if upsert_finding_respecting_suppression(pool, f, now_ms)
            .await
            .unwrap_or(false)
        {
            created += 1;
        }
    }
    Ok(created)
}

/// Starts a passive `AF_PACKET` sniffer for UDP/53 DNS queries when `CAP_NET_RAW` is available.
/// Degrades gracefully if unprivileged.
pub fn spawn_dns_capture(pool: SqlitePool) -> Option<tokio::task::JoinHandle<()>> {
    use std::os::fd::FromRawFd;

    let eth_p_ip = u16::to_be(0x0800);
    // SAFETY: Standard POSIX socket creation; descriptor wrapped immediately in OwnedFd if valid.
    let raw_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(eth_p_ip)) };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "AF_PACKET DNS capture unavailable (requires CAP_NET_RAW); skipping live DNS sniffing");
        return None;
    }

    // SAFETY: raw_fd >= 0 was just returned by socket().
    let owned_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String, i64, f64, i64)>(512);

    std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        let fd = owned_fd.as_raw_fd();
        let mut buf = [0u8; 2048];
        loop {
            // SAFETY: buf is valid mutable slice of length 2048.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                break;
            }
            let frame = &buf[..n as usize];
            if let Some(udp_payload) = extract_udp_53_payload(frame)
                && let Some((qname, qtype, rcode)) = parse_dns_wire_packet(udp_payload)
            {
                let (_, sub) = split_base_domain(&qname);
                let entropy = shannon_entropy(if sub.is_empty() { &qname } else { &sub });
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
                    .unwrap_or(0);
                if tx
                    .blocking_send((qname, qtype, rcode, entropy, ts))
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    info!("passive AF_PACKET DNS capture active on UDP/53");
    Some(tokio::spawn(async move {
        while let Some((qname, qtype, rcode, entropy, ts)) = rx.recv().await {
            let _ = sqlx::query(
                "INSERT INTO dns_queries (ts, comm, qname, qtype, rcode, entropy) VALUES (?, 'net-dns', ?, ?, ?, ?)",
            )
            .bind(ts)
            .bind(qname)
            .bind(qtype)
            .bind(rcode)
            .bind(entropy)
            .execute(&pool)
            .await;
        }
    }))
}

fn extract_udp_53_payload(eth_frame: &[u8]) -> Option<&[u8]> {
    if eth_frame.len() < 14 + 20 + 8 {
        return None;
    }
    let ethertype = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    let ip = &eth_frame[14..];
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 || ip.len() < ihl + 8 || ip[9] != 17 {
        return None;
    }
    let udp = &ip[ihl..];
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    if sport != 53 && dport != 53 {
        return None;
    }
    Some(&udp[8..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_wire_packet_correctly() {
        // Minimal DNS query for "example.com" A record (rcode 3 NXDOMAIN in response flags)
        let pkt: &[u8] = &[
            0x12, 0x34, // Transaction ID
            0x81, 0x83, // Flags: response + NXDOMAIN (rcode=3)
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // QNAME
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];
        let (qname, qtype, rcode) = parse_dns_wire_packet(pkt).unwrap();
        assert_eq!(qname, "example.com");
        assert_eq!(qtype, "A");
        assert_eq!(rcode, 3);
    }

    #[test]
    fn detects_dga_entropy_length_nxdomain_and_subdomain_explosion() {
        let mut queries = Vec::new();
        for i in 0..26 {
            let sub = format!("x9k2m8p4q7z{i:02}w3v6n1c5");
            let qname = format!("{sub}.exfil-tunnel.example");
            queries.push(DnsQueryRecord {
                ts: 1000 + i,
                pid: Some(777),
                uid: Some(1000),
                comm: "beacon-proc".to_string(),
                exe_path: Some("/tmp/beacon".to_string()),
                package_name: None,
                qname,
                qtype: "TXT".to_string(),
                rcode: if i < 10 { 3 } else { 0 },
                entropy: 0.0,
            });
        }
        // Long query >= 55 chars
        queries.push(DnsQueryRecord {
            ts: 2000,
            pid: Some(777),
            uid: Some(1000),
            comm: "beacon-proc".to_string(),
            exe_path: None,
            package_name: None,
            qname: "aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbcccccc.exfil-tunnel.example"
                .to_string(),
            qtype: "A".to_string(),
            rcode: 0,
            entropy: 0.0,
        });

        let findings = evaluate_dns_heuristics(&queries, 5000);
        let rules: HashSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains("dns_high_entropy"));
        assert!(rules.contains("dns_excessive_length"));
        assert!(rules.contains("dns_high_nxdomain_rate"));
        assert!(rules.contains("dns_subdomain_explosion"));
    }
}
