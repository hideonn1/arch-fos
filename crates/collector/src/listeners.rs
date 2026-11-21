use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use arch_fos_common::{NewEvent, Severity};
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_sock_diag::SockDiagMessage;
use netlink_packet_sock_diag::constants::{
    AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, TCP_CLOSE, TCP_LISTEN,
};
use netlink_packet_sock_diag::inet::{ExtensionFlags, InetRequest, SocketId, StateFlags};
use netlink_sys::{Socket, protocols::NETLINK_SOCK_DIAG};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::warn;

use crate::db::{NewFinding, insert_events, upsert_finding_respecting_suppression};

const SOURCE_SOCK_DIAG: &str = "collector:sock_diag";

/// Listening socket attributed to process and owning pacman package (US-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerSnapshot {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: i64,
    pub pid: Option<i64>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub package_name: Option<String>,
    pub entity_id: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ListenersRunStats {
    pub total_listeners: usize,
    pub new_listeners: usize,
    pub netlink_available: bool,
}

#[derive(Debug, Clone)]
struct RawSocketEntry {
    protocol: &'static str,
    local_addr: IpAddr,
    local_port: u16,
    inode: u32,
}

/// Queries listening TCP and bound UDP sockets via Linux `NETLINK_SOCK_DIAG`.
pub fn read_sock_diag_listeners(
    exe_to_package: &HashMap<String, String>,
) -> Result<Vec<ListenerSnapshot>, std::io::Error> {
    let mut raw_entries = Vec::new();
    raw_entries.extend(query_inet_diag(
        AF_INET,
        IPPROTO_TCP,
        "tcp",
        StateFlags::LISTEN,
    )?);
    raw_entries.extend(query_inet_diag(
        AF_INET6,
        IPPROTO_TCP,
        "tcp6",
        StateFlags::LISTEN,
    )?);
    raw_entries.extend(query_inet_diag(
        AF_INET,
        IPPROTO_UDP,
        "udp",
        StateFlags::from_bits_retain(1 << TCP_CLOSE),
    )?);
    raw_entries.extend(query_inet_diag(
        AF_INET6,
        IPPROTO_UDP,
        "udp6",
        StateFlags::from_bits_retain(1 << TCP_CLOSE),
    )?);

    let inode_pids = map_socket_inodes_to_pids();
    let mut seen_keys = HashSet::new();
    let mut snapshots = Vec::new();

    for entry in raw_entries {
        if entry.local_port == 0 {
            continue;
        }
        let addr_str = entry.local_addr.to_string();
        let entity_id = format!("{}:{addr_str}:{}", entry.protocol, entry.local_port);
        if !seen_keys.insert(entity_id.clone()) {
            continue;
        }

        let proc_info = if entry.inode > 0 {
            inode_pids.get(&entry.inode).cloned()
        } else {
            None
        };

        let (pid, process_name, exe_path, package_name) = match proc_info {
            Some(info) => {
                let pkg = info
                    .exe_path
                    .as_deref()
                    .and_then(|exe| resolve_package_for_exe(exe, exe_to_package));
                (Some(info.pid), info.comm, info.exe_path, pkg)
            }
            None => (None, None, None, None),
        };

        snapshots.push(ListenerSnapshot {
            protocol: entry.protocol.to_string(),
            local_addr: addr_str,
            local_port: i64::from(entry.local_port),
            pid,
            process_name,
            exe_path,
            package_name,
            entity_id,
        });
    }

    Ok(snapshots)
}

fn query_inet_diag(
    family: u8,
    protocol: u8,
    proto_label: &'static str,
    states: StateFlags,
) -> Result<Vec<RawSocketEntry>, std::io::Error> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&netlink_sys::SocketAddr::new(0, 0))?;

    let req = SockDiagMessage::InetRequest(InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::empty(),
        states,
        socket_id: SocketId {
            source_port: 0,
            destination_port: 0,
            source_address: match family {
                AF_INET => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                _ => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            destination_address: match family {
                AF_INET => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                _ => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            interface_id: 0,
            cookie: [0xff; 8],
        },
    });

    let mut nl_msg = NetlinkMessage::from(req);
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_msg.finalize();

    let mut send_buf = vec![0u8; nl_msg.header.length as usize];
    nl_msg.serialize(&mut send_buf);
    socket.send(&send_buf, 0)?;

    let mut receive_buf = vec![0u8; 64 * 1024];
    let mut entries = Vec::new();

    'outer: loop {
        let len = socket.recv(&mut &mut receive_buf[..], 0)?;
        let mut offset = 0;
        while offset < len {
            let bytes = &receive_buf[offset..len];
            let Ok(rx_packet) = NetlinkMessage::<SockDiagMessage>::deserialize(bytes) else {
                break 'outer;
            };

            match rx_packet.payload {
                NetlinkPayload::Done(_) => break 'outer,
                NetlinkPayload::Error(err) => {
                    if let Some(code) = err.code {
                        return Err(std::io::Error::from_raw_os_error(-code.get()));
                    }
                    break 'outer;
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                    let hdr = resp.header;
                    let keep = if protocol == IPPROTO_TCP {
                        hdr.state == TCP_LISTEN
                    } else {
                        hdr.socket_id.source_port != 0
                    };
                    if keep {
                        entries.push(RawSocketEntry {
                            protocol: proto_label,
                            local_addr: hdr.socket_id.source_address,
                            local_port: hdr.socket_id.source_port,
                            inode: hdr.inode,
                        });
                    }
                }
                _ => {}
            }

            let msg_len = rx_packet.header.length as usize;
            if msg_len == 0 {
                break 'outer;
            }
            offset += msg_len;
        }
    }

    Ok(entries)
}

#[derive(Debug, Clone)]
struct ProcSocketInfo {
    pid: i64,
    comm: Option<String>,
    exe_path: Option<String>,
}

fn map_socket_inodes_to_pids() -> HashMap<u32, ProcSocketInfo> {
    let mut map = HashMap::new();
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<i64>() else {
            continue;
        };

        let proc_dir = entry.path();
        let fd_dir = proc_dir.join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };

        let mut proc_inodes = Vec::new();
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && let Some(target_str) = target.to_str()
                && let Some(inner) = target_str
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                && let Ok(inode) = inner.parse::<u32>()
            {
                proc_inodes.push(inode);
            }
        }

        if proc_inodes.is_empty() {
            continue;
        }

        let comm = std::fs::read_to_string(proc_dir.join("comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let exe_path = std::fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|p| p.display().to_string());

        let info = ProcSocketInfo {
            pid,
            comm,
            exe_path,
        };
        for inode in proc_inodes {
            map.insert(inode, info.clone());
        }
    }

    map
}

/// Resolves an executable path (e.g. `/usr/bin/sshd`) to its owning ALPM package.
#[must_use]
pub fn resolve_package_for_exe(
    exe_path: &str,
    exe_to_package: &HashMap<String, String>,
) -> Option<String> {
    let trimmed = exe_path
        .trim_start_matches('/')
        .trim_end_matches(" (deleted)");
    if let Some(pkg) = exe_to_package.get(trimmed) {
        return Some(pkg.clone());
    }
    if let Ok(canon) = Path::new(exe_path).canonicalize() {
        let canon_trimmed = canon.to_string_lossy();
        let key = canon_trimmed.trim_start_matches('/');
        if let Some(pkg) = exe_to_package.get(key) {
            return Some(pkg.clone());
        }
    }
    None
}

/// Returns true if the address binds all interfaces (`0.0.0.0` or `::`).
#[must_use]
pub fn is_wildcard_addr(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "[::]")
}

/// Computes `new_listener` events and wildcard-exposure findings for unseen listeners.
#[must_use]
pub fn detect_new_listeners(
    known_entity_ids: &HashSet<String>,
    current: &[ListenerSnapshot],
    emit_events: bool,
    now_ms: i64,
) -> (Vec<NewEvent>, Vec<NewFinding>) {
    let mut events = Vec::new();
    let mut findings = Vec::new();

    for l in current {
        if known_entity_ids.contains(&l.entity_id) {
            continue;
        }
        let wildcard = is_wildcard_addr(&l.local_addr);
        let severity = if wildcard {
            Severity::High
        } else if l.local_addr == "127.0.0.1" || l.local_addr == "::1" {
            Severity::Info
        } else {
            Severity::Medium
        };

        if emit_events {
            events.push(NewEvent {
                ts: now_ms,
                event_type: "new_listener".to_string(),
                severity,
                source: SOURCE_SOCK_DIAG.to_string(),
                entity_type: "listener".to_string(),
                entity_id: l.entity_id.clone(),
                payload: json!({
                    "protocol": l.protocol,
                    "local_addr": l.local_addr,
                    "local_port": l.local_port,
                    "pid": l.pid,
                    "process_name": l.process_name,
                    "exe_path": l.exe_path,
                    "package_name": l.package_name,
                    "wildcard": wildcard,
                }),
            });
        }

        if wildcard {
            findings.push(NewFinding {
                ts: now_ms,
                rule_id: "wildcard_listener".to_string(),
                severity: Severity::Medium,
                entity_type: "listener".to_string(),
                entity_id: l.entity_id.clone(),
                title: format!(
                    "Puerto {} ({}) escuchando en todas las interfaces ({})",
                    l.local_port, l.protocol, l.local_addr
                ),
                summary: format!(
                    "Proceso {} (paquete: {}) expone el puerto {} en {}.",
                    l.process_name.as_deref().unwrap_or("desconocido"),
                    l.package_name.as_deref().unwrap_or("sin paquete"),
                    l.local_port,
                    l.local_addr
                ),
                evidence: json!({
                    "protocol": l.protocol,
                    "local_addr": l.local_addr,
                    "local_port": l.local_port,
                    "pid": l.pid,
                    "process_name": l.process_name,
                    "exe_path": l.exe_path,
                    "package_name": l.package_name,
                }),
            });
        }
    }

    (events, findings)
}

type PackageFileCacheKey = (i64, i64, i64, i64);
type PackageFileMap = std::sync::Arc<HashMap<String, String>>;

static PACKAGE_FILE_CACHE: std::sync::OnceLock<
    tokio::sync::RwLock<Option<(PackageFileCacheKey, PackageFileMap)>>,
> = std::sync::OnceLock::new();

fn is_indexable_package_file(path: &str) -> bool {
    if path.ends_with('/') {
        return false;
    }
    if path.starts_with("usr/share/")
        || path.starts_with("usr/include/")
        || path.starts_with("usr/src/")
        || path.ends_with(".pyc")
        || path.ends_with(".h")
        || path.ends_with(".a")
        || path.ends_with(".o")
        || path.ends_with(".rlib")
        || path.ends_with(".html")
        || path.ends_with(".gz")
    {
        return false;
    }
    path.starts_with("etc/")
        || path.starts_with("usr/bin/")
        || path.starts_with("usr/sbin/")
        || path.starts_with("usr/local/")
        || path.starts_with("usr/lib/")
        || path.starts_with("opt/")
        || path.starts_with("var/spool/cron/")
        || path.contains("/bin/")
        || path.contains("/sbin/")
}

/// Builds or returns a cached file-path-to-package lookup map from the stored `packages` table.
/// Avoids deserializing hundreds of thousands of JSON file paths multiple times per minute.
pub async fn load_exe_package_index(pool: &SqlitePool) -> Result<PackageFileMap, sqlx::Error> {
    let key: PackageFileCacheKey = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(install_date), 0), COALESCE(MAX(first_seen_at), 0), COALESCE(MIN(first_seen_at), 0) FROM packages",
    )
    .fetch_one(pool)
    .await?;

    let lock = PACKAGE_FILE_CACHE.get_or_init(|| tokio::sync::RwLock::new(None));
    if key.0 > 0
        && let Some((cached_key, cached_map)) = lock.read().await.as_ref()
        && *cached_key == key
    {
        return Ok(std::sync::Arc::clone(cached_map));
    }

    let rows: Vec<(String, String)> = sqlx::query_as("SELECT name, files FROM packages")
        .fetch_all(pool)
        .await?;
    let mut index = HashMap::new();
    for (pkg_name, files_json) in rows {
        if let Ok(files) = serde_json::from_str::<Vec<String>>(&files_json) {
            for f in files {
                if is_indexable_package_file(&f) {
                    index.entry(f).or_insert_with(|| pkg_name.clone());
                }
            }
        }
    }

    let arc_map = std::sync::Arc::new(index);
    if key.0 > 0 {
        *lock.write().await = Some((key, std::sync::Arc::clone(&arc_map)));
    }
    Ok(arc_map)
}

/// Runs one `sock_diag` listener snapshot, attributing processes/packages and emitting diffs.
pub async fn run_listeners_once(pool: &SqlitePool) -> Result<ListenersRunStats, sqlx::Error> {
    let exe_index = load_exe_package_index(pool).await?;
    let listeners =
        match tokio::task::spawn_blocking(move || read_sock_diag_listeners(&exe_index)).await {
            Ok(Ok(list)) => list,
            Ok(Err(err)) => {
                warn!(error = %err, "netlink sock_diag failed; skipping listeners pass");
                return Ok(ListenersRunStats {
                    netlink_available: false,
                    ..Default::default()
                });
            }
            Err(err) => {
                warn!(error = %err, "listeners task panicked");
                return Ok(ListenersRunStats::default());
            }
        };

    let now_ms = current_unix_ms();
    let known_rows: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT entity_id FROM listeners")
        .fetch_all(pool)
        .await?;
    let known_set: HashSet<String> = known_rows.into_iter().map(|(id,)| id).collect();
    let emit_events = !known_set.is_empty();

    let (events, findings) = detect_new_listeners(&known_set, &listeners, emit_events, now_ms);
    let new_count = listeners
        .iter()
        .filter(|l| !known_set.contains(&l.entity_id))
        .count();

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM listeners")
        .execute(&mut *tx)
        .await?;
    for l in &listeners {
        sqlx::query(
            r#"
            INSERT INTO listeners (
                ts, protocol, local_addr, local_port, pid, process_name, exe_path, package_name, entity_type, entity_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'listener', ?)
            "#,
        )
        .bind(now_ms)
        .bind(&l.protocol)
        .bind(&l.local_addr)
        .bind(l.local_port)
        .bind(l.pid)
        .bind(&l.process_name)
        .bind(&l.exe_path)
        .bind(&l.package_name)
        .bind(&l.entity_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    if let Err(err) = insert_events(pool, &events).await {
        warn!(error = %err, "failed to store new_listener events");
    }
    for finding in &findings {
        let _ = upsert_finding_respecting_suppression(pool, finding, now_ms).await;
    }

    Ok(ListenersRunStats {
        total_listeners: listeners.len(),
        new_listeners: new_count,
        netlink_available: true,
    })
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_listener_assigns_higher_severity_to_wildcard_addrs() {
        let mut known = HashSet::new();
        known.insert("tcp:127.0.0.1:8420".to_string());

        let current = vec![
            ListenerSnapshot {
                protocol: "tcp".to_string(),
                local_addr: "127.0.0.1".to_string(),
                local_port: 8420,
                pid: Some(100),
                process_name: Some("arch-fos-api".to_string()),
                exe_path: Some("/usr/bin/arch-fos-api".to_string()),
                package_name: Some("arch-fos".to_string()),
                entity_id: "tcp:127.0.0.1:8420".to_string(),
            },
            ListenerSnapshot {
                protocol: "tcp".to_string(),
                local_addr: "0.0.0.0".to_string(),
                local_port: 9000,
                pid: Some(200),
                process_name: Some("nc".to_string()),
                exe_path: Some("/usr/bin/nc".to_string()),
                package_name: Some("openbsd-netcat".to_string()),
                entity_id: "tcp:0.0.0.0:9000".to_string(),
            },
            ListenerSnapshot {
                protocol: "tcp".to_string(),
                local_addr: "127.0.0.1".to_string(),
                local_port: 5432,
                pid: Some(300),
                process_name: Some("postgres".to_string()),
                exe_path: Some("/usr/bin/postgres".to_string()),
                package_name: Some("postgresql".to_string()),
                entity_id: "tcp:127.0.0.1:5432".to_string(),
            },
        ];

        let (events, findings) = detect_new_listeners(&known, &current, true, 10_000);
        assert_eq!(events.len(), 2);
        let wildcard_ev = events
            .iter()
            .find(|e| e.entity_id == "tcp:0.0.0.0:9000")
            .unwrap();
        let local_ev = events
            .iter()
            .find(|e| e.entity_id == "tcp:127.0.0.1:5432")
            .unwrap();
        assert!(wildcard_ev.severity > local_ev.severity);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "wildcard_listener");
    }

    #[test]
    fn resolves_exe_to_owning_package() {
        let mut index = HashMap::new();
        index.insert("usr/bin/sshd".to_string(), "openssh".to_string());
        assert_eq!(
            resolve_package_for_exe("/usr/bin/sshd", &index),
            Some("openssh".to_string())
        );
    }
}
