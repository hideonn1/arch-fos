use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, TracePoint};
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_sock_diag::SockDiagMessage;
use netlink_packet_sock_diag::constants::{
    AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, TCP_ESTABLISHED, TCP_SYN_SENT,
};
use netlink_packet_sock_diag::inet::{ExtensionFlags, InetRequest, SocketId, StateFlags};
use netlink_sys::{Socket, protocols::NETLINK_SOCK_DIAG};
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Compiled eBPF ELF object built from `bpf/arch_fos_net.bpf.c`.
static EBPF_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/arch_fos_net.bpf.o"));

/// Mirrors `struct flow_event` in `bpf/arch_fos_net.bpf.c`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawBpfFlowEvent {
    pub pid: u32,
    pub uid: u32,
    pub family: u16,
    pub protocol: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub comm: [u8; 16],
}

/// Normalized flow observation prior to 1-minute bucket aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFlow {
    pub ts_ms: i64,
    pub pid: Option<i64>,
    pub uid: Option<i64>,
    pub comm: String,
    pub exe_path: Option<String>,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
    pub protocol: String,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub packets: i64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowBucketKey {
    bucket_ts: i64,
    pid: Option<i64>,
    uid: Option<i64>,
    comm: String,
    exe_path: Option<String>,
    src_ip: String,
    dst_ip: String,
    dst_port: i64,
    protocol: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct FlowBucketTotals {
    latest_ts: i64,
    bytes_tx: i64,
    bytes_rx: i64,
    packets: i64,
}

/// Aggregated 1-minute flow record ready for SQLite `flows_1m`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedFlow1m {
    pub bucket_ts: i64,
    pub ts: i64,
    pub pid: Option<i64>,
    pub uid: Option<i64>,
    pub comm: String,
    pub exe_path: Option<String>,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
    pub protocol: String,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub packets: i64,
}

/// Active capture mode detected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Ebpf,
    DegradedSockDiag,
}

impl CaptureMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ebpf => "ebpf",
            Self::DegradedSockDiag => "degraded_sock_diag",
        }
    }
}

/// Handle managing the background eBPF ring-buffer reader when eBPF is supported.
pub struct EbpfFlowReceiver {
    pub mode: CaptureMode,
    rx: Option<mpsc::Receiver<ObservedFlow>>,
    _task: Option<tokio::task::JoinHandle<()>>,
}

impl EbpfFlowReceiver {
    /// Detects kernel/BTF/privilege support for eBPF (`aya`) and falls back to `sock_diag` if unavailable.
    pub fn start_or_fallback() -> Self {
        if !Path::new("/sys/kernel/btf/vmlinux").exists() {
            warn!(
                "BTF /sys/kernel/btf/vmlinux not found; running flows in degraded sock_diag+/proc mode"
            );
            return Self {
                mode: CaptureMode::DegradedSockDiag,
                rx: None,
                _task: None,
            };
        }

        match try_attach_ebpf() {
            Ok((rx, handle)) => {
                info!("eBPF flow collector attached via aya (tracepoint inet_sock_set_state)");
                Self {
                    mode: CaptureMode::Ebpf,
                    rx: Some(rx),
                    _task: Some(handle),
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "eBPF unavailable (requires CAP_BPF/CAP_PERFMON); falling back to degraded sock_diag+/proc mode"
                );
                Self {
                    mode: CaptureMode::DegradedSockDiag,
                    rx: None,
                    _task: None,
                }
            }
        }
    }

    /// Drains any buffered eBPF flow observations or polls `sock_diag` in degraded mode.
    pub async fn collect_pending(&mut self) -> Vec<ObservedFlow> {
        let mut out = Vec::new();
        if let Some(ref mut rx) = self.rx {
            while let Ok(flow) = rx.try_recv() {
                out.push(flow);
            }
        }
        // In degraded mode (or to supplement UDP/established flows), also poll sock_diag when needed.
        if self.mode == CaptureMode::DegradedSockDiag
            && let Ok(list) = tokio::task::spawn_blocking(poll_sock_diag_flows).await
            && let Ok(flows) = list
        {
            out.extend(flows);
        }
        out
    }
}

fn try_attach_ebpf()
-> Result<(mpsc::Receiver<ObservedFlow>, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let mut ebpf = Ebpf::load(EBPF_BYTES)?;

    let tp: &mut TracePoint = ebpf
        .program_mut("handle_inet_sock_set_state")
        .ok_or("missing handle_inet_sock_set_state program")?
        .try_into()?;
    tp.load()?;
    tp.attach("sock", "inet_sock_set_state")?;

    // Best-effort attach for UDP cgroup hook if root cgroup v2 is accessible.
    if let Ok(cgroup_file) = std::fs::File::open("/sys/fs/cgroup")
        && let Some(prog) = ebpf.program_mut("handle_udp_sendmsg4")
        && let Ok(cg) = <&mut CgroupSockAddr>::try_from(prog)
        && cg.load().is_ok()
    {
        let _ = cg.attach(cgroup_file, CgroupAttachMode::Single);
    }

    let mut ring_buf = RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .ok_or("missing FLOW_EVENTS map")?,
    )?;
    let (tx, rx) = mpsc::channel(4096);

    let handle = tokio::spawn(async move {
        // Keep `ebpf` alive inside the task so links stay attached.
        let _ebpf_guard = ebpf;
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            ticker.tick().await;
            while let Some(item) = ring_buf.next() {
                if let Some(flow) = parse_raw_bpf_flow(&item, current_unix_ms())
                    && tx.try_send(flow).is_err()
                {
                    break;
                }
            }
            if tx.is_closed() {
                break;
            }
        }
    });

    Ok((rx, handle))
}

/// Parses a `RawBpfFlowEvent` ring-buffer byte slice safely.
#[must_use]
pub fn parse_raw_bpf_flow(bytes: &[u8], now_ms: i64) -> Option<ObservedFlow> {
    if bytes.len() < std::mem::size_of::<RawBpfFlowEvent>() {
        return None;
    }
    // SAFETY: RawBpfFlowEvent is #[repr(C)] POD with only integer/byte fields; unaligned read avoids UB.
    let ev: RawBpfFlowEvent = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
    if ev.dport == 0 {
        return None;
    }

    let (src_ip, dst_ip) = match u32::from(ev.family) {
        x if x == u32::from(AF_INET) => {
            let s = Ipv4Addr::new(ev.saddr[0], ev.saddr[1], ev.saddr[2], ev.saddr[3]);
            let d = Ipv4Addr::new(ev.daddr[0], ev.daddr[1], ev.daddr[2], ev.daddr[3]);
            (s.to_string(), d.to_string())
        }
        _ => {
            let s = Ipv6Addr::from(ev.saddr);
            let d = Ipv6Addr::from(ev.daddr);
            (s.to_string(), d.to_string())
        }
    };

    let comm_end = ev
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ev.comm.len());
    let comm = String::from_utf8_lossy(&ev.comm[..comm_end]).into_owned();
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", ev.pid))
        .ok()
        .map(|p| p.display().to_string());

    let protocol = match ev.protocol {
        17 => "udp",
        _ => "tcp",
    }
    .to_string();

    Some(ObservedFlow {
        ts_ms: now_ms,
        pid: Some(i64::from(ev.pid)),
        uid: Some(i64::from(ev.uid)),
        comm: if comm.is_empty() {
            format!("pid-{}", ev.pid)
        } else {
            comm
        },
        exe_path,
        src_ip,
        dst_ip,
        dst_port: i64::from(ev.dport),
        protocol,
        bytes_tx: 64,
        bytes_rx: 0,
        packets: 1,
    })
}

/// Degraded-mode collector polling active outbound TCP/UDP sockets via `NETLINK_SOCK_DIAG` + `/proc`.
pub fn poll_sock_diag_flows() -> Result<Vec<ObservedFlow>, std::io::Error> {
    let mut entries = Vec::new();
    let flags = StateFlags::from_bits_retain((1 << TCP_ESTABLISHED) | (1 << TCP_SYN_SENT));
    entries.extend(query_diag_sockets(
        AF_INET,
        IPPROTO_TCP,
        "tcp",
        flags.clone(),
    )?);
    entries.extend(query_diag_sockets(AF_INET6, IPPROTO_TCP, "tcp", flags)?);
    entries.extend(query_diag_sockets(
        AF_INET,
        IPPROTO_UDP,
        "udp",
        StateFlags::all(),
    )?);

    let inode_proc = map_inodes_to_proc();
    let now_ms = current_unix_ms();
    let mut flows = Vec::new();

    for e in entries {
        if e.dst_port == 0 || e.dst_ip.is_unspecified() {
            continue;
        }
        let Some(proc_meta) = inode_proc.get(&e.inode) else {
            continue;
        };
        flows.push(ObservedFlow {
            ts_ms: now_ms,
            pid: Some(proc_meta.pid),
            uid: proc_meta.uid,
            comm: proc_meta.comm.clone(),
            exe_path: proc_meta.exe_path.clone(),
            src_ip: e.src_ip.to_string(),
            dst_ip: e.dst_ip.to_string(),
            dst_port: i64::from(e.dst_port),
            protocol: e.protocol.to_string(),
            bytes_tx: 0,
            bytes_rx: 0,
            packets: 1,
        });
    }

    Ok(flows)
}

struct RawDiagFlow {
    protocol: &'static str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    inode: u32,
}

fn query_diag_sockets(
    family: u8,
    protocol: u8,
    label: &'static str,
    states: StateFlags,
) -> Result<Vec<RawDiagFlow>, std::io::Error> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&netlink_sys::SocketAddr::new(0, 0))?;

    let unspec = match family {
        AF_INET => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        _ => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let req = SockDiagMessage::InetRequest(InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::empty(),
        states,
        socket_id: SocketId {
            source_port: 0,
            destination_port: 0,
            source_address: unspec,
            destination_address: unspec,
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

    let mut recv_buf = vec![0u8; 64 * 1024];
    let mut out = Vec::new();

    'outer: loop {
        let len = socket.recv(&mut &mut recv_buf[..], 0)?;
        let mut offset = 0;
        while offset < len {
            let Ok(pkt) = NetlinkMessage::<SockDiagMessage>::deserialize(&recv_buf[offset..len])
            else {
                break 'outer;
            };
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'outer,
                NetlinkPayload::Error(err) => {
                    if let Some(code) = err.code {
                        return Err(std::io::Error::from_raw_os_error(-code.get()));
                    }
                    break 'outer;
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                    let h = resp.header;
                    if h.socket_id.destination_port != 0 {
                        out.push(RawDiagFlow {
                            protocol: label,
                            src_ip: h.socket_id.source_address,
                            dst_ip: h.socket_id.destination_address,
                            dst_port: h.socket_id.destination_port,
                            inode: h.inode,
                        });
                    }
                }
                _ => {}
            }
            let msg_len = pkt.header.length as usize;
            if msg_len == 0 {
                break 'outer;
            }
            offset += msg_len;
        }
    }

    Ok(out)
}

#[derive(Clone)]
struct ProcMeta {
    pid: i64,
    uid: Option<i64>,
    comm: String,
    exe_path: Option<String>,
}

fn map_inodes_to_proc() -> HashMap<u32, ProcMeta> {
    let mut map = HashMap::new();
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i64>().ok())
        else {
            continue;
        };
        let proc_dir = entry.path();
        let Ok(fds) = std::fs::read_dir(proc_dir.join("fd")) else {
            continue;
        };

        let mut inodes = Vec::new();
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path())
                && let Some(s) = link.to_str()
                && let Some(num) = s.strip_prefix("socket:[").and_then(|v| v.strip_suffix(']'))
                && let Ok(inode) = num.parse::<u32>()
            {
                inodes.push(inode);
            }
        }
        if inodes.is_empty() {
            continue;
        }

        let comm = std::fs::read_to_string(proc_dir.join("comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("pid-{pid}"));
        let exe_path = std::fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|p| p.display().to_string());
        let uid = std::fs::read_to_string(proc_dir.join("status"))
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("Uid:")
                        .and_then(|rest| rest.split_whitespace().next())
                        .and_then(|u| u.parse::<i64>().ok())
                })
            });

        let meta = ProcMeta {
            pid,
            uid,
            comm,
            exe_path,
        };
        for inode in inodes {
            map.insert(inode, meta.clone());
        }
    }

    map
}

/// Aggregates observed flows into 1-minute buckets (`flows_1m` schema) without storing packets.
#[must_use]
pub fn aggregate_flows_into_1m(flows: &[ObservedFlow]) -> Vec<AggregatedFlow1m> {
    let mut map: HashMap<FlowBucketKey, FlowBucketTotals> = HashMap::new();

    for f in flows {
        let bucket_ts = (f.ts_ms / 60_000) * 60_000;
        let key = FlowBucketKey {
            bucket_ts,
            pid: f.pid,
            uid: f.uid,
            comm: f.comm.clone(),
            exe_path: f.exe_path.clone(),
            src_ip: f.src_ip.clone(),
            dst_ip: f.dst_ip.clone(),
            dst_port: f.dst_port,
            protocol: f.protocol.clone(),
        };
        let entry = map.entry(key).or_default();
        entry.latest_ts = entry.latest_ts.max(f.ts_ms);
        entry.bytes_tx += f.bytes_tx;
        entry.bytes_rx += f.bytes_rx;
        entry.packets += f.packets;
    }

    map.into_iter()
        .map(|(k, v)| AggregatedFlow1m {
            bucket_ts: k.bucket_ts,
            ts: v.latest_ts,
            pid: k.pid,
            uid: k.uid,
            comm: k.comm,
            exe_path: k.exe_path,
            src_ip: k.src_ip,
            dst_ip: k.dst_ip,
            dst_port: k.dst_port,
            protocol: k.protocol,
            bytes_tx: v.bytes_tx,
            bytes_rx: v.bytes_rx,
            packets: v.packets,
        })
        .collect()
}

/// Persists 1-minute aggregated flows to SQLite `flows_1m`.
pub async fn persist_aggregated_flows(
    pool: &SqlitePool,
    flows: &[AggregatedFlow1m],
) -> Result<(), sqlx::Error> {
    if flows.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for f in flows {
        let entity_id = f
            .pid
            .map_or_else(|| f.comm.clone(), |pid| format!("{}:{pid}", f.comm));
        sqlx::query(
            r#"
            INSERT INTO flows_1m (
                bucket_ts, ts, pid, uid, comm, exe_path, src_ip, dst_ip, dst_port,
                protocol, bytes_tx, bytes_rx, packets, entity_type, entity_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'process', ?)
            "#,
        )
        .bind(f.bucket_ts)
        .bind(f.ts)
        .bind(f.pid)
        .bind(f.uid)
        .bind(&f.comm)
        .bind(&f.exe_path)
        .bind(&f.src_ip)
        .bind(&f.dst_ip)
        .bind(f.dst_port)
        .bind(&f.protocol)
        .bind(f.bytes_tx)
        .bind(f.bytes_rx)
        .bind(f.packets)
        .bind(entity_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
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
    fn aggregates_multiple_samples_into_single_minute_bucket() {
        let base = 1_700_000_040_000_i64; // minute aligned? (base / 60000) * 60000
        let flows = vec![
            ObservedFlow {
                ts_ms: base + 100,
                pid: Some(42),
                uid: Some(1000),
                comm: "curl".to_string(),
                exe_path: Some("/usr/bin/curl".to_string()),
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                dst_port: 443,
                protocol: "tcp".to_string(),
                bytes_tx: 500,
                bytes_rx: 1000,
                packets: 3,
            },
            ObservedFlow {
                ts_ms: base + 500,
                pid: Some(42),
                uid: Some(1000),
                comm: "curl".to_string(),
                exe_path: Some("/usr/bin/curl".to_string()),
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                dst_port: 443,
                protocol: "tcp".to_string(),
                bytes_tx: 250,
                bytes_rx: 500,
                packets: 2,
            },
        ];

        let agg = aggregate_flows_into_1m(&flows);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].bytes_tx, 750);
        assert_eq!(agg[0].bytes_rx, 1500);
        assert_eq!(agg[0].packets, 5);
    }

    #[test]
    fn parses_raw_bpf_flow_event_safely() {
        let mut ev = RawBpfFlowEvent {
            pid: 1337,
            uid: 1000,
            family: u16::from(AF_INET),
            protocol: 6,
            sport: 54321,
            dport: 443,
            saddr: [0; 16],
            daddr: [0; 16],
            comm: [0; 16],
        };
        ev.saddr[..4].copy_from_slice(&[192, 168, 1, 10]);
        ev.daddr[..4].copy_from_slice(&[93, 184, 216, 34]);
        ev.comm[..4].copy_from_slice(b"curl");

        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                (&raw const ev).cast::<u8>(),
                std::mem::size_of::<RawBpfFlowEvent>(),
            )
        };
        let parsed = parse_raw_bpf_flow(bytes, 9000).unwrap();
        assert_eq!(parsed.pid, Some(1337));
        assert_eq!(parsed.comm, "curl");
        assert_eq!(parsed.dst_ip, "93.184.216.34");
        assert_eq!(parsed.dst_port, 443);
    }
}
