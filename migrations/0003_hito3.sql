-- Arch Forward Observations System - Milestone 3 Schema (US-16, 17, 18, 19)

CREATE INDEX IF NOT EXISTS idx_flows_1m_comm_ts
    ON flows_1m (comm, ts);

CREATE TABLE IF NOT EXISTS dns_queries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    pid          INTEGER,
    uid          INTEGER,
    comm         TEXT NOT NULL,
    exe_path     TEXT,
    package_name TEXT,
    qname        TEXT NOT NULL,
    qtype        TEXT NOT NULL DEFAULT 'A',
    rcode        INTEGER NOT NULL DEFAULT 0,
    entropy      REAL NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_dns_queries_ts ON dns_queries (ts);
CREATE INDEX IF NOT EXISTS idx_dns_queries_qname ON dns_queries (qname);
CREATE INDEX IF NOT EXISTS idx_dns_queries_comm ON dns_queries (comm, ts);

CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator      TEXT NOT NULL,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url')),
    feed           TEXT NOT NULL,
    threat_label   TEXT NOT NULL,
    first_seen     TEXT,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (indicator, feed)
);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_ind ON threat_indicators (indicator);

CREATE TABLE IF NOT EXISTS process_network_baselines (
    comm              TEXT PRIMARY KEY,
    first_seen_at     INTEGER NOT NULL,
    last_seen_at      INTEGER NOT NULL,
    known_dst_ips     TEXT NOT NULL DEFAULT '[]',
    known_dst_ports   TEXT NOT NULL DEFAULT '[]',
    avg_bytes_per_min REAL NOT NULL DEFAULT 0.0,
    sample_count      INTEGER NOT NULL DEFAULT 0
);
