-- Arch Forward Observations System - Initial SQLite Schema (US-02)
-- Designed for WAL mode with collector as sole writer and API as read-only reader.

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    source      TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_entity ON events (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_events_severity_ts ON events (severity, ts);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status      TEXT NOT NULL CHECK (status IN ('new', 'acknowledged', 'ignored', 'resolved')),
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings (ts);
CREATE INDEX IF NOT EXISTS idx_findings_entity ON findings (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity_status ON findings (severity, status);

CREATE TABLE IF NOT EXISTS packages (
    name          TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    repo          TEXT,
    is_foreign    INTEGER NOT NULL CHECK (is_foreign IN (0, 1)),
    install_date  INTEGER,
    reason        TEXT NOT NULL CHECK (reason IN ('explicit', 'dependency')),
    description   TEXT,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    files         TEXT NOT NULL DEFAULT '[]',
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_packages_foreign ON packages (is_foreign, name);
CREATE INDEX IF NOT EXISTS idx_packages_repo ON packages (repo, name);

CREATE TABLE IF NOT EXISTS services (
    unit_name       TEXT PRIMARY KEY,
    active_state    TEXT NOT NULL,
    sub_state       TEXT NOT NULL,
    unit_file_state TEXT NOT NULL,
    cpu_usage_ns    INTEGER NOT NULL DEFAULT 0,
    memory_bytes    INTEGER NOT NULL DEFAULT 0,
    io_read_bytes   INTEGER NOT NULL DEFAULT 0,
    io_write_bytes  INTEGER NOT NULL DEFAULT 0,
    last_seen_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_services_state ON services (active_state, unit_name);

CREATE TABLE IF NOT EXISTS listeners (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    local_addr   TEXT NOT NULL,
    local_port   INTEGER NOT NULL,
    pid          INTEGER,
    process_name TEXT,
    exe_path     TEXT,
    package_name TEXT,
    entity_type  TEXT NOT NULL DEFAULT 'listener',
    entity_id    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_listeners_ts ON listeners (ts);
CREATE INDEX IF NOT EXISTS idx_listeners_entity ON listeners (entity_type, entity_id);

CREATE TABLE IF NOT EXISTS flows_1m (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_ts   INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    pid         INTEGER,
    uid         INTEGER,
    comm        TEXT NOT NULL,
    exe_path    TEXT,
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    bytes_tx    INTEGER NOT NULL DEFAULT 0,
    bytes_rx    INTEGER NOT NULL DEFAULT 0,
    packets     INTEGER NOT NULL DEFAULT 0,
    entity_type TEXT NOT NULL DEFAULT 'process',
    entity_id   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_1m_ts ON flows_1m (ts);
CREATE INDEX IF NOT EXISTS idx_flows_1m_bucket_ts ON flows_1m (bucket_ts);
CREATE INDEX IF NOT EXISTS idx_flows_1m_entity ON flows_1m (entity_type, entity_id);

CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    config      TEXT NOT NULL DEFAULT '{}',
    updated_at  INTEGER NOT NULL
);
