-- Arch Forward Observations System - Milestone 2 Schema (US-06, 07, 09, 11, 23, 30)

CREATE TABLE IF NOT EXISTS suppressions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT 'local-admin',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suppressions_rule_entity
    ON suppressions (rule_id, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_expires
    ON suppressions (expires_at);

CREATE TABLE IF NOT EXISTS finding_audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    note       TEXT NOT NULL DEFAULT '',
    ts         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_audit_finding_ts
    ON finding_audit_log (finding_id, ts);

CREATE TABLE IF NOT EXISTS feed_cache (
    feed_name      TEXT PRIMARY KEY,
    etag           TEXT,
    last_modified  TEXT,
    last_synced_at INTEGER NOT NULL,
    payload        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS aur_cache (
    package_name    TEXT PRIMARY KEY,
    maintainer      TEXT,
    was_orphan      INTEGER NOT NULL DEFAULT 0 CHECK (was_orphan IN (0, 1)),
    num_votes       INTEGER NOT NULL DEFAULT 0,
    popularity      REAL NOT NULL DEFAULT 0.0,
    first_submitted INTEGER,
    last_modified   INTEGER,
    out_of_date     INTEGER,
    version         TEXT NOT NULL,
    fetched_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collector_health (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    last_heartbeat_at       INTEGER NOT NULL,
    cpu_time_ms             INTEGER NOT NULL DEFAULT 0,
    rss_bytes               INTEGER NOT NULL DEFAULT 0,
    db_size_bytes           INTEGER NOT NULL DEFAULT 0,
    last_ingest_latency_ms  INTEGER NOT NULL DEFAULT 0,
    status                  TEXT NOT NULL DEFAULT 'healthy'
);

CREATE TABLE IF NOT EXISTS event_daily_summaries (
    day        TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity   TEXT NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (day, event_type, severity)
);
