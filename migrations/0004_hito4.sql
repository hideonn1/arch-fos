-- Arch Forward Observations System - Milestone 4 Schema (US-08, 10, 29)

CREATE TABLE IF NOT EXISTS persistence_baseline (
    category      TEXT NOT NULL,
    path          TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    package_name  TEXT NOT NULL,
    mode          INTEGER NOT NULL DEFAULT 0,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    PRIMARY KEY (category, path)
);

CREATE INDEX IF NOT EXISTS idx_persistence_category ON persistence_baseline (category);

ALTER TABLE rules ADD COLUMN mitre_attack TEXT;
ALTER TABLE rules ADD COLUMN source_file TEXT;
