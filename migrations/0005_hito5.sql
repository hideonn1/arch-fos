-- Arch Forward Observations System - Milestone 5 Schema (US-26, 27, 28)

CREATE TABLE IF NOT EXISTS llm_explanations (
    finding_hash      TEXT PRIMARY KEY,
    finding_id        INTEGER NOT NULL,
    model             TEXT NOT NULL,
    summary           TEXT NOT NULL,
    risk              TEXT NOT NULL,
    suggested_actions TEXT NOT NULL DEFAULT '[]',
    references_json   TEXT NOT NULL DEFAULT '[]',
    rag_sources       TEXT NOT NULL DEFAULT '[]',
    created_at        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_llm_explanations_finding ON llm_explanations (finding_id, created_at);

CREATE TABLE IF NOT EXISTS suggested_actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    command     TEXT NOT NULL,
    rationale   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by  TEXT,
    decided_at  INTEGER,
    created_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_suggested_actions_finding_cmd
    ON suggested_actions (finding_id, command);
CREATE INDEX IF NOT EXISTS idx_suggested_actions_status
    ON suggested_actions (status, created_at);

CREATE TABLE IF NOT EXISTS wiki_chunks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    url        TEXT NOT NULL,
    section    TEXT NOT NULL DEFAULT '',
    content    TEXT NOT NULL,
    embedding  BLOB,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wiki_chunks_title ON wiki_chunks (title);
