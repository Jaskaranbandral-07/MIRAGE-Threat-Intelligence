-- ============================================================================
--  MIRAGE Database Schema (PRD §6)
-- ============================================================================
--  Table creation order respects foreign-key dependencies:
--    1. sources          (no FK)
--    2. clusters         (no FK)
--    3. sessions         (FK → sources, clusters)
--    4. commands          (FK → sessions)
--    5. technique_signatures (no FK)
--    6. session_techniques  (FK → sessions, technique_signatures, commands)
-- ============================================================================

CREATE TABLE IF NOT EXISTS sources (
    ip_address      TEXT PRIMARY KEY,
    first_seen      DATETIME NOT NULL,
    last_seen       DATETIME NOT NULL,
    asn             TEXT,
    country         TEXT,
    session_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clusters (
    cluster_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label              TEXT,
    first_seen         DATETIME,
    last_seen          DATETIME,
    session_count      INTEGER DEFAULT 0,
    centroid_features  TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip         TEXT NOT NULL,
    protocol          TEXT NOT NULL CHECK (protocol IN ('ssh', 'http')),
    start_time        DATETIME NOT NULL,
    end_time          DATETIME,
    duration_seconds  INTEGER,
    cluster_id        INTEGER,
    FOREIGN KEY (source_ip) REFERENCES sources(ip_address),
    FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS commands (
    command_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          INTEGER NOT NULL,
    sequence_number      INTEGER NOT NULL,
    raw_input            TEXT NOT NULL,
    timestamp            DATETIME NOT NULL,
    time_since_prev_ms   INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS technique_signatures (
    signature_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern              TEXT NOT NULL,
    attack_technique_id  TEXT NOT NULL,
    technique_name       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_techniques (
    session_id          INTEGER NOT NULL,
    signature_id        INTEGER NOT NULL,
    matched_command_id  INTEGER,
    PRIMARY KEY (session_id, signature_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (signature_id) REFERENCES technique_signatures(signature_id),
    FOREIGN KEY (matched_command_id) REFERENCES commands(command_id)
);

-- ── Performance Indexes ────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_cluster_id ON sessions(cluster_id);
CREATE INDEX IF NOT EXISTS idx_commands_session_id ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_session_techniques_session ON session_techniques(session_id);
