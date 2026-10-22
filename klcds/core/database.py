"""
klcds.core.database — SQLite database layer (PostgreSQL-ready)
===============================================================
Schema design principles:
  • Every table uses TEXT primary keys (UUIDs) — works on both SQLite & PG.
  • Timestamps stored as ISO-8601 TEXT (SQLite) / TIMESTAMPTZ (PG).
  • Lists stored as comma-separated TEXT in SQLite, JSONB in PG.
  • Foreign keys enabled on SQLite (``PRAGMA foreign_keys = ON``).
  • Schema versioning via a ``schema_version`` table so we can run ALTER TABLE
    migrations safely.

The module exposes a thin ``Database`` class — not an ORM — so we keep full
control over queries and can swap engines via ``engine`` config.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from klcds.core.config import KLCDSConfig

logger = logging.getLogger("klcds.database")

# Current schema revision — bump this when adding migrations.
SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# SQL statements
# ---------------------------------------------------------------------------

_CREATE_TABLES = """
-- ===================================================================
-- Schema version tracking
-- ===================================================================
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ===================================================================
-- Kernel events captured by eBPF probes and log consumers
-- ===================================================================
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,        -- ISO-8601 UTC
    syscall         TEXT NOT NULL,        -- SyscallType enum value
    pid             INTEGER NOT NULL,
    ppid            INTEGER NOT NULL DEFAULT 0,
    uid             INTEGER NOT NULL DEFAULT 0,
    gid             INTEGER NOT NULL DEFAULT 0,
    comm            TEXT NOT NULL DEFAULT '',
    exe_path        TEXT,
    exe_sha256      TEXT,
    cmdline         TEXT,
    file_path       TEXT,
    file_path_dst   TEXT,
    src_ip          TEXT,
    src_port        INTEGER,
    dst_ip          TEXT,
    dst_port        INTEGER,
    protocol        TEXT,
    module_name     TEXT,
    target_uid      INTEGER,
    target_gid      INTEGER,
    capabilities    TEXT,
    return_code     INTEGER,
    source          TEXT NOT NULL DEFAULT 'ebpf',
    raw             TEXT
);

-- Indexes for the queries we run most often
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_syscall   ON events(syscall);
CREATE INDEX IF NOT EXISTS idx_events_pid       ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_uid       ON events(uid);
CREATE INDEX IF NOT EXISTS idx_events_exe_path  ON events(exe_path);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip    ON events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_source    ON events(source);

-- ===================================================================
-- Alerts / incidents raised by the detection engine
-- ===================================================================
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    severity        TEXT NOT NULL,        -- info / low / medium / high / critical
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL DEFAULT '',
    attack_type     TEXT NOT NULL DEFAULT 'unknown',
    description     TEXT NOT NULL DEFAULT '',
    event_ids       TEXT NOT NULL DEFAULT '',   -- comma-separated (JSONB in PG)
    process_tree    TEXT,                        -- JSON string
    affected_files  TEXT NOT NULL DEFAULT '',   -- comma-separated
    affected_ips    TEXT NOT NULL DEFAULT '',   -- comma-separated
    actions_taken   TEXT NOT NULL DEFAULT '',   -- comma-separated ActionType
    status          TEXT NOT NULL DEFAULT 'new',
    risk_score      REAL NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id   ON alerts(rule_id);

-- ===================================================================
-- Response action log — every action the engine takes (or would take)
-- ===================================================================
CREATE TABLE IF NOT EXISTS response_actions (
    action_id       TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    alert_id        TEXT NOT NULL REFERENCES alerts(alert_id),
    action_type     TEXT NOT NULL,
    target          TEXT NOT NULL,
    safe_mode       INTEGER NOT NULL DEFAULT 1,  -- boolean
    success         INTEGER NOT NULL DEFAULT 1,
    detail          TEXT NOT NULL DEFAULT '',
    reversible      INTEGER NOT NULL DEFAULT 1,
    reverse_command TEXT
);

CREATE INDEX IF NOT EXISTS idx_actions_alert ON response_actions(alert_id);
CREATE INDEX IF NOT EXISTS idx_actions_type  ON response_actions(action_type);

-- ===================================================================
-- System posture snapshots
-- ===================================================================
CREATE TABLE IF NOT EXISTS posture_snapshots (
    snapshot_id         TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    score               REAL NOT NULL,
    firewall_score      REAL NOT NULL DEFAULT 0.0,
    open_ports_score    REAL NOT NULL DEFAULT 0.0,
    suid_score          REAL NOT NULL DEFAULT 0.0,
    world_writable_score REAL NOT NULL DEFAULT 0.0,
    ssh_config_score    REAL NOT NULL DEFAULT 0.0,
    updates_score       REAL NOT NULL DEFAULT 0.0,
    encryption_score    REAL NOT NULL DEFAULT 0.0,
    services_score      REAL NOT NULL DEFAULT 0.0,
    os_version          TEXT NOT NULL DEFAULT '',
    kernel_version      TEXT NOT NULL DEFAULT '',
    open_port_count     INTEGER NOT NULL DEFAULT 0,
    root_service_count  INTEGER NOT NULL DEFAULT 0,
    suid_binary_count   INTEGER NOT NULL DEFAULT 0,
    world_writable_count INTEGER NOT NULL DEFAULT 0,
    pending_updates     INTEGER NOT NULL DEFAULT 0,
    firewall_active     INTEGER NOT NULL DEFAULT 0,
    disk_encrypted      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_posture_ts ON posture_snapshots(timestamp);

-- ===================================================================
-- File-integrity monitoring baselines
-- ===================================================================
CREATE TABLE IF NOT EXISTS fim_baselines (
    file_path       TEXT PRIMARY KEY,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    mode            TEXT NOT NULL DEFAULT '',        -- e.g. '0644'
    owner           TEXT NOT NULL DEFAULT '',
    group_name      TEXT NOT NULL DEFAULT '',        -- 'group' is reserved in PG
    mtime           TEXT NOT NULL DEFAULT '',
    baseline_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ===================================================================
-- Known-bad hash blocklist (loaded from file, cached in DB)
-- ===================================================================
CREATE TABLE IF NOT EXISTS hash_blocklist (
    sha256      TEXT PRIMARY KEY,
    label       TEXT NOT NULL DEFAULT '',
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ===================================================================
-- Process-tree cache (rebuilt periodically or on demand)
-- ===================================================================
CREATE TABLE IF NOT EXISTS process_tree (
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    uid         INTEGER NOT NULL DEFAULT 0,
    comm        TEXT    NOT NULL DEFAULT '',
    exe_path    TEXT,
    cmdline     TEXT,
    start_time  TEXT,
    snapshot_at TEXT NOT NULL,
    PRIMARY KEY (pid, snapshot_at)
);

-- ===================================================================
-- Quarantine ledger — tracks quarantined files for restoration
-- ===================================================================
CREATE TABLE IF NOT EXISTS quarantine_ledger (
    quarantine_id   TEXT PRIMARY KEY,
    original_path   TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    quarantined_at  TEXT NOT NULL,
    alert_id        TEXT REFERENCES alerts(alert_id),
    restored        INTEGER NOT NULL DEFAULT 0,
    restored_at     TEXT
);
"""


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """
    Thin wrapper around sqlite3 for KLCDS.

    Usage::

        db = Database(config)
        db.initialize()
        db.insert_event(event.dict_for_db())
        rows = db.query("SELECT * FROM events WHERE pid = ?", (1234,))
    """

    def __init__(self, config: KLCDSConfig) -> None:
        self._config = config
        self._db_path = config.database.sqlite_path
        self._conn: Optional[sqlite3.Connection] = None

    # -- connection management -----------------------------------------------

    def _ensure_dir(self) -> None:
        try:
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            fallback = Path("./data/klcds.db")
            fallback.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(fallback)

    def connect(self) -> None:
        """Open (or reopen) the database connection."""
        self._ensure_dir()
        try:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=10,
            )
        except sqlite3.OperationalError:
            fallback = Path("./data/klcds.db")
            fallback.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(fallback)
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=10,
            )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        logger.info("Connected to SQLite at %s", self._db_path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        return self._conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager that commits on success, rolls back on error."""
        cur = self.conn.cursor()
        try:
            yield cur
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # -- schema management ---------------------------------------------------

    def initialize(self) -> None:
        """Create all tables and indexes if they don't exist."""
        self.conn.executescript(_CREATE_TABLES)
        # Record schema version
        self.conn.execute(
            "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        self.conn.commit()
        logger.info("Database schema initialized (version %d)", SCHEMA_VERSION)

    def current_schema_version(self) -> int:
        try:
            row = self.conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            return row[0] if row and row[0] else 0
        except sqlite3.OperationalError:
            return 0

    # -- generic helpers -----------------------------------------------------

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, seq: list[tuple[Any, ...]]) -> None:
        self.conn.executemany(sql, seq)
        self.conn.commit()

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """Run a SELECT and return rows as plain dicts."""
        cur = self.conn.execute(sql, params)
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    # -- typed insert helpers ------------------------------------------------

    def insert_event(self, data: dict[str, Any]) -> None:
        """Insert a single KernelEvent (as dict)."""
        cols = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})"
        self.conn.execute(sql, tuple(data.values()))
        self.conn.commit()

    def insert_event_batch(self, batch: list[dict[str, Any]]) -> None:
        """Insert a batch of events efficiently."""
        if not batch:
            return
        cols = ", ".join(batch[0].keys())
        placeholders = ", ".join(["?"] * len(batch[0]))
        sql = f"INSERT OR IGNORE INTO events ({cols}) VALUES ({placeholders})"
        self.conn.executemany(sql, [tuple(d.values()) for d in batch])
        self.conn.commit()

    def insert_alert(self, data: dict[str, Any]) -> None:
        cols = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT OR IGNORE INTO alerts ({cols}) VALUES ({placeholders})"
        self.conn.execute(sql, tuple(data.values()))
        self.conn.commit()

    def insert_response_action(self, data: dict[str, Any]) -> None:
        cols = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT OR IGNORE INTO response_actions ({cols}) VALUES ({placeholders})"
        self.conn.execute(sql, tuple(data.values()))
        self.conn.commit()

    def insert_posture(self, data: dict[str, Any]) -> None:
        cols = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        sql = f"INSERT OR IGNORE INTO posture_snapshots ({cols}) VALUES ({placeholders})"
        self.conn.execute(sql, tuple(data.values()))
        self.conn.commit()

    # -- query helpers -------------------------------------------------------

    def get_recent_events(
        self,
        limit: int = 100,
        syscall: Optional[str] = None,
        pid: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Fetch the most recent events with optional filters."""
        clauses = []
        params: list[Any] = []
        if syscall:
            clauses.append("syscall = ?")
            params.append(syscall)
        if pid is not None:
            clauses.append("pid = ?")
            params.append(pid)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return self.query(sql, tuple(params))

    def get_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return self.query(sql, tuple(params))

    # Alias for API consistency
    get_recent_alerts = get_alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[dict[str, Any]]:
        rows = self.query("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        return rows[0] if rows else None

    def update_alert_status(self, alert_id: str, status: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (status, alert_id),
        )
        self.conn.commit()

    def get_event_count_in_window(
        self,
        syscall: str,
        window_seconds: int,
        pid: Optional[int] = None,
    ) -> int:
        """Count events of a given type within the last *window_seconds*."""
        sql = """
            SELECT COUNT(*) FROM events
            WHERE syscall = ?
              AND timestamp >= datetime('now', ? || ' seconds')
        """
        params: list[Any] = [syscall, f"-{window_seconds}"]
        if pid is not None:
            sql += " AND pid = ?"
            params.append(pid)
        row = self.conn.execute(sql, tuple(params)).fetchone()
        return row[0] if row else 0

    def get_stats(self) -> dict[str, Any]:
        """Quick summary stats for the dashboard."""
        return {
            "total_events": self.conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0],
            "total_alerts": self.conn.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0],
            "critical_alerts": self.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = 'critical'"
            ).fetchone()[0],
            "high_alerts": self.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = 'high'"
            ).fetchone()[0],
            "active_alerts": self.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved', 'false_positive')"
            ).fetchone()[0],
        }
