"""
tests/test_database.py — Unit tests for the database layer
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from klcds.core.config import KLCDSConfig
from klcds.core.database import Database, SCHEMA_VERSION
from klcds.core.models import KernelEvent, Alert, SyscallType, Severity


@pytest.fixture
def db(tmp_path: Path) -> Generator[Database, None, None]:
    """Create a fresh in-memory-like database for each test."""
    cfg = KLCDSConfig(
        database={"engine": "sqlite", "sqlite_path": str(tmp_path / "test.db")}
    )
    database = Database(cfg)
    database.connect()
    database.initialize()
    yield database
    database.close()


class TestSchemaInit:
    def test_tables_created(self, db: Database) -> None:
        tables = db.query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        names = {t["name"] for t in tables}
        assert "events" in names
        assert "alerts" in names
        assert "response_actions" in names
        assert "posture_snapshots" in names
        assert "fim_baselines" in names
        assert "quarantine_ledger" in names

    def test_schema_version(self, db: Database) -> None:
        ver = db.current_schema_version()
        assert ver == SCHEMA_VERSION

    def test_idempotent_init(self, db: Database) -> None:
        """Calling initialize() twice should not fail."""
        db.initialize()
        db.initialize()
        assert db.current_schema_version() == SCHEMA_VERSION


class TestEventCRUD:
    def test_insert_and_retrieve_event(self, db: Database) -> None:
        evt = KernelEvent(
            syscall=SyscallType.EXECVE,
            pid=9999,
            uid=1000,
            comm="test_bin",
            exe_path="/tmp/test_bin",
        )
        db.insert_event(evt.dict_for_db())
        rows = db.get_recent_events(limit=10)
        assert len(rows) == 1
        assert rows[0]["pid"] == 9999
        assert rows[0]["comm"] == "test_bin"

    def test_batch_insert(self, db: Database) -> None:
        events = [
            KernelEvent(syscall=SyscallType.OPENAT, pid=i, comm=f"proc_{i}")
            .dict_for_db()
            for i in range(50)
        ]
        db.insert_event_batch(events)
        rows = db.get_recent_events(limit=100)
        assert len(rows) == 50

    def test_filter_by_syscall(self, db: Database) -> None:
        for sc in [SyscallType.EXECVE, SyscallType.OPENAT, SyscallType.EXECVE]:
            db.insert_event(KernelEvent(syscall=sc, pid=1).dict_for_db())
        rows = db.get_recent_events(syscall="execve")
        assert len(rows) == 2

    def test_filter_by_pid(self, db: Database) -> None:
        db.insert_event(KernelEvent(syscall=SyscallType.EXECVE, pid=111).dict_for_db())
        db.insert_event(KernelEvent(syscall=SyscallType.EXECVE, pid=222).dict_for_db())
        rows = db.get_recent_events(pid=111)
        assert len(rows) == 1


class TestAlertCRUD:
    def test_insert_and_retrieve_alert(self, db: Database) -> None:
        alert = Alert(
            severity=Severity.HIGH,
            rule_id="ssh_brute_force",
            attack_type="brute_force",
            risk_score=75.0,
        )
        db.insert_alert(alert.dict_for_db())
        rows = db.get_alerts(limit=10)
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "ssh_brute_force"

    def test_filter_alerts_by_severity(self, db: Database) -> None:
        for sev in [Severity.LOW, Severity.HIGH, Severity.CRITICAL]:
            db.insert_alert(
                Alert(severity=sev, rule_id=f"rule_{sev.value}").dict_for_db()
            )
        rows = db.get_alerts(severity="critical")
        assert len(rows) == 1

    def test_update_alert_status(self, db: Database) -> None:
        alert = Alert(severity=Severity.MEDIUM, rule_id="test")
        db.insert_alert(alert.dict_for_db())
        db.update_alert_status(alert.alert_id, "resolved")
        row = db.get_alert_by_id(alert.alert_id)
        assert row is not None
        assert row["status"] == "resolved"


class TestStats:
    def test_stats_empty(self, db: Database) -> None:
        stats = db.get_stats()
        assert stats["total_events"] == 0
        assert stats["total_alerts"] == 0

    def test_stats_after_inserts(self, db: Database) -> None:
        db.insert_event(KernelEvent(syscall=SyscallType.EXECVE, pid=1).dict_for_db())
        db.insert_alert(Alert(severity=Severity.CRITICAL, rule_id="r1").dict_for_db())
        stats = db.get_stats()
        assert stats["total_events"] == 1
        assert stats["total_alerts"] == 1
        assert stats["critical_alerts"] == 1
