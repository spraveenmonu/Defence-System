"""
tests/test_models.py — Unit tests for event and alert data models
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from klcds.core.models import (
    KernelEvent,
    Alert,
    ResponseAction,
    PostureSnapshot,
    SyscallType,
    Severity,
    AlertStatus,
    ActionType,
    sha256_of_file,
)


class TestKernelEvent:
    """Tests for the KernelEvent model."""

    def test_minimal_event(self) -> None:
        evt = KernelEvent(syscall=SyscallType.EXECVE, pid=1234)
        assert evt.pid == 1234
        assert evt.syscall == SyscallType.EXECVE
        assert evt.ppid == 0
        assert evt.source == "ebpf"
        assert len(evt.event_id) == 32  # UUID hex

    def test_full_event(self) -> None:
        evt = KernelEvent(
            syscall=SyscallType.CONNECT,
            pid=5678,
            ppid=1,
            uid=1000,
            comm="curl",
            exe_path="/usr/bin/curl",
            dst_ip="93.184.216.34",
            dst_port=443,
            protocol="tcp",
        )
        assert evt.dst_ip == "93.184.216.34"
        assert evt.protocol == "tcp"

    def test_dict_for_db_serialization(self) -> None:
        evt = KernelEvent(syscall=SyscallType.OPENAT, pid=100)
        d = evt.dict_for_db()
        assert isinstance(d["timestamp"], str)  # ISO string
        assert d["syscall"] == "openat"

    def test_invalid_sha256_rejected(self) -> None:
        with pytest.raises(ValueError, match="64-char hex"):
            KernelEvent(
                syscall=SyscallType.EXECVE,
                pid=1,
                exe_sha256="tooshort",
            )

    def test_valid_sha256_accepted(self) -> None:
        h = "a" * 64
        evt = KernelEvent(syscall=SyscallType.EXECVE, pid=1, exe_sha256=h)
        assert evt.exe_sha256 == h


class TestAlert:
    """Tests for the Alert model."""

    def test_minimal_alert(self) -> None:
        alert = Alert(
            severity=Severity.HIGH,
            rule_id="test_rule",
        )
        assert alert.status == AlertStatus.NEW
        assert alert.risk_score == 0.0

    def test_dict_for_db(self) -> None:
        alert = Alert(
            severity=Severity.CRITICAL,
            rule_id="ransomware_mass_rename",
            event_ids=["aaa", "bbb"],
            affected_files=["/tmp/a.txt"],
            affected_ips=["10.0.0.1"],
            actions_taken=["suspend_process"],
        )
        d = alert.dict_for_db()
        assert d["severity"] == "critical"
        assert d["event_ids"] == "aaa,bbb"
        assert d["affected_files"] == "/tmp/a.txt"

    def test_risk_score_bounds(self) -> None:
        with pytest.raises(ValueError):
            Alert(severity=Severity.LOW, rule_id="x", risk_score=150.0)
        with pytest.raises(ValueError):
            Alert(severity=Severity.LOW, rule_id="x", risk_score=-1.0)


class TestResponseAction:
    """Tests for the ResponseAction model."""

    def test_default_safe_mode(self) -> None:
        action = ResponseAction(
            alert_id="abc",
            action_type=ActionType.KILL_PROCESS,
            target="1234",
        )
        assert action.safe_mode is True
        assert action.reversible is True


class TestPostureSnapshot:
    """Tests for the PostureSnapshot model."""

    def test_score_bounds(self) -> None:
        snap = PostureSnapshot(score=85.0)
        assert snap.score == 85.0

        with pytest.raises(ValueError):
            PostureSnapshot(score=101.0)

    def test_defaults(self) -> None:
        snap = PostureSnapshot(score=50.0)
        assert snap.firewall_active is False
        assert snap.disk_encrypted is False


class TestSHA256Helper:
    """Tests for the sha256_of_file utility."""

    def test_sha256_of_known_content(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello world\n")
        h = sha256_of_file(str(f))
        assert h is not None
        assert len(h) == 64

    def test_sha256_of_missing_file(self) -> None:
        h = sha256_of_file("/nonexistent/file.bin")
        assert h is None

    def test_sha256_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "det.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        h1 = sha256_of_file(str(f))
        h2 = sha256_of_file(str(f))
        assert h1 == h2
