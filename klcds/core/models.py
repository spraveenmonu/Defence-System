"""
klcds.core.models — Event and alert data models
=================================================
These Pydantic models define the canonical shape of every event flowing through
KLCDS.  They are used for:
  • Serialization from eBPF ring-buffer structs (ctypes → dict → model)
  • Database INSERT/SELECT mapping
  • FastAPI request/response schemas
  • CLI pretty-printing

Design note: field names use snake_case and match the SQLite column names
exactly so we can do ``Event(**row)`` on SELECT results.
"""

from __future__ import annotations

import enum
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SyscallType(str, enum.Enum):
    """Kernel syscalls we hook via eBPF tracepoints / kprobes."""
    EXECVE = "execve"
    OPENAT = "openat"
    UNLINK = "unlink"
    RENAME = "rename"
    CONNECT = "connect"
    BIND = "bind"
    SETUID = "setuid"
    SETGID = "setgid"
    CAPSET = "capset"
    INIT_MODULE = "init_module"
    FINIT_MODULE = "finit_module"
    DELETE_MODULE = "delete_module"
    # Pseudo-events from auditd / journald
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    SUDO = "sudo"
    SSH_AUTH = "ssh_auth"
    PAM = "pam"
    USB = "usb"
    # Synthetic / internal
    FIM_CHANGE = "fim_change"
    CANARY_TOUCH = "canary_touch"
    ANOMALY = "anomaly"


class Severity(str, enum.Enum):
    """Alert severity levels — maps directly to response tiers."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """Lifecycle of an incident alert."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ActionType(str, enum.Enum):
    """Response actions the engine can take."""
    LOG = "log"
    ALERT = "alert"
    COLLECT_EVIDENCE = "collect_evidence"
    KILL_PROCESS = "kill_process"
    SUSPEND_PROCESS = "suspend_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    DISABLE_CRON = "disable_cron"
    DISABLE_SYSTEMD_UNIT = "disable_systemd_unit"
    NETWORK_ISOLATE = "network_isolate"
    BACKUP_VERIFY = "backup_verify"
    RESTORE_QUARANTINE = "restore_quarantine"


# ---------------------------------------------------------------------------
# Core event model
# ---------------------------------------------------------------------------

class KernelEvent(BaseModel):
    """
    A single kernel-level event captured by an eBPF probe or log consumer.

    Every field that might be absent for a given syscall type is Optional so
    the same model works for ``execve`` (which has exe_path) and ``connect``
    (which has dst_ip/dst_port but no file_path).
    """
    # Identity & timing
    event_id: str = Field(
        default_factory=lambda: uuid4().hex,
        description="Unique event identifier (UUID hex)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the event",
    )

    # Process context
    syscall: SyscallType
    pid: int
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    comm: str = Field(
        default="",
        description="Task comm (up to 16 chars from the kernel)",
    )
    exe_path: Optional[str] = Field(
        default=None,
        description="Full path of the executable",
    )
    exe_sha256: Optional[str] = Field(
        default=None,
        description="SHA-256 of the executable binary (computed in user space)",
    )
    cmdline: Optional[str] = Field(
        default=None,
        description="Full command line (argv joined)",
    )

    # File context
    file_path: Optional[str] = Field(
        default=None,
        description="Target file path (openat, unlink, rename-src)",
    )
    file_path_dst: Optional[str] = Field(
        default=None,
        description="Destination file path (rename only)",
    )

    # Network context
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = Field(
        default=None,
        description="'tcp', 'udp', or 'raw'",
    )

    # Module context (init_module / delete_module)
    module_name: Optional[str] = None

    # Privilege context (setuid / capset)
    target_uid: Optional[int] = None
    target_gid: Optional[int] = None
    capabilities: Optional[str] = None

    # Return value from the syscall
    return_code: Optional[int] = None

    # Extra metadata
    source: str = Field(
        default="ebpf",
        description="Event source: 'ebpf', 'auditd', 'journald', 'fim', 'internal'",
    )
    raw: Optional[str] = Field(
        default=None,
        description="Raw log line or BPF struct dump (for forensics)",
    )

    @field_validator("exe_sha256")
    @classmethod
    def validate_sha256(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) != 64:
            raise ValueError("exe_sha256 must be a 64-char hex string")
        return v

    def dict_for_db(self) -> dict[str, Any]:
        """Return a dict suitable for SQLite INSERT (datetimes → ISO strings)."""
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["syscall"] = self.syscall.value
        return d


# ---------------------------------------------------------------------------
# Alert / incident model
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """An alert raised by the detection / rule engine."""
    alert_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    severity: Severity
    rule_id: str = Field(description="ID of the detection rule that fired")
    rule_name: str = Field(default="", description="Human-readable rule name")
    attack_type: str = Field(
        default="unknown",
        description="Category: ransomware, brute_force, malware, privilege_escalation, …",
    )
    description: str = ""

    # Linked evidence
    event_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs that triggered this alert",
    )
    process_tree: Optional[str] = Field(
        default=None,
        description="JSON-serialized process-tree snapshot",
    )
    affected_files: list[str] = Field(default_factory=list)
    affected_ips: list[str] = Field(default_factory=list)

    # Response
    actions_taken: list[str] = Field(
        default_factory=list,
        description="ActionType values executed (or 'would_do:' in safe mode)",
    )
    status: AlertStatus = AlertStatus.NEW

    # Risk scoring
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Composite risk score (0–100)",
    )

    def dict_for_db(self) -> dict[str, Any]:
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        # Lists → comma-separated for SQLite (JSON in PostgreSQL)
        d["event_ids"] = ",".join(d["event_ids"])
        d["affected_files"] = ",".join(d["affected_files"])
        d["affected_ips"] = ",".join(d["affected_ips"])
        d["actions_taken"] = ",".join(d["actions_taken"])
        return d


# ---------------------------------------------------------------------------
# Response action log
# ---------------------------------------------------------------------------

class ResponseAction(BaseModel):
    """Record of an automated (or would-be) response action."""
    action_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    alert_id: str
    action_type: ActionType
    target: str = Field(description="PID, file path, IP, or unit name")
    safe_mode: bool = Field(
        default=True,
        description="True = action was only logged, not executed",
    )
    success: bool = True
    detail: str = ""
    reversible: bool = True
    reverse_command: Optional[str] = Field(
        default=None,
        description="Shell command to undo the action",
    )


# ---------------------------------------------------------------------------
# System posture snapshot
# ---------------------------------------------------------------------------

class PostureSnapshot(BaseModel):
    """Point-in-time system security posture (score 0–100)."""
    snapshot_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    score: float = Field(ge=0.0, le=100.0)

    # Component scores (each 0–100)
    firewall_score: float = 0.0
    open_ports_score: float = 0.0
    suid_score: float = 0.0
    world_writable_score: float = 0.0
    ssh_config_score: float = 0.0
    updates_score: float = 0.0
    encryption_score: float = 0.0
    services_score: float = 0.0

    # Raw inventory counts
    os_version: str = ""
    kernel_version: str = ""
    open_port_count: int = 0
    root_service_count: int = 0
    suid_binary_count: int = 0
    world_writable_count: int = 0
    pending_updates: int = 0
    firewall_active: bool = False
    disk_encrypted: bool = False


# ---------------------------------------------------------------------------
# Helper: compute SHA-256 of a file
# ---------------------------------------------------------------------------

def sha256_of_file(path: str | Path, block_size: int = 65536) -> Optional[str]:
    """
    Return the hex SHA-256 digest of the file at *path*, or None if the file
    cannot be read (permission denied, gone, etc.).
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(block_size):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
