"""
klcds.core.config — Centralized configuration management
=========================================================
Loads configuration from YAML files with the following priority (highest first):
  1. CLI overrides (--config-override key=value)
  2. /etc/klcds/klcds.yaml   (system-wide)
  3. ./klcds.yaml             (project-local / dev)
  4. Built-in defaults        (this module)

All settings are validated with Pydantic v2 models so typos and bad types are
caught at startup rather than at runtime.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class DatabaseConfig(BaseModel):
    """Database connection settings.  SQLite now, PostgreSQL later."""
    engine: str = Field(
        default="sqlite",
        description="Database engine: 'sqlite' or 'postgresql'",
    )
    sqlite_path: str = Field(
        default="/var/lib/klcds/klcds.db",
        description="Path to the SQLite database file",
    )
    # PostgreSQL fields (unused until migration)
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_user: str = "klcds"
    pg_password: str = ""
    pg_database: str = "klcds"

    @field_validator("engine")
    @classmethod
    def validate_engine(cls, v: str) -> str:
        if v not in ("sqlite", "postgresql"):
            raise ValueError(f"Unsupported DB engine: {v!r}")
        return v


class EBPFConfig(BaseModel):
    """eBPF collector tuning knobs."""
    ring_buffer_pages: int = Field(
        default=64,
        description="Ring-buffer size in pages (each page = 4 KiB)",
    )
    poll_timeout_ms: int = Field(
        default=100,
        description="epoll timeout when draining the ring buffer (ms)",
    )
    enabled_probes: list[str] = Field(
        default=[
            "execve", "openat", "unlink", "rename",
            "connect", "bind",
            "setuid", "setgid", "capset",
            "init_module", "finit_module", "delete_module",
        ],
        description="Syscall probes to attach",
    )


class AuditdConfig(BaseModel):
    """Settings for the auditd / journald log consumer."""
    enabled: bool = True
    journal_filters: list[str] = Field(
        default=["_TRANSPORT=audit", "SYSLOG_IDENTIFIER=sshd"],
        description="systemd-journal match filters",
    )
    ssh_brute_threshold: int = Field(
        default=10,
        description="Failed SSH logins per IP within window → alert",
    )
    ssh_brute_window_sec: int = Field(
        default=60,
        description="Rolling window for SSH brute-force detection (seconds)",
    )


class RuleEngineConfig(BaseModel):
    """YAML rule engine settings."""
    rules_dir: str = Field(
        default="/etc/klcds/rules",
        description="Directory containing YAML detection-rule files",
    )
    custom_rules_dir: str = Field(
        default="/etc/klcds/rules.d",
        description="Drop-in directory for user-added rules",
    )


class RansomwareConfig(BaseModel):
    """Ransomware-shield tuning."""
    canary_dir: str = Field(
        default="/var/lib/klcds/canary",
        description="Directory for canary/decoy files",
    )
    canary_count: int = Field(
        default=10,
        description="Number of canary files to deploy across the filesystem",
    )
    rename_threshold: int = Field(
        default=20,
        description="Renames within window → alert",
    )
    rename_window_sec: int = Field(
        default=10,
        description="Rolling window for mass-rename detection (seconds)",
    )
    entropy_threshold: float = Field(
        default=7.5,
        description="Shannon entropy above this on written data → suspicious",
    )
    files_per_sec_threshold: int = Field(
        default=30,
        description="File modifications/sec above this → alert",
    )
    dirs_per_min_threshold: int = Field(
        default=50,
        description="Distinct directories touched/min above this → alert",
    )


class FIMConfig(BaseModel):
    """File Integrity Monitoring settings."""
    baseline_paths: list[str] = Field(
        default=[
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/etc/crontab",
            "/etc/systemd/system",
            "/etc/sudoers",
        ],
        description="Paths to baseline for integrity monitoring",
    )
    baseline_db: str = Field(
        default="/var/lib/klcds/fim_baseline.json",
        description="Path to the FIM baseline database (JSON)",
    )
    check_interval_sec: int = Field(
        default=300,
        description="Seconds between periodic FIM checks",
    )


class ScannerConfig(BaseModel):
    """ClamAV / YARA / hash-list scanner settings."""
    clamav_socket: str = Field(
        default="/var/run/clamav/clamd.ctl",
        description="Path to ClamAV clamd Unix socket",
    )
    yara_rules_dir: str = Field(
        default="/etc/klcds/yara",
        description="Directory containing .yar / .yara rule files",
    )
    hash_list_path: str = Field(
        default="/etc/klcds/hash_blocklist.txt",
        description="Newline-separated SHA-256 hashes of known-bad binaries",
    )


class ResponseConfig(BaseModel):
    """Automated response / containment settings."""
    safe_mode: bool = Field(
        default=True,
        description="When True, actions are only *logged*, never executed",
    )
    quarantine_dir: str = Field(
        default="/var/lib/klcds/quarantine",
        description="Root-only quarantine directory (chmod 000)",
    )
    nftables_table: str = Field(
        default="klcds_block",
        description="nftables table name used by the response engine",
    )
    nftables_chain: str = Field(
        default="klcds_input",
        description="nftables chain name for IP blocking",
    )
    backup_dir: str = Field(
        default="/var/lib/klcds/backups",
        description="Immutable / append-only evidence backups",
    )


class AlertConfig(BaseModel):
    """Alert delivery channels."""
    desktop_notify: bool = True
    email_enabled: bool = False
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_from: str = ""
    email_to: str = ""
    email_password: str = ""
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


class AllowlistEntry(BaseModel):
    """A single allowlist entry for trusted processes / paths."""
    name: str
    exe_path: Optional[str] = None
    comm: Optional[str] = None
    reason: str = ""


class AllowlistConfig(BaseModel):
    """Processes and paths that must never be killed or quarantined."""
    entries: list[AllowlistEntry] = Field(
        default=[
            AllowlistEntry(
                name="systemd",
                exe_path="/usr/lib/systemd/systemd",
                comm="systemd",
                reason="PID 1 — init system",
            ),
            AllowlistEntry(
                name="apt",
                exe_path="/usr/bin/apt",
                comm="apt",
                reason="Package manager — modifies many files legitimately",
            ),
            AllowlistEntry(
                name="dpkg",
                exe_path="/usr/bin/dpkg",
                comm="dpkg",
                reason="Package manager backend",
            ),
            AllowlistEntry(
                name="klcds",
                comm="klcds",
                reason="The defense tool itself must never self-destruct",
            ),
        ],
        description="Trusted executables that skip automated response",
    )
    trusted_paths: list[str] = Field(
        default=[
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/libexec",
        ],
        description="Execution from these paths is lower-risk",
    )


class APIConfig(BaseModel):
    """FastAPI server settings."""
    host: str = "127.0.0.1"
    port: int = 8443
    reload: bool = False
    workers: int = 2
    cors_origins: list[str] = Field(default=["http://localhost:3000"])


class DashboardConfig(BaseModel):
    """Dashboard settings."""
    framework: str = Field(
        default="react",
        description="Dashboard framework: 'react' or 'streamlit'",
    )
    theme: str = Field(
        default="cyberpunk",
        description="UI theme preset",
    )


class MLConfig(BaseModel):
    """Machine-learning anomaly detector settings."""
    enabled: bool = True
    model_path: str = Field(
        default="/var/lib/klcds/models/isolation_forest.pkl",
        description="Persisted Isolation Forest model",
    )
    contamination: float = Field(
        default=0.05,
        description="Expected anomaly fraction (Isolation Forest param)",
    )
    retrain_interval_sec: int = Field(
        default=3600,
        description="Seconds between automatic model retraining",
    )
    min_samples: int = Field(
        default=500,
        description="Minimum events before first training run",
    )


# ---------------------------------------------------------------------------
# Root config model
# ---------------------------------------------------------------------------

class KLCDSConfig(BaseModel):
    """Top-level configuration — every sub-section has sane defaults."""
    log_level: str = Field(default="INFO", description="Python log level")
    log_file: str = Field(
        default="/var/log/klcds/klcds.log",
        description="Path to the main log file",
    )
    pid_file: str = Field(
        default="/var/run/klcds/klcds.pid",
        description="PID file for the daemon",
    )
    data_dir: str = Field(
        default="/var/lib/klcds",
        description="Base directory for runtime data",
    )

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    ebpf: EBPFConfig = Field(default_factory=EBPFConfig)
    auditd: AuditdConfig = Field(default_factory=AuditdConfig)
    rules: RuleEngineConfig = Field(default_factory=RuleEngineConfig)
    ransomware: RansomwareConfig = Field(default_factory=RansomwareConfig)
    fim: FIMConfig = Field(default_factory=FIMConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    ml: MLConfig = Field(default_factory=MLConfig)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        up = v.upper()
        if up not in valid:
            raise ValueError(f"Invalid log_level {v!r}; choose from {valid}")
        return up


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_CONFIG_SEARCH_PATHS = [
    Path("./klcds.yaml"),
    Path("/etc/klcds/klcds.yaml"),
]


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base* (mutates base)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(
    explicit_path: Optional[str | Path] = None,
    overrides: Optional[dict[str, Any]] = None,
) -> KLCDSConfig:
    """
    Load and validate configuration.

    Parameters
    ----------
    explicit_path : str | Path, optional
        If given, only this file is read (no search-path fallback).
    overrides : dict, optional
        Key-value overrides applied *after* file loading (e.g. from CLI).

    Returns
    -------
    KLCDSConfig
        Fully validated configuration object.
    """
    raw: dict[str, Any] = {}

    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            with open(p, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            logging.info("Config loaded from %s", p)
        else:
            logging.warning("Explicit config %s not found; using defaults", p)
    else:
        # Environment variable override
        env_path = os.environ.get("KLCDS_CONFIG")
        if env_path:
            _CONFIG_SEARCH_PATHS.insert(0, Path(env_path))

        for candidate in _CONFIG_SEARCH_PATHS:
            if candidate.exists():
                with open(candidate, "r", encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh) or {}
                logging.info("Config loaded from %s", candidate)
                break
        else:
            logging.info("No config file found; using built-in defaults")

    if overrides:
        _deep_merge(raw, overrides)

    return KLCDSConfig(**raw)
