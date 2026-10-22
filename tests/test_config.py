"""
tests/test_config.py — Unit tests for the configuration system
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from klcds.core.config import KLCDSConfig, load_config, _deep_merge


class TestDefaults:
    """Verify that default config values are sane."""

    def test_default_config_creates_successfully(self) -> None:
        cfg = KLCDSConfig()
        assert cfg.log_level == "INFO"
        assert cfg.database.engine == "sqlite"
        assert cfg.response.safe_mode is True

    def test_safe_mode_default_on(self) -> None:
        """MANDATORY: safe mode must default to ON."""
        cfg = KLCDSConfig()
        assert cfg.response.safe_mode is True

    def test_default_probes(self) -> None:
        cfg = KLCDSConfig()
        assert "execve" in cfg.ebpf.enabled_probes
        assert "connect" in cfg.ebpf.enabled_probes
        assert "rename" in cfg.ebpf.enabled_probes

    def test_allowlist_has_systemd(self) -> None:
        """PID 1 must never be killed."""
        cfg = KLCDSConfig()
        names = [e.name for e in cfg.allowlist.entries]
        assert "systemd" in names

    def test_allowlist_has_klcds_itself(self) -> None:
        """The tool must never kill itself."""
        cfg = KLCDSConfig()
        names = [e.name for e in cfg.allowlist.entries]
        assert "klcds" in names


class TestValidation:
    """Test Pydantic validation catches bad values."""

    def test_invalid_db_engine(self) -> None:
        with pytest.raises(ValueError, match="Unsupported DB engine"):
            KLCDSConfig(database={"engine": "mysql"})

    def test_invalid_log_level(self) -> None:
        with pytest.raises(ValueError, match="Invalid log_level"):
            KLCDSConfig(log_level="VERBOSE")

    def test_valid_log_levels(self) -> None:
        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            cfg = KLCDSConfig(log_level=level)
            assert cfg.log_level == level


class TestDeepMerge:
    """Test the YAML deep-merge utility."""

    def test_shallow_merge(self) -> None:
        base = {"a": 1, "b": 2}
        over = {"b": 3, "c": 4}
        result = _deep_merge(base, over)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self) -> None:
        base = {"db": {"engine": "sqlite", "path": "/tmp/a.db"}}
        over = {"db": {"path": "/tmp/b.db"}}
        result = _deep_merge(base, over)
        assert result["db"]["engine"] == "sqlite"
        assert result["db"]["path"] == "/tmp/b.db"


class TestFileLoading:
    """Test loading config from a YAML file."""

    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        cfg_data = {
            "log_level": "DEBUG",
            "database": {"engine": "sqlite", "sqlite_path": str(tmp_path / "test.db")},
            "response": {"safe_mode": True},
        }
        cfg_file = tmp_path / "klcds.yaml"
        cfg_file.write_text(yaml.dump(cfg_data))

        cfg = load_config(explicit_path=str(cfg_file))
        assert cfg.log_level == "DEBUG"
        assert cfg.database.sqlite_path == str(tmp_path / "test.db")

    def test_load_with_overrides(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "klcds.yaml"
        cfg_file.write_text(yaml.dump({"log_level": "INFO"}))

        cfg = load_config(
            explicit_path=str(cfg_file),
            overrides={"log_level": "WARNING"},
        )
        assert cfg.log_level == "WARNING"

    def test_load_missing_file_uses_defaults(self) -> None:
        cfg = load_config(explicit_path="/nonexistent/klcds.yaml")
        assert cfg.log_level == "INFO"
        assert cfg.response.safe_mode is True
