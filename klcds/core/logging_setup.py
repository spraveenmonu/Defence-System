"""
klcds.core.logging_setup — Structured logging for KLCDS
========================================================
Sets up Python logging with:
  • Console handler with colored output (via Rich if available, else ANSI)
  • File handler with JSON-structured lines (for machine parsing)
  • A ``klcds`` root logger that all submodules inherit
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line (structured logging)."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class ColorFormatter(logging.Formatter):
    """ANSI-colored console output without external dependencies."""

    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[1;31m", # Bold Red
    }
    RESET = "\033[0m"
    CYAN = "\033[36m"
    DIM = "\033[2m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return (
            f"{self.DIM}{ts}{self.RESET} "
            f"{color}{record.levelname:<8}{self.RESET} "
            f"{self.CYAN}{record.name}{self.RESET} "
            f"│ {record.getMessage()}"
        )


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Configure the ``klcds`` logger hierarchy.

    Parameters
    ----------
    level : str
        Python log level name.
    log_file : str, optional
        If given, JSON-structured log lines are written here.

    Returns
    -------
    logging.Logger
        The root ``klcds`` logger.
    """
    root = logging.getLogger("klcds")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    # Console handler (always)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ColorFormatter())
    root.addHandler(console)

    # File handler (optional)
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setFormatter(JSONFormatter())
        root.addHandler(fh)

    return root
