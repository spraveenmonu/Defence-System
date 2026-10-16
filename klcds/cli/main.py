"""
klcds.cli.main — Command-line interface for KLCDS
===================================================
Entry point for the ``klcds`` command.  Uses ``click`` for argument parsing.

Usage::

    klcds status                  # Show system status
    klcds events --live           # Stream events in real time
    klcds alerts                  # List recent alerts
    klcds posture                 # Show security posture score
    klcds init-db                 # Initialize / migrate the database
    klcds config-dump             # Dump effective configuration
    klcds run                     # Start the full engine (daemon)
    klcds run --enforce           # Start with response enforcement ON
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from klcds import __version__
from klcds.core.config import load_config
from klcds.core.database import Database
from klcds.core.logging_setup import setup_logging
from klcds.core.models import Severity


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="klcds")
@click.option(
    "-c", "--config",
    type=click.Path(exists=False),
    default=None,
    help="Path to klcds.yaml config file.",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Enable DEBUG logging.",
)
@click.pass_context
def cli(ctx: click.Context, config: str | None, verbose: bool) -> None:
    """
    ╔═══════════════════════════════════════════════════════════╗
    ║   KLCDS — Kernel-Level Cyber Defense System              ║
    ║   Defensive host security for Linux                      ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    cfg = load_config(explicit_path=config)
    if verbose:
        cfg.log_level = "DEBUG"
    logger = setup_logging(level=cfg.log_level, log_file=cfg.log_file)
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg
    ctx.obj["logger"] = logger


# ---------------------------------------------------------------------------
# init-db
# ---------------------------------------------------------------------------

@cli.command("init-db")
@click.pass_context
def init_db(ctx: click.Context) -> None:
    """Initialize (or migrate) the SQLite database."""
    cfg = ctx.obj["config"]
    db = Database(cfg)
    db.connect()
    db.initialize()
    ver = db.current_schema_version()
    click.echo(f"✅ Database initialized at {cfg.database.sqlite_path}")
    click.echo(f"   Schema version: {ver}")
    db.close()


# ---------------------------------------------------------------------------
# config-dump
# ---------------------------------------------------------------------------

@cli.command("config-dump")
@click.pass_context
def config_dump(ctx: click.Context) -> None:
    """Dump the effective (merged) configuration as JSON."""
    cfg = ctx.obj["config"]
    click.echo(cfg.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show KLCDS system status and database summary."""
    cfg = ctx.obj["config"]
    db = Database(cfg)
    try:
        db.connect()
        stats = db.get_stats()
    except Exception as exc:
        click.echo(f"⚠️  Cannot connect to database: {exc}")
        stats = {}
    finally:
        db.close()

    safe = "🟢 ON (actions logged only)" if cfg.response.safe_mode else "🔴 OFF (enforcement active)"

    click.echo()
    click.echo("╔══════════════════════════════════════════════════╗")
    click.echo("║          KLCDS — System Status                  ║")
    click.echo("╠══════════════════════════════════════════════════╣")
    click.echo(f"║  Version      : {__version__:<33}║")
    click.echo(f"║  Safe Mode    : {safe:<33}║")
    click.echo(f"║  DB Engine    : {cfg.database.engine:<33}║")
    click.echo(f"║  DB Path      : {cfg.database.sqlite_path:<33}║")
    click.echo(f"║  Log Level    : {cfg.log_level:<33}║")
    click.echo("╠══════════════════════════════════════════════════╣")
    if stats:
        click.echo(f"║  Total Events : {stats.get('total_events', 0):<33}║")
        click.echo(f"║  Total Alerts : {stats.get('total_alerts', 0):<33}║")
        click.echo(f"║  Critical     : {stats.get('critical_alerts', 0):<33}║")
        click.echo(f"║  High         : {stats.get('high_alerts', 0):<33}║")
        click.echo(f"║  Active       : {stats.get('active_alerts', 0):<33}║")
    else:
        click.echo("║  (database not yet initialized)                  ║")
    click.echo("╚══════════════════════════════════════════════════╝")
    click.echo()


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-n", "--limit", default=20, help="Number of events to show.")
@click.option("--syscall", default=None, help="Filter by syscall type.")
@click.option("--pid", default=None, type=int, help="Filter by PID.")
@click.option("--live", is_flag=True, help="Stream events in real time (Phase 2).")
@click.pass_context
def events(ctx: click.Context, limit: int, syscall: str | None, pid: int | None, live: bool) -> None:
    """Show recent kernel events."""
    if live:
        click.echo("🔴 Live event streaming will be available in Phase 2.")
        click.echo("   (Requires the eBPF collector to be running.)")
        return

    cfg = ctx.obj["config"]
    db = Database(cfg)
    db.connect()
    rows = db.get_recent_events(limit=limit, syscall=syscall, pid=pid)
    db.close()

    if not rows:
        click.echo("No events found.")
        return

    # Pretty table output
    click.echo(f"\n{'TIMESTAMP':<26} {'SYSCALL':<12} {'PID':>7} {'UID':>6} {'COMM':<16} {'PATH'}")
    click.echo("─" * 100)
    for r in rows:
        ts = r.get("timestamp", "")[:25]
        sc = r.get("syscall", "")
        p = r.get("pid", "")
        u = r.get("uid", "")
        c = r.get("comm", "")[:15]
        path = r.get("exe_path", "") or r.get("file_path", "") or ""
        click.echo(f"{ts:<26} {sc:<12} {p:>7} {u:>6} {c:<16} {path}")


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-n", "--limit", default=20, help="Number of alerts to show.")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--status", "alert_status", default=None, help="Filter by status.")
@click.pass_context
def alerts(ctx: click.Context, limit: int, severity: str | None, alert_status: str | None) -> None:
    """Show recent alerts."""
    cfg = ctx.obj["config"]
    db = Database(cfg)
    db.connect()
    rows = db.get_alerts(limit=limit, severity=severity, status=alert_status)
    db.close()

    if not rows:
        click.echo("No alerts found.")
        return

    SEVERITY_COLORS = {
        "critical": "\033[1;31m",  # Bold red
        "high": "\033[31m",        # Red
        "medium": "\033[33m",      # Yellow
        "low": "\033[36m",         # Cyan
        "info": "\033[37m",        # White
    }
    RESET = "\033[0m"

    click.echo(f"\n{'TIMESTAMP':<26} {'SEV':<10} {'RULE':<30} {'STATUS':<14} {'SCORE':>5}")
    click.echo("─" * 90)
    for r in rows:
        sev = r.get("severity", "")
        color = SEVERITY_COLORS.get(sev, "")
        click.echo(
            f"{r.get('timestamp', '')[:25]:<26} "
            f"{color}{sev:<10}{RESET} "
            f"{r.get('rule_id', '')[:29]:<30} "
            f"{r.get('status', ''):<14} "
            f"{r.get('risk_score', 0):>5.1f}"
        )


# ---------------------------------------------------------------------------
# posture
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def posture(ctx: click.Context) -> None:
    """Show the latest security posture score."""
    cfg = ctx.obj["config"]
    db = Database(cfg)
    db.connect()
    rows = db.query(
        "SELECT * FROM posture_snapshots ORDER BY timestamp DESC LIMIT 1"
    )
    db.close()

    if not rows:
        click.echo("No posture snapshot available yet.  Run `klcds scan-posture` first.")
        return

    s = rows[0]
    score = s.get("score", 0)

    if score >= 80:
        bar_color = "\033[32m"   # Green
        grade = "A"
    elif score >= 60:
        bar_color = "\033[33m"   # Yellow
        grade = "B"
    elif score >= 40:
        bar_color = "\033[33m"
        grade = "C"
    else:
        bar_color = "\033[31m"   # Red
        grade = "F"

    RESET = "\033[0m"
    filled = int(score / 2)
    bar = f"{bar_color}{'█' * filled}{'░' * (50 - filled)}{RESET}"

    click.echo()
    click.echo("╔══════════════════════════════════════════════════════════╗")
    click.echo("║            KLCDS — Security Posture Score               ║")
    click.echo("╠══════════════════════════════════════════════════════════╣")
    click.echo(f"║  Overall  {bar} {score:.0f}/100 [{grade}]  ║")
    click.echo("╠══════════════════════════════════════════════════════════╣")
    click.echo(f"║  Firewall       : {s.get('firewall_score', 0):>5.1f}  │  Open Ports   : {s.get('open_ports_score', 0):>5.1f}     ║")
    click.echo(f"║  SUID Binaries  : {s.get('suid_score', 0):>5.1f}  │  World-Write  : {s.get('world_writable_score', 0):>5.1f}     ║")
    click.echo(f"║  SSH Config     : {s.get('ssh_config_score', 0):>5.1f}  │  Updates      : {s.get('updates_score', 0):>5.1f}     ║")
    click.echo(f"║  Encryption     : {s.get('encryption_score', 0):>5.1f}  │  Services     : {s.get('services_score', 0):>5.1f}     ║")
    click.echo("╚══════════════════════════════════════════════════════════╝")
    click.echo()


# ---------------------------------------------------------------------------
# run (daemon / foreground)
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--enforce", is_flag=True, default=False,
              help="Enable enforcement (disable safe mode). ⚠️ Use only in a VM.")
@click.option("--daemon", is_flag=True, default=False,
              help="Run as a background daemon.")
@click.pass_context
def run(ctx: click.Context, enforce: bool, daemon: bool) -> None:
    """Start the KLCDS defense engine."""
    cfg = ctx.obj["config"]

    if enforce:
        cfg.response.safe_mode = False
        click.echo("⚠️  ENFORCEMENT MODE ACTIVE — response actions WILL be executed.")
        click.echo("   Make sure you are running inside an isolated VM!\n")
    else:
        click.echo("🛡️  Safe mode ON — all response actions are logged only.\n")

    click.echo("Starting KLCDS engine...")
    click.echo("  • eBPF collectors    → Phase 2")
    click.echo("  • Rule engine        → Phase 3")
    click.echo("  • Scanners           → Phase 4")
    click.echo("  • Ransomware shield  → Phase 5")
    click.echo("  • Response engine    → Phase 6")
    click.echo("  • API server         → Phase 7")
    click.echo("  • ML detector        → Phase 8")
    click.echo()
    click.echo("Phase 1 complete.  Engine subsystems will be wired in subsequent phases.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
