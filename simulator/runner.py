"""
simulator.runner — Orchestrator for executing attack & defense simulations
==========================================================================
Executes scenario kill-chains, updates telemetry databases, calculates real-time
posture metrics, and emits structured event streams.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional
from uuid import uuid4

from klcds.core.database import Database
from klcds.core.models import PostureSnapshot
from simulator.models import SimulationResult, SimulationStep
from simulator.scenarios import get_scenario, list_available_scenarios


def _clean_action_for_db(act: dict[str, Any], is_safe: bool) -> dict[str, Any]:
    return {
        "action_id": act.get("action_id", str(uuid4())),
        "timestamp": act.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "alert_id": act.get("alert_id") or str(uuid4()),
        "action_type": act.get("action_type", "alert"),
        "target": act.get("target") or f"{act.get('target_type', 'target')}:{act.get('target_value', 'system')}",
        "safe_mode": 1 if is_safe else 0,
        "success": 1 if act.get("success") else 0,
        "detail": act.get("detail") or act.get("reason", "Simulated countermeasure"),
        "reversible": 1,
        "reverse_command": act.get("reverse_command", ""),
    }


def _snapshot_for_db(score: float) -> dict[str, Any]:
    return {
        "snapshot_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score": float(score),
        "firewall_score": 85.0,
        "open_ports_score": 90.0,
        "suid_score": 95.0,
        "world_writable_score": 92.0,
        "ssh_config_score": 88.0,
        "updates_score": 95.0,
        "encryption_score": 90.0,
        "services_score": 94.0,
        "os_version": "Simulated Linux / Windows Host",
        "kernel_version": "6.5.0-sim",
        "open_port_count": 4,
        "root_service_count": 12,
        "suid_binary_count": 8,
        "world_writable_count": 2,
        "pending_updates": 0,
        "firewall_active": 1,
        "disk_encrypted": 1,
    }


class SimulationRunner:
    """Executes attack scenarios and coordinates defensive responses."""

    def __init__(self, db: Optional[Database] = None, safe_mode: bool = True) -> None:
        self.db = db
        self.safe_mode = safe_mode
        self._current_posture_score = 98

    def execute_scenario(
        self,
        scenario_id: str,
        safe_mode: Optional[bool] = None,
    ) -> SimulationResult:
        """Run a simulation synchronously from start to finish."""
        is_safe = self.safe_mode if safe_mode is None else safe_mode
        scenario = get_scenario(scenario_id)
        steps = scenario.build_steps()

        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()

        total_events = 0
        total_alerts = 0
        critical_alerts = 0
        all_actions = []
        posture_before = self._current_posture_score

        for step in steps:
            # Events
            for evt in step.events:
                total_events += 1
                if self.db:
                    self.db.insert_event(evt.dict_for_db())

            # Alerts
            for alt in step.alerts:
                total_alerts += 1
                if alt.severity.value == "critical":
                    critical_alerts += 1
                if self.db:
                    self.db.insert_alert(alt.dict_for_db())

            # Actions
            for act in step.actions:
                act_copy = dict(act)
                act_copy["safe_mode"] = is_safe
                act_copy["executed"] = not is_safe
                all_actions.append(act_copy)
                if self.db:
                    self.db.insert_response_action(_clean_action_for_db(act_copy, is_safe))

            self._current_posture_score = max(
                15, min(100, self._current_posture_score + step.posture_impact)
            )

        duration = time.perf_counter() - t0
        finished_at = datetime.now(timezone.utc).isoformat()

        # Record final posture snapshot
        if self.db:
            self.db.insert_posture(_snapshot_for_db(self._current_posture_score))

        defense_summary = (
            f"Scenario '{scenario.metadata.name}' simulated. "
            f"Generated {total_events} kernel events and {total_alerts} alerts. "
            f"Autonomous defense enacted {len(all_actions)} countermeasures "
            f"(Safe Mode: {'ENGAGED' if is_safe else 'OFF/ENFORCE'})."
        )

        return SimulationResult(
            scenario_id=scenario.metadata.id,
            scenario_name=scenario.metadata.name,
            started_at=started_at,
            finished_at=finished_at,
            duration_sec=round(duration, 3),
            total_events=total_events,
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            actions_taken=all_actions,
            posture_before=posture_before,
            posture_after=self._current_posture_score,
            contained=True,
            defense_summary=defense_summary,
        )

    async def stream_scenario(
        self,
        scenario_id: str,
        safe_mode: Optional[bool] = None,
        speed_multiplier: float = 1.0,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Asynchronously stream simulation steps with live timing for WebSocket clients."""
        is_safe = self.safe_mode if safe_mode is None else safe_mode
        scenario = get_scenario(scenario_id)
        steps = scenario.build_steps()

        yield {
            "type": "scenario_start",
            "scenario": scenario.metadata.model_dump(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "posture": self._current_posture_score,
        }

        for step in steps:
            # Yield step initiation
            yield {
                "type": "step_start",
                "step_number": step.step_number,
                "phase": step.phase.value,
                "title": step.title,
                "description": step.description,
            }

            # Emit events one by one
            for evt in step.events:
                evt_dict = evt.dict_for_db()
                if self.db:
                    self.db.insert_event(evt_dict)

                yield {
                    "type": "kernel_event",
                    "event": evt_dict,
                }
                sleep_s = max(0.04, (step.delay_ms / 1000.0) / speed_multiplier)
                await asyncio.sleep(sleep_s)

            # Emit alerts
            for alt in step.alerts:
                alt_dict = alt.dict_for_db()
                if self.db:
                    self.db.insert_alert(alt_dict)

                yield {
                    "type": "alert",
                    "alert": alt_dict,
                }
                await asyncio.sleep(0.05 / speed_multiplier)

            # Emit actions
            for act in step.actions:
                act_copy = dict(act)
                act_copy["safe_mode"] = is_safe
                act_copy["executed"] = not is_safe
                if self.db:
                    self.db.insert_response_action(_clean_action_for_db(act_copy, is_safe))

                yield {
                    "type": "response_action",
                    "action": act_copy,
                }

            self._current_posture_score = max(
                15, min(100, self._current_posture_score + step.posture_impact)
            )

            yield {
                "type": "posture_update",
                "posture": self._current_posture_score,
            }

            await asyncio.sleep(0.2 / speed_multiplier)

        yield {
            "type": "scenario_complete",
            "scenario_id": scenario_id,
            "final_posture": self._current_posture_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def reset_state(self) -> None:
        """Reset simulation posture and purge database tables."""
        self._current_posture_score = 98
        if self.db:
            with self.db.transaction() as cur:
                cur.execute("DELETE FROM response_actions")
                cur.execute("DELETE FROM alerts")
                cur.execute("DELETE FROM events")
                cur.execute("DELETE FROM posture_snapshots")
            # Insert initial clean posture
            self.db.insert_posture(_snapshot_for_db(98.0))
