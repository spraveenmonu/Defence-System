"""
simulator.scenarios.base — Base class and helpers for attack scenarios
======================================================================
"""

from __future__ import annotations

import abc
import hashlib
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from klcds.core.models import (
    ActionType,
    Alert,
    AlertStatus,
    KernelEvent,
    Severity,
    SyscallType,
)
from simulator.models import (
    KillChainPhase,
    SimulationScenarioMetadata,
    SimulationStep,
)


class BaseScenario(abc.ABC):
    """Abstract base class for all cybersecurity attack simulations."""

    @property
    @abc.abstractmethod
    def metadata(self) -> SimulationScenarioMetadata:
        """Return scenario metadata."""
        ...

    @abc.abstractmethod
    def build_steps(self) -> list[SimulationStep]:
        """Construct the sequence of execution steps, events, alerts, and defenses."""
        ...

    # -- Convenience generators ----------------------------------------------

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def make_sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def create_event(
        self,
        syscall: SyscallType,
        pid: int,
        comm: str,
        uid: int = 1000,
        gid: int = 1000,
        ppid: int = 1,
        exe_path: Optional[str] = None,
        cmdline: Optional[str] = None,
        file_path: Optional[str] = None,
        file_path_dst: Optional[str] = None,
        src_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        target_uid: Optional[int] = None,
        return_code: int = 0,
    ) -> KernelEvent:
        """Generate a simulated KernelEvent with realistic telemetry."""
        return KernelEvent(
            event_id=str(uuid4()),
            timestamp=self.now_iso(),
            syscall=syscall,
            pid=pid,
            ppid=ppid,
            uid=uid,
            gid=gid,
            comm=comm,
            exe_path=exe_path or f"/usr/bin/{comm}",
            exe_sha256=self.make_sha256(comm + str(pid)),
            cmdline=cmdline or comm,
            file_path=file_path,
            file_path_dst=file_path_dst,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            target_uid=target_uid,
            return_code=return_code,
        )

    def create_alert(
        self,
        rule_name: str,
        title: str,
        description: str,
        severity: Severity,
        risk_score: float,
        primary_event: KernelEvent,
        affected_file: Optional[str] = None,
        affected_ip: Optional[str] = None,
        recommended_action: ActionType = ActionType.ALERT,
        attack_type: str = "simulation",
    ) -> Alert:
        """Generate an Alert triggered by simulated detection rules."""
        file_list = [affected_file] if affected_file else ([primary_event.file_path] if primary_event.file_path else [])
        ip_val = affected_ip or primary_event.dst_ip or primary_event.src_ip
        ip_list = [ip_val] if ip_val else []
        return Alert(
            alert_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            rule_id=rule_name,
            rule_name=title,
            attack_type=attack_type,
            description=description,
            severity=severity,
            status=AlertStatus.NEW,
            risk_score=float(risk_score),
            event_ids=[primary_event.event_id],
            affected_files=file_list,
            affected_ips=ip_list,
            actions_taken=[recommended_action.value],
        )

    def create_action(
        self,
        action_type: ActionType,
        target_type: str,
        target_value: str,
        reason: str,
        alert_id: Optional[str] = None,
        success: bool = True,
        executed: bool = True,
    ) -> dict[str, Any]:
        """Generate a simulated automated response action record."""
        return {
            "action_id": str(uuid4()),
            "alert_id": alert_id or str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type.value,
            "target": f"{target_type}:{target_value}",
            "target_type": target_type,
            "target_value": target_value,
            "success": 1 if success else 0,
            "executed": executed,
            "safe_mode": 0 if executed else 1,
            "detail": reason,
            "reversible": 1,
            "reverse_command": f"# undo {action_type.value} on {target_value}",
            "error_message": None,
            "reason": reason,
        }
