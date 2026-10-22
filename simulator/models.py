"""
simulator.models — Data models for the Cyber Defense Simulation Engine
======================================================================
Defines schemas for attack scenarios, execution steps, simulation results,
and MITRE ATT&CK mappings.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field

from klcds.core.models import ActionType, Alert, KernelEvent, Severity


class ScenarioCategory(str, enum.Enum):
    """Categorization of cyber attack simulations."""
    RANSOMWARE = "ransomware"
    MALWARE = "malware"
    NETWORK = "network"
    CREDENTIALS = "credentials"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RESOURCE_HIJACKING = "resource_hijacking"
    DENIAL_OF_SERVICE = "denial_of_service"


class KillChainPhase(str, enum.Enum):
    """Cyber Kill Chain phases for attack progression."""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command & Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


class SimulationScenarioMetadata(BaseModel):
    """Metadata describing a simulation scenario."""
    id: str
    name: str
    category: ScenarioCategory
    description: str
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: Severity = Severity.HIGH
    default_delay_ms: int = 400
    target_asset: str = "SRV-PROD-01 (Ubuntu 22.04 LTS / Simulated Kernel 6.5)"
    attacker_profile: str = "APT / Threat Actor Simulation"


class SimulationStep(BaseModel):
    """A single discrete step in a multi-stage simulation scenario."""
    step_number: int
    phase: KillChainPhase
    title: str
    description: str
    events: list[KernelEvent] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    posture_impact: int = 0
    delay_ms: int = 400


class SimulationResult(BaseModel):
    """Summary of a completed simulation run."""
    scenario_id: str
    scenario_name: str
    started_at: str
    finished_at: str
    duration_sec: float
    total_events: int
    total_alerts: int
    critical_alerts: int
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    posture_before: int = 95
    posture_after: int = 70
    contained: bool = True
    defense_summary: str = ""
