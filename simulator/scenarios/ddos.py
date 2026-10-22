"""
simulator.scenarios.ddos — Denial of Service / SYN Flood attack scenario
========================================================================
Simulates high-velocity SYN flood, connection table exhaustion, and automated
mitigation via virtual SYN cookies and traffic rate limiting.
"""

from __future__ import annotations

from klcds.core.models import ActionType, Severity, SyscallType
from simulator.models import (
    KillChainPhase,
    ScenarioCategory,
    SimulationScenarioMetadata,
    SimulationStep,
)
from simulator.scenarios.base import BaseScenario


class DDoSScenario(BaseScenario):
    """Simulates volumetric TCP SYN flood denial-of-service attack."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="ddos",
            name="Volumetric SYN Flood Denial of Service",
            category=ScenarioCategory.DENIAL_OF_SERVICE,
            description="Simulates incoming multi-source SYN flood against web server, exhausting TCP socket backlog and triggering automated SYN cookie countermeasures.",
            mitre_tactics=["Impact"],
            mitre_techniques=["T1498.001 Direct Network Flood", "T1499 Endpoint Denial of Service"],
            severity=Severity.HIGH,
            default_delay_ms=250,
        )

    def build_steps(self) -> list[SimulationStep]:
        spoofed_ips = [
            "185.190.140.12",
            "185.190.140.13",
            "185.190.140.14",
            "45.142.122.9",
            "45.142.122.10",
        ]

        events = [
            self.create_event(
                syscall=SyscallType.CONNECT,
                pid=80,
                comm="nginx",
                src_ip=ip,
                src_port=40000 + i * 111,
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="TCP_SYN",
                return_code=-11,  # EAGAIN / Backlog full
            )
            for i, ip in enumerate(spoofed_ips)
        ]

        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            title="SYN Ingress Flood",
            description="High frequency SYN handshake requests received with non-acknowledging spoofed origin addresses.",
            events=events[:3],
            alerts=[],
            actions=[],
            posture_impact=-15,
            delay_ms=200,
        )

        primary_e = events[0]
        a1 = self.create_alert(
            rule_name="syn_flood_exhaustion",
            title="🌊 Volumetric TCP SYN Flood Detected",
            description="Connection queue exceeded 12,000 half-open embryonic states per second from botnet subnet 185.190.140.0/24.",
            severity=Severity.HIGH,
            risk_score=87,
            primary_event=primary_e,
            affected_ip="185.190.140.0/24",
            recommended_action=ActionType.BLOCK_IP,
        )

        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            title="SYN Cookie Activation & Subnet Filter",
            description="Defense mechanism enables kernel SYN cookies and drops anomalous half-open connection bursts.",
            events=events[3:],
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.BLOCK_IP,
                    "subnet",
                    "185.190.140.0/24",
                    "Enforced subnet rate limiting and TCP SYN proxy mitigation",
                    alert_id=a1.alert_id,
                )
            ],
            posture_impact=-15,
            delay_ms=250,
        )

        return [step1, step2]
