"""
simulator.scenarios.portscan — Network port scan and reconnaissance scenario
============================================================================
Simulates TCP SYN scanning across common service ports, banner grabbing,
and automated rate limiting / dynamic IP ban.
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


class PortScanScenario(BaseScenario):
    """Simulates reconnaissance port scanning and defense firewall auto-containment."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="portscan",
            name="Stealth SYN Port Scan & Reconnaissance",
            category=ScenarioCategory.NETWORK,
            description="Simulates external actor probing 16 standard and high ports in rapid succession to discover exposed services, tripping connection velocity rules.",
            mitre_tactics=["Discovery"],
            mitre_techniques=["T1046 Network Service Scanning", "T1595 Active Scanning"],
            severity=Severity.MEDIUM,
            default_delay_ms=250,
        )

    def build_steps(self) -> list[SimulationStep]:
        scanner_pid = 6204
        src_ip = "203.0.113.88"
        dst_ip = "10.0.0.15"

        # Step 1: Low-profile probing
        ports_batch_1 = [21, 22, 23, 25, 53, 80]
        events_1 = [
            self.create_event(
                syscall=SyscallType.CONNECT,
                pid=scanner_pid,
                comm="nmap_syn",
                src_ip=src_ip,
                src_port=50000 + p,
                dst_ip=dst_ip,
                dst_port=p,
                protocol="TCP",
                return_code=0 if p in (22, 80) else -111,
            )
            for p in ports_batch_1
        ]
        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.RECONNAISSANCE,
            title="Initial Service Probing",
            description=f"Source {src_ip} probes common management and web ports (21, 22, 23, 25, 53, 80).",
            events=events_1,
            alerts=[],
            actions=[],
            posture_impact=-5,
            delay_ms=250,
        )

        # Step 2: High velocity sweep across database and remote desktop ports
        ports_batch_2 = [135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
        events_2 = [
            self.create_event(
                syscall=SyscallType.CONNECT,
                pid=scanner_pid,
                comm="nmap_syn",
                src_ip=src_ip,
                src_port=51000 + p,
                dst_ip=dst_ip,
                dst_port=p,
                protocol="TCP",
                return_code=0 if p in (443, 8080) else -111,
            )
            for p in ports_batch_2
        ]
        primary_e = events_2[2]
        a1 = self.create_alert(
            rule_name="port_scan_detected",
            title="🔍 Vertical & Horizontal Port Scan Detected",
            description=f"Host {src_ip} probed 16 distinct ports within 4.2 seconds (threshold: >10 ports in 15s).",
            severity=Severity.MEDIUM,
            risk_score=68,
            primary_event=primary_e,
            affected_ip=src_ip,
            recommended_action=ActionType.BLOCK_IP,
        )
        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.RECONNAISSANCE,
            title="Aggressive Port Sweep & Firewall Ban",
            description="Reconnaissance crosses velocity threshold. Automated defense initiates a dynamic 1-hour IP block on virtual firewall.",
            events=events_2,
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.COLLECT_EVIDENCE,
                    "ip",
                    src_ip,
                    f"Logged 16 connection attempts and SYN timing profiles for IP {src_ip}",
                    alert_id=a1.alert_id,
                ),
                self.create_action(
                    ActionType.BLOCK_IP,
                    "ip",
                    src_ip,
                    f"Blocked scanner IP {src_ip} on INPUT chain (drop stateful packets)",
                    alert_id=a1.alert_id,
                ),
            ],
            posture_impact=-15,
            delay_ms=300,
        )

        return [step1, step2]
