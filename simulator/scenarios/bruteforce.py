"""
simulator.scenarios.bruteforce — SSH / Auth brute force scenario
================================================================
Simulates credential stuffing and dictionary attack against SSH / auth daemons,
prompting failed login thresholds, alerts, and automatic IP lockout.
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


class BruteForceScenario(BaseScenario):
    """Simulates credential stuffing and brute force login attempts against host services."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="bruteforce",
            name="SSH / Auth Credential Stuffing Attack",
            category=ScenarioCategory.CREDENTIALS,
            description="Simulates automated botnet running dictionary authentication against SSH daemon, triggering threshold correlation and instant firewall blacklisting.",
            mitre_tactics=["Credential Access", "Initial Access"],
            mitre_techniques=["T1110.001 Password Guessing", "T1110.003 Password Spraying"],
            severity=Severity.HIGH,
            default_delay_ms=280,
        )

    def build_steps(self) -> list[SimulationStep]:
        sshd_pid = 4820
        src_ip = "192.168.1.105"
        accounts = ["root", "admin", "ubuntu", "postgres", "deploy", "guest"]

        events = []
        for i, user in enumerate(accounts):
            events.append(
                self.create_event(
                    syscall=SyscallType.SSH_AUTH,
                    pid=sshd_pid + i,
                    comm="sshd",
                    uid=0,
                    cmdline=f"pam_authenticate user={user} result=FAIL",
                    src_ip=src_ip,
                    src_port=41230 + i,
                    dst_ip="10.0.0.1",
                    dst_port=22,
                    protocol="TCP",
                    return_code=-1,
                )
            )

        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.EXPLOITATION,
            title="Credential Spraying Initiated",
            description=f"Initial failed authentication spikes from remote client {src_ip}.",
            events=events[:3],
            alerts=[],
            actions=[],
            posture_impact=-10,
            delay_ms=250,
        )

        primary_e = events[-1]
        a1 = self.create_alert(
            rule_name="ssh_brute_force",
            title="🔑 SSH Dictionary / Brute Force Attack",
            description=f"Host {src_ip} accumulated 14 failed SSH authentication attempts within 30 seconds across multiple usernames ({', '.join(accounts)}).",
            severity=Severity.HIGH,
            risk_score=88,
            primary_event=primary_e,
            affected_ip=src_ip,
            recommended_action=ActionType.BLOCK_IP,
        )

        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.EXPLOITATION,
            title="Threshold Exceeded & IP Lockout",
            description="Authentication velocity trips defensive threshold. Engine triggers autonomous firewall block and notifies SIEM.",
            events=events[3:],
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.BLOCK_IP,
                    "ip",
                    src_ip,
                    f"Blocked brute-force IP {src_ip} in nftables input filter table",
                    alert_id=a1.alert_id,
                )
            ],
            posture_impact=-20,
            delay_ms=300,
        )

        return [step1, step2]
