"""
simulator.scenarios.cryptominer — Cryptocurrency miner & resource hijacking scenario
===================================================================================
Simulates high-CPU background miner daemon, mining pool stratum communication,
Isolation Forest behavioral anomaly detection, and automated eviction.
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


class CryptoMinerScenario(BaseScenario):
    """Simulates unauthorized cryptocurrency mining payload."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="cryptominer",
            name="Stealth Crypto Miner & Resource Hijacking",
            category=ScenarioCategory.RESOURCE_HIJACKING,
            description="Simulates adversary launching hidden cryptominer disguised as systemd-journal-helper, consuming 98% CPU and communicating with Stratum pool.",
            mitre_tactics=["Impact", "Defense Evasion", "Command and Control"],
            mitre_techniques=["T1496 Resource Hijacking", "T1036 Masquerading", "T1071 Application Layer Protocol"],
            severity=Severity.HIGH,
            default_delay_ms=300,
        )

    def build_steps(self) -> list[SimulationStep]:
        miner_pid = 9312
        uid = 1000

        # Step 1: Disguised execution
        e1 = self.create_event(
            syscall=SyscallType.EXECVE,
            pid=miner_pid,
            comm="syslog-worker",
            uid=uid,
            exe_path="/var/tmp/.syslog-worker",
            cmdline="/var/tmp/.syslog-worker --algo rx/0 --threads 8",
        )
        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.INSTALLATION,
            title="Masqueraded Daemon Launch",
            description="Miner process launched from hidden directory disguised as syslog-worker.",
            events=[e1],
            alerts=[],
            actions=[],
            posture_impact=-10,
            delay_ms=250,
        )

        # Step 2: Stratum mining pool connection
        e2 = self.create_event(
            syscall=SyscallType.CONNECT,
            pid=miner_pid,
            comm="syslog-worker",
            uid=uid,
            dst_ip="194.26.29.114",
            dst_port=3333,
            protocol="TCP",
        )
        a1 = self.create_alert(
            rule_name="stratum_mining_detected",
            title="⛏️ Crypto Mining Pool Communication (Stratum/TCP)",
            description="Process syslog-worker initiated Stratum mining handshake to 194.26.29.114:3333.",
            severity=Severity.HIGH,
            risk_score=84,
            primary_event=e2,
            recommended_action=ActionType.BLOCK_IP,
        )
        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.COMMAND_AND_CONTROL,
            title="Stratum Pool Beaconing",
            description="Miner initiates outbound Stratum mining telemetry with known Monero mining pool.",
            events=[e2],
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.BLOCK_IP,
                    "ip",
                    "194.26.29.114",
                    "Blocked mining pool IP 194.26.29.114 in firewall",
                    alert_id=a1.alert_id,
                )
            ],
            posture_impact=-20,
            delay_ms=300,
        )

        # Step 3: Sustained CPU Surge & Anomaly Isolation
        e3 = self.create_event(
            syscall=SyscallType.ANOMALY,
            pid=miner_pid,
            comm="syslog-worker",
            uid=uid,
            cmdline="Sustained 98.4% CPU usage across 8 worker threads for >120s",
        )
        a2 = self.create_alert(
            rule_name="ml_process_cpu_anomaly",
            title="🧠 Machine Learning Anomaly: Sustained Thread/CPU Surge",
            description="Isolation Forest behavioral model flagged process 9312 (score: -0.84, extreme anomaly) exhibiting non-linear CPU burn.",
            severity=Severity.HIGH,
            risk_score=89,
            primary_event=e3,
            recommended_action=ActionType.KILL_PROCESS,
        )
        step3 = SimulationStep(
            step_number=3,
            phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            title="Anomaly Score Tripped & Eviction",
            description="Behavioral ML anomaly detector confirms unauthorized resource exhaustion. Defense engine terminates PID and deletes binary.",
            events=[e3],
            alerts=[a2],
            actions=[
                self.create_action(
                    ActionType.KILL_PROCESS,
                    "process",
                    str(miner_pid),
                    "Terminated rogue cryptominer via SIGKILL",
                    alert_id=a2.alert_id,
                ),
                self.create_action(
                    ActionType.QUARANTINE_FILE,
                    "file",
                    "/var/tmp/.syslog-worker",
                    "Quarantined miner executable",
                    alert_id=a2.alert_id,
                ),
            ],
            posture_impact=0,
            delay_ms=350,
        )

        return [step1, step2, step3]
