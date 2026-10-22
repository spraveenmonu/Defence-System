"""
simulator.scenarios.ransomware — Ransomware attack simulation
=============================================================
Simulates canary trap file access, rapid high-entropy encryption, mass file
renaming, backup shadow deletion attempt, and automated defense containment.
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


class RansomwareScenario(BaseScenario):
    """Simulates a sophisticated ransomware kill chain against sensitive user directories."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="ransomware",
            name="Ransomware Mass Encryption & Canary Breach",
            category=ScenarioCategory.RANSOMWARE,
            description="Simulates adversary deploying cryptor binary, breaching canary decoy files, rapidly encrypting user directories, attempting backup sabotage, and triggering automated kernel containment.",
            mitre_tactics=["Impact", "Defense Evasion", "Inhibit System Recovery"],
            mitre_techniques=["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery", "T1036 Masquerading"],
            severity=Severity.CRITICAL,
            default_delay_ms=350,
        )

    def build_steps(self) -> list[SimulationStep]:
        pid = 9942
        comm = "cryptor"
        uid = 1000

        # Step 1: Reconnaissance & Canary Tripwire
        e1 = self.create_event(
            syscall=SyscallType.OPENAT,
            pid=pid,
            comm=comm,
            uid=uid,
            cmdline="./cryptor --target /home/user",
            file_path="/var/lib/klcds/canary/trap_secret_financials.xlsx",
        )
        e2 = self.create_event(
            syscall=SyscallType.OPENAT,
            pid=pid,
            comm=comm,
            uid=uid,
            cmdline="./cryptor --target /home/user",
            file_path="/home/user/Documents/q4_report.docx",
        )
        a1 = self.create_alert(
            rule_name="ransomware_canary_touch",
            title="🪤 Decoy Canary File Accessed",
            description=f"Process '{comm}' (PID {pid}) opened tripwire file '/var/lib/klcds/canary/trap_secret_financials.xlsx'. High confidence ransomware early warning.",
            severity=Severity.CRITICAL,
            risk_score=95,
            primary_event=e1,
            recommended_action=ActionType.SUSPEND_PROCESS,
        )
        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.RECONNAISSANCE,
            title="Canary File Access Probed",
            description="The malicious process discovers and touches a hidden canary decoy file, tripping the defense decoy alarm.",
            events=[e1, e2],
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.ALERT,
                    "file",
                    "/var/lib/klcds/canary/trap_secret_financials.xlsx",
                    "Canary trap triggered by cryptor process",
                    alert_id=a1.alert_id,
                )
            ],
            posture_impact=-20,
            delay_ms=300,
        )

        # Step 2: High Entropy Encryption & Mass Renaming
        e3 = self.create_event(
            syscall=SyscallType.RENAME,
            pid=pid,
            comm=comm,
            uid=uid,
            file_path="/home/user/Documents/q4_report.docx",
            file_path_dst="/home/user/Documents/q4_report.docx.LOCKED",
        )
        e4 = self.create_event(
            syscall=SyscallType.RENAME,
            pid=pid,
            comm=comm,
            uid=uid,
            file_path="/home/user/Photos/family_vacation.jpg",
            file_path_dst="/home/user/Photos/family_vacation.jpg.LOCKED",
        )
        e5 = self.create_event(
            syscall=SyscallType.RENAME,
            pid=pid,
            comm=comm,
            uid=uid,
            file_path="/home/user/Database/customers.db",
            file_path_dst="/home/user/Database/customers.db.LOCKED",
        )
        a2 = self.create_alert(
            rule_name="ransomware_mass_rename",
            title="🔐 Mass File Encryption & Rename Detected",
            description=f"PID {pid} modified 48 files in under 3 seconds with Shannon entropy 7.92 (encrypted payload signature).",
            severity=Severity.CRITICAL,
            risk_score=99,
            primary_event=e3,
            recommended_action=ActionType.KILL_PROCESS,
        )
        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            title="High-Entropy Mass Encryption Wave",
            description="Process initiates rapid multi-threaded AES encryption across document trees, triggering the Shannon entropy threshold.",
            events=[e3, e4, e5],
            alerts=[a2],
            actions=[
                self.create_action(
                    ActionType.SUSPEND_PROCESS,
                    "process",
                    str(pid),
                    "Kernel emergency freeze (SIGSTOP) issued to prevent further file modifications",
                    alert_id=a2.alert_id,
                )
            ],
            posture_impact=-35,
            delay_ms=400,
        )

        # Step 3: Backup Tampering & Shadow Copy Deletion Attempt
        e6 = self.create_event(
            syscall=SyscallType.EXECVE,
            pid=pid + 1,
            ppid=pid,
            comm="sh",
            uid=uid,
            cmdline="vssadmin delete shadows /all /quiet || rm -rf /var/backups/*",
        )
        e7 = self.create_event(
            syscall=SyscallType.UNLINK,
            pid=pid + 1,
            ppid=pid,
            comm="rm",
            uid=uid,
            file_path="/var/backups/system_snapshot.tar.gz",
            return_code=-13,  # EACCES (blocked)
        )
        a3 = self.create_alert(
            rule_name="backup_tamper_attempt",
            title="🛡️ Backup Tampering & Shadow Copy Sabotage",
            description=f"Child process {pid + 1} attempted to purge backup snapshots and system recovery images.",
            severity=Severity.CRITICAL,
            risk_score=97,
            primary_event=e6,
            recommended_action=ActionType.NETWORK_ISOLATE,
        )
        step3 = SimulationStep(
            step_number=3,
            phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            title="Backup Invalidation Attempt",
            description="The ransomware attempts to delete local backup stores and volume snapshots to prevent restoration.",
            events=[e6, e7],
            alerts=[a3],
            actions=[
                self.create_action(
                    ActionType.KILL_PROCESS,
                    "process",
                    str(pid),
                    "Terminated rogue encryptor process tree via SIGKILL",
                    alert_id=a3.alert_id,
                ),
                self.create_action(
                    ActionType.NETWORK_ISOLATE,
                    "interface",
                    "eth0",
                    "Host isolated from local LAN to prevent lateral ransomware spreading",
                    alert_id=a3.alert_id,
                ),
                self.create_action(
                    ActionType.BACKUP_VERIFY,
                    "backup_store",
                    "/var/backups",
                    "Immutable backup snapshot verified intact (100% integrity verified)",
                    alert_id=a3.alert_id,
                ),
            ],
            posture_impact=-10,
            delay_ms=450,
        )

        return [step1, step2, step3]
