"""
simulator.scenarios.privesc — Privilege escalation and SUID abuse scenario
==========================================================================
Simulates unprivileged user triggering an SUID vulnerability, transitioning
UID to 0 (root), tampering with capabilities, and attempting shadow read.
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


class PrivEscScenario(BaseScenario):
    """Simulates local privilege escalation via SUID binary abuse."""

    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="privesc",
            name="SUID Abuse & Privilege Escalation",
            category=ScenarioCategory.PRIVILEGE_ESCALATION,
            description="Simulates low-privileged process exploiting an SUID/capset flaw, attempting unauthorized setuid(0) transition and reading /etc/shadow, caught by kernel telemetry.",
            mitre_tactics=["Privilege Escalation", "Defense Evasion", "Credential Access"],
            mitre_techniques=[
                "T1068 Exploitation for Privilege Escalation",
                "T1548.001 Setuid and Setgid",
                "T1003.008 /etc/passwd and /etc/shadow",
            ],
            severity=Severity.CRITICAL,
            default_delay_ms=320,
        )

    def build_steps(self) -> list[SimulationStep]:
        low_pid = 8110
        suid_pid = 8112
        uid_normal = 1000

        # Step 1: Enumeration & SUID Execution
        e1 = self.create_event(
            syscall=SyscallType.EXECVE,
            pid=low_pid,
            comm="bash",
            uid=uid_normal,
            cmdline="find / -perm -4000 2>/dev/null",
        )
        e2 = self.create_event(
            syscall=SyscallType.EXECVE,
            pid=suid_pid,
            ppid=low_pid,
            comm="pkexec",
            uid=uid_normal,
            exe_path="/usr/bin/pkexec",
            cmdline="pkexec /tmp/exploit.so",
        )
        step1 = SimulationStep(
            step_number=1,
            phase=KillChainPhase.EXPLOITATION,
            title="SUID Vector Probed",
            description="Low-privilege session locates and triggers pkexec with malicious shared object parameter.",
            events=[e1, e2],
            alerts=[],
            actions=[],
            posture_impact=-15,
            delay_ms=300,
        )

        # Step 2: Unauthorized setuid transition
        e3 = self.create_event(
            syscall=SyscallType.SETUID,
            pid=suid_pid,
            comm="exploit",
            uid=uid_normal,
            target_uid=0,
            cmdline="./exploit --elevate",
        )
        e4 = self.create_event(
            syscall=SyscallType.CAPSET,
            pid=suid_pid,
            comm="exploit",
            uid=0,
            cmdline="./exploit --elevate",
        )
        a1 = self.create_alert(
            rule_name="unauthorized_setuid_root",
            title="🚨 Unauthorized Privilege Transition to Root (UID 0)",
            description=f"Process PID {suid_pid} transitioned credentials from non-root (UID 1000) to UID 0 outside of approved PAM session.",
            severity=Severity.CRITICAL,
            risk_score=96,
            primary_event=e3,
            recommended_action=ActionType.KILL_PROCESS,
        )
        step2 = SimulationStep(
            step_number=2,
            phase=KillChainPhase.EXPLOITATION,
            title="Root Privilege Transition",
            description="Process invokes setuid(0) and capset. Defense kernel sensor identifies illegal privilege transition.",
            events=[e3, e4],
            alerts=[a1],
            actions=[
                self.create_action(
                    ActionType.COLLECT_EVIDENCE,
                    "process",
                    str(suid_pid),
                    "Captured /proc/<pid>/status and stack trace of escalating process",
                    alert_id=a1.alert_id,
                )
            ],
            posture_impact=-30,
            delay_ms=350,
        )

        # Step 3: Shadow file access attempt & Immediate Termination
        e5 = self.create_event(
            syscall=SyscallType.OPENAT,
            pid=suid_pid,
            comm="exploit",
            uid=0,
            file_path="/etc/shadow",
            return_code=-13,
        )
        a2 = self.create_alert(
            rule_name="sensitive_shadow_read",
            title="🛡️ Sensitive Credential Store Read Attempt (/etc/shadow)",
            description=f"Elevated PID {suid_pid} attempted opening '/etc/shadow' for credential exfiltration.",
            severity=Severity.CRITICAL,
            risk_score=99,
            primary_event=e5,
            recommended_action=ActionType.KILL_PROCESS,
        )
        step3 = SimulationStep(
            step_number=3,
            phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            title="Credential Harvest Attempt & Kernel Kill",
            description="Process attempts reading password hashes. Kernel defense blocks syscall and instantly terminates process tree.",
            events=[e5],
            alerts=[a2],
            actions=[
                self.create_action(
                    ActionType.KILL_PROCESS,
                    "process",
                    str(suid_pid),
                    "Issued SIGKILL to terminate compromised process",
                    alert_id=a2.alert_id,
                ),
                self.create_action(
                    ActionType.SUSPEND_PROCESS,
                    "process",
                    str(low_pid),
                    "Suspended parent shell session PID 8110 for forensic investigation",
                    alert_id=a2.alert_id,
                ),
            ],
            posture_impact=0,
            delay_ms=400,
        )

        return [step1, step2, step3]
