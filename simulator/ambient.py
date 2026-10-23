"""
simulator.ambient — Ambient telemetry generator for benign background noise
============================================================================
Produces realistic benign kernel events (systemd, cron, sshd, nginx, etc.)
so the simulation environment behaves like an active operating system.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import NotRequired, TypedDict
from uuid import uuid4

from klcds.core.models import KernelEvent, SyscallType


class BenignService(TypedDict):
    comm: str
    pid: int
    uid: int
    syscall: SyscallType
    cmd: str
    file: NotRequired[str | None]
    src_ip: NotRequired[str | None]
    dst_ip: NotRequired[str | None]
    dst_port: NotRequired[int | None]


BENIGN_SERVICES: list[BenignService] = [
    {
        "comm": "systemd-journal",
        "pid": 290,
        "uid": 0,
        "syscall": SyscallType.OPENAT,
        "file": "/var/log/journal/system.journal",
        "cmd": "/usr/lib/systemd/systemd-journald",
    },
    {
        "comm": "cron",
        "pid": 512,
        "uid": 0,
        "syscall": SyscallType.EXECVE,
        "file": None,
        "cmd": "/usr/sbin/cron -f",
    },
    {
        "comm": "nginx",
        "pid": 341,
        "uid": 33,
        "syscall": SyscallType.CONNECT,
        "file": None,
        "cmd": "nginx: worker process",
        "src_ip": "10.0.0.45",
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
    },
    {
        "comm": "sshd",
        "pid": 8801,
        "uid": 0,
        "syscall": SyscallType.SSH_AUTH,
        "file": None,
        "cmd": "sshd: user [priv]",
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
    },
    {
        "comm": "postgres",
        "pid": 1104,
        "uid": 105,
        "syscall": SyscallType.OPENAT,
        "file": "/var/lib/postgresql/data/base/16384/2610",
        "cmd": "postgres: checkpointer",
    },
    {
        "comm": "rsyslogd",
        "pid": 418,
        "uid": 104,
        "syscall": SyscallType.OPENAT,
        "file": "/var/log/syslog",
        "cmd": "/usr/sbin/rsyslogd -n",
    },
    {
        "comm": "python3",
        "pid": 2180,
        "uid": 1000,
        "syscall": SyscallType.EXECVE,
        "file": None,
        "cmd": "python3 worker.py --batch-size=64",
    },
]


def generate_ambient_event() -> KernelEvent:
    """Generate a single benign background event."""
    sample: BenignService = random.choice(BENIGN_SERVICES)
    dst_port = sample.get("dst_port")
    return KernelEvent(
        event_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        syscall=sample["syscall"],
        pid=sample["pid"],
        ppid=1,
        uid=sample["uid"],
        gid=sample["uid"],
        comm=sample["comm"],
        exe_path=f"/usr/bin/{sample['comm']}",
        cmdline=sample["cmd"],
        file_path=sample.get("file"),
        src_ip=sample.get("src_ip"),
        dst_ip=sample.get("dst_ip"),
        dst_port=dst_port,
        protocol="TCP" if dst_port else None,
        return_code=0,
    )
