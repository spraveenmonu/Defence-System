# KLCDS — Kernel-Level Cyber Defense System

<p align="center">
  <img src="docs/assets/klcds_banner.png" alt="KLCDS Banner" width="800">
</p>

<p align="center">
  <strong>A defensive host-security tool for Linux that monitors kernel-level activity, detects attacks, and automatically contains them.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#detection-rules">Rules</a> •
  <a href="#safety">Safety</a> •
  <a href="#roadmap">Roadmap</a>
</p>

---

## Overview

KLCDS is a **defensive-only** host intrusion detection and response system (HIDRS) that operates at the kernel level using **eBPF** probes. It captures syscall-level telemetry (process execution, file operations, network connections, privilege changes, kernel module loading), runs real-time detection rules, and can automatically contain threats — all while maintaining strict safety guarantees.

> **⚠️ This tool is designed for use in isolated VMs only.** It is a final-year academic project. Never deploy on production systems without thorough testing.

## Features

| Layer | Capability |
|-------|-----------|
| **Kernel Monitoring** | eBPF tracepoints/kprobes for `execve`, `openat`, `unlink`, `rename`, `connect`, `bind`, `setuid/setgid/capset`, `init_module/finit_module/delete_module` |
| **Log Integration** | auditd + journald for SSH, sudo, PAM, USB events |
| **Malware Detection** | ClamAV, YARA rules, SHA-256 hash blocklists, behavioral analysis |
| **Ransomware Shield** | Entropy analysis, mass-rename detection, canary/decoy files, backup tampering detection |
| **File Integrity** | SHA-256 baseline monitoring of critical system files |
| **Network Analysis** | Port scanning, service enumeration, SSH brute-force detection, suspicious outbound connections |
| **Secret Scanner** | Finds leaked keys, tokens, and passwords in files |
| **ML Anomaly Detection** | Isolation Forest on process/network behavioral features |
| **Risk Scoring** | Composite 0–100 risk score per alert and system-wide posture score |
| **Automated Response** | Kill/freeze processes, quarantine files, block IPs via nftables, disable cron/systemd units |
| **Incident Reporting** | HTML/PDF export with process trees, timelines, and evidence |
| **Dashboard** | React cyberpunk UI with real-time event streaming, alert management, and posture visualization |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        KLCDS Architecture                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                   Layer 3: Dashboard + CLI                       │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │    │
│  │  │ React UI │  │ FastAPI  │  │   CLI    │  │ Report Export │  │    │
│  │  │ Cyberpunk│  │ Backend  │  │  (click) │  │  (HTML/PDF)   │  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └───────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ▲                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │              Layer 2: User-Space Defense Engine                   │    │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │    │
│  │  │ Event   │ │  Rule    │ │  Risk    │ │    Response      │   │    │
│  │  │Normalize│ │  Engine  │ │  Scorer  │ │   Controller     │   │    │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────────────┘   │    │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │    │
│  │  │ Process │ │ ClamAV / │ │Ransomware│ │  ML Anomaly      │   │    │
│  │  │  Tree   │ │  YARA    │ │  Shield  │ │  Detector (IF)   │   │    │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ▲                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │            Layer 1: Kernel Monitoring (eBPF + Logs)              │    │
│  │  ┌──────────────────────────────┐  ┌────────────────────────┐  │    │
│  │  │  eBPF Probes (C / libbpf)   │  │  auditd / journald     │  │    │
│  │  │  • tracepoints / kprobes    │  │  • SSH auth events      │  │    │
│  │  │  • ring buffer → user space │  │  • sudo / PAM / USB     │  │    │
│  │  └──────────────────────────────┘  └────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ▲                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                      Linux Kernel                                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- **OS:** Ubuntu 22.04 or 24.04 LTS (inside an isolated VM)
- **Kernel:** 5.15+ (for eBPF ring buffer support)
- **Python:** 3.11+
- **Privileges:** root or `CAP_BPF` + `CAP_PERFMON` for eBPF probes

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/your-org/klcds.git
cd klcds

# Run the setup script (as root, inside your VM)
sudo bash setup.sh
```

### Manual Setup

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3.11 python3.11-venv bpfcc-tools libbpf-dev \
    clamav clamav-daemon nftables auditd nmap sqlite3

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install KLCDS
pip install -e .

# Initialize the database
klcds init-db
```

## Usage

```bash
# Activate the virtual environment
source venv/bin/activate

# Show system status
klcds status

# Initialize / migrate the database
klcds init-db

# Dump effective configuration
klcds config-dump

# View recent kernel events
klcds events -n 50
klcds events --syscall execve
klcds events --pid 1234
klcds events --live              # Real-time stream (Phase 2)

# View alerts
klcds alerts
klcds alerts --severity critical
klcds alerts --status new

# Show security posture score
klcds posture

# Start the defense engine (safe mode — default)
klcds run

# Start with enforcement enabled (⚠️ VM only!)
klcds run --enforce
```

## Configuration

KLCDS loads configuration from (highest priority first):

1. CLI `--config` flag
2. `KLCDS_CONFIG` environment variable
3. `./klcds.yaml` (project directory)
4. `/etc/klcds/klcds.yaml` (system-wide)
5. Built-in defaults

See [`klcds.yaml`](klcds.yaml) for the full reference with all defaults documented.

## Detection Rules

Rules are defined in YAML and live in `/etc/klcds/rules/` (built-in) and `/etc/klcds/rules.d/` (user-added). Example:

```yaml
- id: ransomware_mass_rename
  name: "Mass File Rename — Ransomware Indicator"
  condition: "rename_events >= 20 within 10s from same_pid"
  severity: critical
  action: suspend_process
  attack_type: ransomware
  enabled: true
  tags: [ransomware, file_ops, critical]
```

### Built-in Rule Categories

| Category | Rules | Examples |
|----------|-------|---------|
| Ransomware | 5 | Mass rename, high entropy writes, canary file touch, backup tampering |
| Malware | 4 | Execution from /tmp, deleted binary, download-execute chain |
| Brute Force | 1 | SSH brute force (10 failures / 60s per IP) |
| Reconnaissance | 1 | Port scan detection |
| C2 Communication | 1 | Suspicious outbound ports (4444, 5555, 1337, etc.) |
| Persistence | 3 | Cron modification, systemd unit creation, shell RC modification |
| Privilege Escalation | 2 | setuid/setgid to root, kernel module loading |
| Evasion | 2 | Logging service tampering, security tool killed |
| File Integrity | 2 | Critical file changes, /etc/shadow read by non-root |

## Safety

### Safe Mode (Default: ON)

All automated response actions are **logged only** by default. No process is killed, no file is quarantined, no IP is blocked — KLCDS only records *"would have done X"*.

To enable enforcement:
```bash
klcds run --enforce
```

### Allowlist

Trusted processes and paths are never targeted by automated responses:
- `systemd` (PID 1)
- `apt` / `dpkg` (package managers)
- `klcds` (the tool itself)
- All binaries in `/usr/bin`, `/usr/sbin`, `/usr/lib`

### Protected Processes

KLCDS will **never**:
- Kill PID 1 or kernel threads
- Kill its own processes
- Execute real malware or encryption code

### Reversibility

Every automated action includes a reverse command:
- Quarantine → restore from quarantine ledger
- IP block → `nft delete rule` command logged
- Process freeze → `kill -CONT` command logged

## Project Structure

```
klcds/
├── klcds/                  # Python package
│   ├── __init__.py
│   ├── core/               # Config, database, models, logging
│   │   ├── config.py       # Pydantic config with YAML loading
│   │   ├── database.py     # SQLite layer (PG-migration-ready)
│   │   ├── models.py       # Event, Alert, Action data models
│   │   └── logging_setup.py
│   ├── collectors/          # eBPF probes, auditd/journald consumers
│   ├── detection/           # Rule engine, process tree, risk scorer, ML
│   ├── scanners/            # ClamAV, YARA, hash lists, port scanner
│   ├── response/            # Containment, quarantine, alerting
│   ├── api/                 # FastAPI backend
│   └── cli/                 # Click CLI
│       └── main.py
├── ebpf/                    # C eBPF probe source code
├── rules/                   # YAML detection rules
├── yara/                    # YARA rule files
├── dashboard/               # React cyberpunk dashboard
├── tests/                   # pytest test suite
├── docs/                    # Documentation & diagrams
├── simulator/               # Safe attack simulator scripts
├── klcds.yaml               # Default configuration
├── pyproject.toml           # Build & dependency config
├── requirements.txt         # Pip dependencies
├── setup.sh                 # Ubuntu setup script
└── README.md
```

## Development Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ Complete | Repo structure, SQLite schema, config, event models |
| 2 | 🔲 Next | eBPF collector → ring buffer → Python consumer → DB |
| 3 | 🔲 | Rule engine + process tree + risk scoring |
| 4 | 🔲 | Port scanner, FIM, ClamAV/YARA, secret scanner |
| 5 | 🔲 | Ransomware shield + canary files + simulator |
| 6 | 🔲 | Response engine (safe mode → enforce mode) |
| 7 | 🔲 | FastAPI backend + React dashboard |
| 8 | 🔲 | Isolation Forest anomaly detection |
| 9 | 🔲 | Test suite, demo scenarios, NIST CSF mapping |

## NIST Cybersecurity Framework Mapping

| NIST Function | KLCDS Component |
|---------------|-----------------|
| **Identify** | System inventory, posture scoring, service enumeration |
| **Protect** | FIM baselines, canary files, allowlists, secret scanning |
| **Detect** | eBPF monitoring, rule engine, ML anomaly detection, ClamAV/YARA |
| **Respond** | Automated containment, IP blocking, process kill/freeze, alerting |
| **Recover** | Quarantine restore, backup verification, incident reports |

## Kernel & Privilege Requirements

| Feature | Minimum Kernel | Privileges Needed |
|---------|---------------|-------------------|
| eBPF ring buffer | 5.8+ | `CAP_BPF` + `CAP_PERFMON` (or root) |
| eBPF tracepoints | 5.5+ | Same |
| nftables blocking | 3.13+ | `CAP_NET_ADMIN` (or root) |
| auditd | 2.6+ | root for `auditctl` |
| ClamAV scanning | Any | `clamav` group membership |

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for academic purposes. Defensive use only. Never deploy without understanding the implications.</sub>
</p>
