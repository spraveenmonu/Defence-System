# KLCDS — Cyber Defense Simulation Platform

<p align="center">
  <strong>A high-fidelity, cross-platform Cyber Defense Simulation System modeling kernel-level telemetry, adversary kill chains, and autonomous countermeasures.</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#scenarios">Scenarios</a> •
  <a href="#building-projects">Building Projects On Top</a> •
  <a href="#command-center">Web Command Center</a> •
  <a href="#cli-reference">CLI Reference</a> •
  <a href="#architecture">Architecture</a>
</p>

---

## Overview

**KLCDS Simulator** transforms complex host-security and kernel-level defense concepts into an accessible, safe, and interactive simulation platform. Instead of requiring dangerous live malware, dedicated Linux VMs, or raw kernel root privileges, KLCDS generates realistic syscall events, network telemetry, and log indicators to simulate attacks and defense mechanisms in real time.

This platform is specifically designed as an **extensible foundation** on which students, researchers, and engineers can build custom cybersecurity projects—such as SIEM integrations, detection rule testing, ML anomaly classifiers, and automated incident response pipelines.

### Key Capabilities

| Component | Capabilities |
|-----------|--------------|
| **Simulation Engine** | 7 pre-built adversary scenarios spanning the entire Cyber Kill Chain |
| **Realistic Telemetry** | High-fidelity synthetic syscall streams (`execve`, `openat`, `rename`, `connect`, `setuid`, etc.) |
| **Autonomous Defense** | Modeled countermeasures: process suspension, IP null-routing, canary triggers, and file quarantine |
| **Interactive Dashboard** | Cyberpunk Web Command Center with dual Red vs Blue telemetry streams and MITRE ATT&CK matrix |
| **Streaming & APIs** | WebSocket broadcast (`/ws/stream`) and REST API for telemetry ingestion into your own tools |
| **Cross-Platform** | 100% pure Python + Web standards; runs seamlessly on **Windows, macOS, and Linux** |

---

## Quickstart

### 1. Installation

Clone the repository and install dependencies:

```bash
# Clone the repository
git clone https://github.com/spraveenmonu/Defence-System.git
cd "Defence-System"

# Install dependencies (Python 3.10+)
pip install -r requirements.txt
```

### 2. Run a Simulation via CLI

List available simulation scenarios and run your first attack:

```bash
# List all simulated attack scenarios
python -m klcds.cli.main sim list

# Execute the Ransomware scenario
python -m klcds.cli.main sim run ransomware

# View generated alerts
python -m klcds.cli.main alerts

# View overall security posture
python -m klcds.cli.main posture
```

### 3. Launch the Interactive Web Command Center

Start the FastAPI simulation server and open the Cyberpunk Command Center in your browser:

```bash
# Starts API server on http://localhost:8000 and opens dashboard
python -m klcds.cli.main web
```

> **Standalone Mode:** You can also simply double-click or open `index.html` directly in any web browser! The standalone engine includes built-in audio synthesizer FX, live synthetic event generation, and scenario playback even without running the Python server.

---

## Pre-Built Simulation Scenarios

The simulator includes 7 scenarios mapped to MITRE ATT&CK techniques:

| Scenario ID | Attack Vector | MITRE Technique | Defensive Countermeasure |
|-------------|---------------|-----------------|--------------------------|
| `ransomware` | Mass File Encryption & Canary Breach | **T1486**, **T1490** | Canary trap trigger, Shannon entropy alert, process `SIGKILL`, shadow copy protection |
| `trojan` | Dropper Execution & C2 Shell | **T1204**, **T1071**, **T1053** | Execution quarantine, crontab persistence purge, C2 egress IP ban |
| `portscan` | Network Reconnaissance Sweep | **T1046** | Port sweep velocity threshold trigger, dynamic firewall null-route |
| `bruteforce` | SSH Credential Stuffing | **T1110** | PAM lockout emulation, brute-force source IP block |
| `privesc` | SUID Abuse & Root Transition | **T1068**, **T1548** | Unauthorized `setuid(0)` syscall block, parent process termination |
| `cryptominer` | Background Mining & CPU Drain | **T1496** | Stratum protocol detection, ML anomaly isolation, worker eviction |
| `ddos` | TCP SYN Direct Connection Flood | **T1498** | Socket queue backlog monitoring, automated SYN cookie mitigation |

---

## Building Projects On Top of KLCDS

KLCDS is engineered as a foundational substrate for cybersecurity research and application development. Here are three primary ways to build projects on top of it:

### 1. Build Custom Attack & Defense Scenarios

You can create custom scenarios by subclassing `BaseScenario`:

```python
# simulator/scenarios/my_custom_attack.py
from simulator.scenarios.base import BaseScenario
from simulator.models import SimulationScenarioMetadata, KillChainPhase, ScenarioCategory

class CustomAttackScenario(BaseScenario):
    @property
    def metadata(self) -> SimulationScenarioMetadata:
        return SimulationScenarioMetadata(
            id="custom_exploit",
            name="Buffer Overflow & Memory Tamper",
            category=ScenarioCategory.EXPLOITATION,
            description="Simulates memory corruption and shellcode injection.",
            kill_chain_phases=[KillChainPhase.EXPLOITATION],
            mitre_attack_ids=["T1203"],
            posture_penalty=20
        )

    def execute(self, session_id: str):
        # 1. Generate attacker syscall events
        evt = self.create_event(
            session_id=session_id,
            syscall="mprotect",
            comm="vulnerable_app",
            cmdline="./vulnerable_app --payload exploit.bin",
            return_code=-1
        )
        
        # 2. Trigger defensive alert
        alert = self.create_alert(
            rule_id="mem_protect_violation",
            rule_name="Writable & Executable Memory Segment Detected",
            attack_type="exploitation",
            description="Process attempted RWX memory allocation.",
            severity="critical",
            risk_score=85,
            event_ids=[evt.id]
        )
        
        # 3. Apply containment action
        action = self.create_action(
            alert_id=alert.id,
            action_type="terminate_process",
            target=str(evt.pid),
            status="executed",
            parameters={"signal": "SIGKILL"}
        )
        
        return self._build_result(session_id, [evt], [alert], [action])
```

Register your scenario in `simulator/scenarios/__init__.py` and it immediately becomes executable via CLI, API, and the Web UI.

### 2. Stream Live Telemetry via WebSockets

Subscribe your own microservices, SIEM clients, or alerting bots to the real-time telemetry stream:

```python
import asyncio
import websockets
import json

async def monitor_defense_events():
    uri = "ws://localhost:8000/ws/stream"
    async with websockets.connect(uri) as websocket:
        print("[+] Connected to KLCDS Telemetry Stream")
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            
            if data["type"] == "kernel_event":
                evt = data["event"]
                print(f"[SYSCALL] {evt['comm']} -> {evt['syscall']} (PID: {evt['pid']})")
                
            elif data["type"] == "alert":
                alert = data["alert"]
                print(f"[ALERT] {alert['severity'].upper()}: {alert['rule_name']}")

asyncio.run(monitor_defense_events())
```

### 3. Build & Train Machine Learning Models

Use the simulation engine's benign background telemetry generator (`simulator/ambient.py`) combined with attack scenario events to extract feature vectors and benchmark detection algorithms:
- **Isolation Forest / One-Class SVM** on process resource usage and syscall frequency.
- **Sequential Pattern Mining (LSTM / Markov Chains)** on process execution sequences.
- **Graph Neural Networks** on simulated process parent-child execution trees.

---

## Web Command Center Features

The Command Center (`index.html`) provides an interactive interface for demonstrating and testing defense mechanisms:

1. **Simulation Studio Control Bar:** Trigger scenarios with custom speed multipliers (0.5x, 1x, 2x, 5x), reset to baseline, launch custom payloads, or export incident reports.
2. **7-Stage Cyber Kill Chain Tracker:** Real-time visual tracking through Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, and Actions on Objectives.
3. **Dual Stream Terminal:** Split-screen view separating adversary attacks (Red Team) from autonomous defensive countermeasures (Blue Team).
4. **MITRE ATT&CK Matrix:** Interactive technique badges reflecting live detection and mitigation states.
5. **Acoustic Synthesizer:** Real-time audio feedback with custom cyber sound effects for alerts, clicks, and mitigations.
6. **Incident Report Generator:** Generate and download markdown forensic incident reports.

---

## CLI Reference

```bash
# General Commands
python -m klcds.cli.main status           # Show simulator database and engine status
python -m klcds.cli.main events -n 25     # Inspect recent simulated syscall events
python -m klcds.cli.main alerts           # Review security alerts and risk scores
python -m klcds.cli.main posture          # Calculate current security posture score (0-100)

# Simulation Management
python -m klcds.cli.main sim list         # Display all simulation scenarios and MITRE IDs
python -m klcds.cli.main sim run <id>     # Run a scenario (e.g., ransomware, trojan, portscan)
python -m klcds.cli.main sim reset        # Clear simulation events and restore baseline posture

# Web Server & UI
python -m klcds.cli.main web              # Start FastAPI server on port 8000 & launch browser
python -m klcds.cli.main web --port 8080  # Launch on custom port
python -m klcds.cli.main web --no-browser # Start server in headless/API mode
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│               KLCDS Cyber Defense Simulation Architecture              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                     Presentation Layer                         │   │
│   │   ┌───────────────────┐    ┌─────────────────┐                 │   │
│   │   │  Web Command      │    │    Rich CLI     │                 │   │
│   │   │  Center (HTML/JS) │    │   (Click/Rich)  │                 │   │
│   │   └───────────────────┘    └─────────────────┘                 │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                   │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                     API & Transport Layer                      │   │
│   │   ┌───────────────────┐    ┌─────────────────────────────────┐ │   │
│   │   │  FastAPI REST     │    │  WebSocket Broadcaster          │ │   │
│   │   │  (/api/scenarios) │    │  (ws://localhost:8000/ws/stream)│ │   │
│   │   └───────────────────┘    └─────────────────────────────────┘ │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                   │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                 Simulation & Defense Engine                    │   │
│   │   ┌───────────────────┐    ┌─────────────────────────────────┐ │   │
│   │   │ Simulation Runner │    │  Autonomous Defense Simulator   │ │   │
│   │   │ (scenarios/runner)│    │  (Canaries, Containment, Quaran)│ │   │
│   │   └───────────────────┘    └─────────────────────────────────┘ │   │
│   │   ┌───────────────────┐    ┌─────────────────────────────────┐ │   │
│   │   │ Ambient Telemetry │    │  Risk & Posture Scoring Engine  │ │   │
│   │   │ (benign noise)    │    │  (0-100 composite posture)      │ │   │
│   │   └───────────────────┘    └─────────────────────────────────┘ │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                   │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                   Data Persistence Layer                       │   │
│   │     SQLite Database (data/klcds.db) — Events, Alerts, Actions  │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Running Automated Tests

Run the full pytest suite to verify scenarios, data persistence, and runners:

```bash
python -m pytest tests -v
```

All 53 unit tests cover:
- Database initialization and cross-platform path handling
- Telemetry model serialization
- Execution of all 7 simulation scenarios
- Posture score calculation and state resets

---

## License

MIT License — see [LICENSE](LICENSE) for details. Built for cybersecurity education, research, and defensive software prototyping.
