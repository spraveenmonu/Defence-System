"""
simulator.scenarios — Registry of cybersecurity attack & defense simulations
============================================================================
"""

from __future__ import annotations

from typing import Any, Type

from simulator.scenarios.base import BaseScenario
from simulator.scenarios.bruteforce import BruteForceScenario
from simulator.scenarios.cryptominer import CryptoMinerScenario
from simulator.scenarios.ddos import DDoSScenario
from simulator.scenarios.portscan import PortScanScenario
from simulator.scenarios.privesc import PrivEscScenario
from simulator.scenarios.ransomware import RansomwareScenario
from simulator.scenarios.trojan import TrojanScenario

SCENARIO_CLASSES: dict[str, Type[BaseScenario]] = {
    "ransomware": RansomwareScenario,
    "trojan": TrojanScenario,
    "portscan": PortScanScenario,
    "bruteforce": BruteForceScenario,
    "privesc": PrivEscScenario,
    "cryptominer": CryptoMinerScenario,
    "ddos": DDoSScenario,
}


def get_scenario(scenario_id: str) -> BaseScenario:
    """Retrieve an instantiated scenario by identifier."""
    cls = SCENARIO_CLASSES.get(scenario_id.lower())
    if not cls:
        raise KeyError(
            f"Unknown scenario '{scenario_id}'. Available: {list(SCENARIO_CLASSES.keys())}"
        )
    return cls()


def list_available_scenarios() -> list[dict[str, Any]]:
    """Return metadata dicts for all available scenarios."""
    scenarios = []
    for cls in SCENARIO_CLASSES.values():
        instance = cls()
        scenarios.append(instance.metadata.model_dump())
    return scenarios
