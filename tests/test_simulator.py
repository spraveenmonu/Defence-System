"""
tests.test_simulator — Test suite for Cyber Defense System Simulator
=====================================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest

from klcds.core.config import KLCDSConfig
from klcds.core.database import Database
from simulator.ambient import generate_ambient_event
from simulator.runner import SimulationRunner
from simulator.scenarios import (
    SCENARIO_CLASSES,
    get_scenario,
    list_available_scenarios,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Generator[Database, None, None]:
    config = KLCDSConfig()
    config.database.sqlite_path = str(tmp_path / "sim_test.db")
    db = Database(config)
    db.connect()
    db.initialize()
    yield db
    db.close()


class TestScenarioRegistry:
    def test_list_all_scenarios(self) -> None:
        scenarios = list_available_scenarios()
        assert len(scenarios) == 7
        ids = {s["id"] for s in scenarios}
        assert "ransomware" in ids
        assert "trojan" in ids
        assert "portscan" in ids
        assert "bruteforce" in ids
        assert "privesc" in ids
        assert "cryptominer" in ids
        assert "ddos" in ids

    def test_get_scenario(self) -> None:
        scen = get_scenario("ransomware")
        assert scen.metadata.id == "ransomware"
        assert len(scen.metadata.mitre_techniques) > 0

    def test_get_unknown_scenario_raises(self) -> None:
        with pytest.raises(KeyError):
            get_scenario("non_existent_exploit")


class TestScenarioExecution:
    @pytest.mark.parametrize("scenario_id", list(SCENARIO_CLASSES.keys()))
    def test_run_scenario_in_memory(self, scenario_id: str) -> None:
        runner = SimulationRunner(safe_mode=True)
        res = runner.execute_scenario(scenario_id)
        assert res.scenario_id == scenario_id
        assert res.total_events > 0
        assert res.total_alerts > 0
        assert res.contained is True
        assert len(res.actions_taken) > 0
        assert all(a["safe_mode"] is True for a in res.actions_taken)

    def test_enforce_mode_actions(self) -> None:
        runner = SimulationRunner(safe_mode=False)
        res = runner.execute_scenario("trojan")
        assert all(a["executed"] is True for a in res.actions_taken)
        assert all(a["safe_mode"] is False for a in res.actions_taken)


class TestSimulatorDatabaseIntegration:
    def test_scenario_persists_to_db(self, temp_db: Database) -> None:
        runner = SimulationRunner(db=temp_db, safe_mode=True)
        res = runner.execute_scenario("ransomware")

        stats = temp_db.get_stats()
        assert stats["total_events"] == res.total_events
        assert stats["total_alerts"] == res.total_alerts
        assert stats["critical_alerts"] > 0

        # Query recent events
        events = temp_db.get_recent_events(limit=50)
        assert len(events) == res.total_events

        # Query recent alerts
        alerts = temp_db.get_recent_alerts(limit=50)
        assert len(alerts) == res.total_alerts

    def test_reset_simulation_state(self, temp_db: Database) -> None:
        runner = SimulationRunner(db=temp_db, safe_mode=True)
        runner.execute_scenario("bruteforce")
        assert temp_db.get_stats()["total_events"] > 0

        runner.reset_state()
        stats = temp_db.get_stats()
        assert stats["total_events"] == 0
        assert stats["total_alerts"] == 0
        assert runner._current_posture_score == 98


class TestAmbientTelemetry:
    def test_ambient_event_generation(self) -> None:
        for _ in range(10):
            evt = generate_ambient_event()
            assert evt.event_id is not None
            assert evt.comm != ""
            assert evt.pid > 0
