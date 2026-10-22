"""
simulator.api — FastAPI application and WebSocket server for Cyber Defense Simulator
=====================================================================================
Exposes REST and WebSocket endpoints for controlling attack scenarios,
streaming telemetry in real time, and serving the web Command Center.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from klcds.core.config import load_config
from klcds.core.database import Database
from simulator.ambient import generate_ambient_event
from simulator.runner import SimulationRunner
from simulator.scenarios import get_scenario, list_available_scenarios

app = FastAPI(
    title="KLCDS Cyber Defense Simulator API",
    description="Interactive attack/defense scenario simulator with real-time kernel telemetry",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global database & simulation runner instances
_config = load_config()
_db = Database(_config)
_runner = SimulationRunner(db=_db, safe_mode=True)


@app.on_event("startup")
def on_startup() -> None:
    try:
        _db.connect()
        _db.initialize()
    except Exception as exc:
        print(f"[!] Warning: Database init fallback: {exc}")


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/scenarios")
def get_scenarios() -> list[dict[str, Any]]:
    """List all available attack scenarios with full metadata."""
    return list_available_scenarios()


@app.post("/api/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: str, safe_mode: Optional[bool] = None) -> dict[str, Any]:
    """Execute an attack scenario synchronously and return the results."""
    try:
        result = _runner.execute_scenario(scenario_id, safe_mode=safe_mode)
        return result.model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/events")
def get_events(limit: int = 100, syscall: Optional[str] = None, pid: Optional[int] = None) -> list[dict[str, Any]]:
    """Fetch the latest simulated kernel events from database."""
    return _db.get_recent_events(limit=limit, syscall=syscall, pid=pid)


@app.get("/api/alerts")
def get_alerts(limit: int = 50, severity: Optional[str] = None) -> list[dict[str, Any]]:
    """Fetch the latest defensive alerts from database."""
    return _db.get_recent_alerts(limit=limit, severity=severity)


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    """Return dashboard metrics, counts, and security posture score."""
    stats = _db.get_stats()
    stats["posture_score"] = _runner._current_posture_score
    stats["safe_mode"] = _runner.safe_mode
    return stats


@app.post("/api/reset")
def reset_simulation() -> dict[str, str]:
    """Reset the database and restore posture score to baseline."""
    _runner.reset_state()
    return {"status": "ok", "message": "Simulation environment reset to clean baseline"}


# ---------------------------------------------------------------------------
# WebSocket Real-Time Stream
# ---------------------------------------------------------------------------

class ActiveConnections:
    def __init__(self) -> None:
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        for ws in list(self.connections):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)


active_sockets = ActiveConnections()


@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket) -> None:
    """
    Bidirectional WebSocket feed. Streams ambient noise + scenario events,
    and accepts client commands (e.g. run_scenario, set_speed, reset).
    """
    await active_sockets.connect(websocket)
    try:
        # Welcome message
        await websocket.send_json({
            "type": "welcome",
            "message": "Connected to KLCDS Defense Simulator Stream",
            "posture": _runner._current_posture_score,
            "safe_mode": _runner.safe_mode,
        })

        async def ambient_heartbeat():
            while True:
                await asyncio.sleep(1.2)
                ambient_evt = generate_ambient_event()
                _db.insert_event(ambient_evt.dict_for_db())
                await websocket.send_json({
                    "type": "kernel_event",
                    "event": ambient_evt.dict_for_db(),
                    "ambient": True,
                })

        heartbeat_task = asyncio.create_task(ambient_heartbeat())

        while True:
            raw_msg = await websocket.receive_text()
            try:
                data = json.loads(raw_msg)
                action = data.get("action")

                if action == "run_scenario":
                    scen_id = data.get("scenario_id", "ransomware")
                    speed = float(data.get("speed", 1.0))
                    safe = data.get("safe_mode", _runner.safe_mode)

                    async for packet in _runner.stream_scenario(
                        scen_id, safe_mode=safe, speed_multiplier=speed
                    ):
                        await websocket.send_json(packet)

                elif action == "reset":
                    _runner.reset_state()
                    await websocket.send_json({
                        "type": "reset_complete",
                        "posture": _runner._current_posture_score,
                    })

                elif action == "toggle_safe_mode":
                    _runner.safe_mode = not _runner.safe_mode
                    await websocket.send_json({
                        "type": "safe_mode_update",
                        "safe_mode": _runner.safe_mode,
                    })

            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        active_sockets.disconnect(websocket)
    finally:
        if 'heartbeat_task' in locals() and not heartbeat_task.done():
            heartbeat_task.cancel()
        active_sockets.disconnect(websocket)


# ---------------------------------------------------------------------------
# Dashboard UI Delivery
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the Cyber Defense Command Center dashboard."""
    index_path = Path(__file__).resolve().parent.parent / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>KLCDS Simulator API running. index.html not found.</h1>")
