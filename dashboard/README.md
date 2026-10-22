# KLCDS Simulation Command Center

The Cyberpunk Glassmorphism Command Center is located at [`index.html`](../index.html) in the project root.

## Running the Command Center

### Method 1: Integrated Simulator Server (Recommended)
Runs the FastAPI telemetry backend and WebSocket broadcaster with automatic browser launch:
```bash
python -m klcds.cli.main web
```
Dashboard will be available at: `http://localhost:8000`

### Method 2: Standalone Mode
Double-click or open `index.html` directly in any modern web browser. The standalone client engine simulates ambient telemetry, audio FX, and scenario playbacks client-side without any backend prerequisites.
