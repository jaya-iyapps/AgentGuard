"""Check already-running development processes without changing application state."""

import json
from urllib.request import urlopen

for name, url in (
    ("backend", "http://127.0.0.1:8000/health"),
    ("gateway scaffold", "http://127.0.0.1:8001/health"),
):
    with urlopen(url, timeout=5) as response:
        body = json.load(response)
        assert body["status"] == "ok" and body["enforcement_enabled"] is False
        print(f"PASS {name}: health is reachable, enforcement disabled")
with urlopen("http://127.0.0.1:5173", timeout=5) as response:
    assert "AgentGuard" in response.read().decode()
    print("PASS frontend: HTML entry point reachable")
with urlopen("http://127.0.0.1:5173/api/health", timeout=5) as response:
    assert json.load(response)["service"] == "agentguard-backend"
    print("PASS frontend development proxy → backend")
