"""Run all three scaffold processes; stop the children together on Ctrl-C."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    if not (ROOT / "apps/dashboard/node_modules/vite").exists():
        raise SystemExit("Frontend dependencies are missing. Run make setup first.")
    commands = [
        [
            sys.executable,
            "-m",
            "uvicorn",
            "agentguard_backend.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
            "--reload",
            "--reload-dir",
            "services/policy-engine",
            "--reload-dir",
            "packages/contracts",
        ],
        [
            sys.executable,
            "-m",
            "uvicorn",
            "agentguard_gateway.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8001",
            "--reload",
            "--reload-dir",
            "services/mcp-gateway",
            "--reload-dir",
            "packages/contracts",
        ],
        ["npm", "--prefix", "apps/dashboard", "run", "dev"],
    ]
    processes = []

    def stop(_signum=None, _frame=None):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        for command in commands:
            processes.append(subprocess.Popen(command, cwd=ROOT, start_new_session=True))
        print("Dashboard: http://localhost:5173 · backend: :8000 · gateway shell: :8001", flush=True)
        while True:
            for process in processes:
                if process.poll() is not None:
                    raise SystemExit(f"Development process exited with status {process.returncode}.")
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


if __name__ == "__main__":
    main()
