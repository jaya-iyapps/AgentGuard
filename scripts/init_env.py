"""Create a non-secret local .env once without replacing teammate settings."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
target = ROOT / ".env"
try:
    with target.open("x") as stream:
        stream.write((ROOT / ".env.example").read_text())
    print("Created .env (development configuration only, no credentials).")
except FileExistsError:
    print("Existing .env preserved.")
