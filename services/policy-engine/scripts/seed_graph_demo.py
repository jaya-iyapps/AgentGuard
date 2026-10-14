"""Opt-in graph metadata only. Does not read/write any private runtime credentials."""

import argparse
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from agentguard_backend.config import Settings
from agentguard_backend.db.engine import postgres_sessions
from agentguard_backend.db.provenance import InconsistentProvenance
from agentguard_backend.graph.demo import seed_graph_demo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--synthetic-demo",
        required=True,
        action="store_true",
        help="Explicitly acknowledge synthetic development fixture import",
    )
    parser.parse_args()
    settings = Settings()
    if settings.env != "development":
        raise SystemExit("Synthetic graph import is restricted to AG_ENV=development")
    sessions = postgres_sessions(
        settings.database_url.get_secret_value(), settings.database_timeout_seconds
    )
    try:
        # The installed package's __file__ is outside the repository in a container.
        fixture_path = Path(__file__).resolve().parents[3] / "demo/fixtures/capability-graph.json"
        seed_graph_demo(sessions, fixture_path=fixture_path)
    except (ValueError, InconsistentProvenance) as error:
        raise SystemExit(str(error)) from None
    except SQLAlchemyError:
        raise SystemExit(
            "Trusted development database unavailable; no graph fixture imported"
        ) from None
    finally:
        sessions.kw["bind"].dispose()
    print(
        "Imported synthetic graph declarations only; no permissions, executions or credentials created."
    )


if __name__ == "__main__":
    main()
