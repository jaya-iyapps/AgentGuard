"""Seed an explicitly configured, migrated, empty PostgreSQL development database."""

from pathlib import Path

from agentguard_backend.config import Settings
from agentguard_backend.db.engine import postgres_sessions
from agentguard_backend.db.seed import seed_context
from agentguard_backend.pdp.models import ContextDocument

settings = Settings()
if settings.env != "development" or not settings.pdp_context_path:
    raise SystemExit("Development context path must be explicitly configured before seeding")
document = ContextDocument.model_validate_json(Path(settings.pdp_context_path).read_text())
sessions = postgres_sessions(
    settings.database_url.get_secret_value(), settings.database_timeout_seconds
)
try:
    seed_context(sessions, document)
finally:
    sessions.kw["bind"].dispose()
print("Seeded trusted synthetic metadata and credential hashes; local credential files unchanged.")
