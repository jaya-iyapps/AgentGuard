"""Alembic supports a supplied test connection or an explicitly configured PostgreSQL URL."""

from alembic import context

from agentguard_backend.config import Settings
from agentguard_backend.db.engine import postgres_sessions
from agentguard_backend.db.models import Base

config = context.config


def database_url() -> str:
    url = config.attributes.get("database_url") or Settings().database_url.get_secret_value()
    if not url:
        raise RuntimeError("Set AG_DATABASE_URL before running migrations")
    return url


def run(connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    context.configure(
        url=database_url(), target_metadata=Base.metadata, literal_binds=True, compare_type=True
    )
    with context.begin_transaction():
        context.run_migrations()
elif config.attributes.get("connection") is not None:
    run(config.attributes["connection"])
else:
    engine = postgres_sessions(database_url(), Settings().database_timeout_seconds).kw["bind"]
    try:
        with engine.connect() as connection:
            run(connection)
    finally:
        engine.dispose()
