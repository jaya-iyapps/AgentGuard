"""Explicit PostgreSQL runtime configuration; SQLite is only used by isolated tests."""

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker


def postgres_sessions(database_url: str, timeout: int = 3) -> sessionmaker:
    if not database_url:
        raise ValueError("AG_DATABASE_URL must be configured for PostgreSQL context")
    url = make_url(database_url)
    if url.drivername != "postgresql+psycopg":
        raise ValueError("Production context requires postgresql+psycopg; SQLite is test-only")
    engine = create_engine(
        url,
        pool_pre_ping=True,
        pool_timeout=timeout,
        isolation_level="REPEATABLE READ",
        connect_args={
            "connect_timeout": timeout,
            "options": f"-c statement_timeout={timeout * 1000}",
        },
        hide_parameters=True,
    )
    return sessionmaker(engine, expire_on_commit=False)
