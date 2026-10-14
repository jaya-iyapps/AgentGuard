import io
import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from agentguard_backend.db.models import Base

CONFIG_PATH = Path(__file__).resolve().parents[1] / "alembic.ini"


def round_trip(connection):
    config = Config(str(CONFIG_PATH))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")
    assert set(Base.metadata.tables) <= set(inspect(connection).get_table_names())
    assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
    assert (
        connection.scalar(text("SELECT version_num FROM alembic_version"))
        == ScriptDirectory.from_config(config).get_current_head()
    )
    command.downgrade(config, "base")
    assert not set(Base.metadata.tables) & set(inspect(connection).get_table_names())
    command.upgrade(config, "head")
    assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []


def test_migration_upgrade_downgrade_upgrade(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.sqlite3'}")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            round_trip(connection)
    finally:
        engine.dispose()


def test_graph_migration_preserves_existing_pdp_rows(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.sqlite3'}")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            config = Config(str(CONFIG_PATH))
            config.attributes["connection"] = connection
            command.upgrade(config, "0001_trusted_context")
            connection.execute(
                text(
                    "INSERT INTO pdp_principals (id, status, created_at) VALUES ('legacy-agent', 'ACTIVE', CURRENT_TIMESTAMP)"
                )
            )
            for identifier, origin, resource_type in [
                ("legacy-case", "SOURCE", "case"),
                ("legacy-report", "DERIVED", "report"),
            ]:
                connection.execute(
                    text(
                        "INSERT INTO pdp_resources (id, type, owner_principal_id, classification, origin, created_at) VALUES (:id, :type, 'legacy-agent', 'CONFIDENTIAL', :origin, CURRENT_TIMESTAMP)"
                    ),
                    {"id": identifier, "type": resource_type, "origin": origin},
                )
            connection.execute(
                text(
                    "INSERT INTO pdp_provenance_edges (parent_id, child_id, created_at) VALUES ('legacy-case', 'legacy-report', CURRENT_TIMESTAMP)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO pdp_permissions (id, principal_id, action, resource_id, status) VALUES ('legacy-permission', 'legacy-agent', 'case.read', 'legacy-case', 'ACTIVE')"
                )
            )
            command.upgrade(config, "head")
            assert connection.execute(
                text("SELECT evidence, evidence_ref FROM pdp_provenance_edges")
            ).one() == ("declared", None)
            assert (
                connection.scalar(
                    text("SELECT status FROM pdp_permissions WHERE id = 'legacy-permission'")
                )
                == "ACTIVE"
            )
            command.downgrade(config, "0001_trusted_context")
            assert "graph_destinations" not in inspect(connection).get_table_names()
            assert connection.execute(
                text("SELECT parent_id, child_id FROM pdp_provenance_edges")
            ).one() == ("legacy-case", "legacy-report")
            command.upgrade(config, "head")
            assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
    finally:
        engine.dispose()


def test_postgresql_migration_sql_compiles_without_a_server():
    output = io.StringIO()
    config = Config(str(CONFIG_PATH), output_buffer=output)
    config.attributes["database_url"] = "postgresql+psycopg://migration-only"
    command.upgrade(config, "head", sql=True)
    sql = output.getvalue()
    for table in Base.metadata.tables:
        assert f"CREATE TABLE {table}" in sql
    assert "TIMESTAMP WITH TIME ZONE" in sql
    assert "FOREIGN KEY" in sql


def test_real_postgresql_migration_round_trip():
    url = os.getenv("AG_TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "Set AG_TEST_DATABASE_URL for an explicitly authorized PostgreSQL test database"
        )
    engine = create_engine(url, hide_parameters=True)
    schema = "pdp_test_" + uuid.uuid4().hex
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text(f'CREATE SCHEMA "{schema}"'))
                connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
                round_trip(connection)
            finally:
                # All schema and table changes were made in this transaction; restore the database.
                transaction.rollback()
    finally:
        engine.dispose()
