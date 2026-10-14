import hashlib
import json
import os
import uuid

import pytest

from agentguard_backend.config import Settings
from agentguard_backend.db.models import Base
from agentguard_backend.db.seed import seed_context
from agentguard_backend.graph.demo import seed_graph_demo
from agentguard_backend.pdp.models import ContextDocument
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def credential():
    return "synthetic-test-credential-" + "x" * 32


@pytest.fixture
def context_document(credential):
    return {
        "identities": [
            {
                "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
                "agent_id": "support-agent",
                "adapter_id": "mcp-adapter",
                "surface": "mcp",
                "status": "ACTIVE",
                "permissions": [
                    {"action": "case.read", "resource_id": "case-1042", "status": "ACTIVE"},
                    {"action": "email.send", "resource_id": "report-1042", "status": "ACTIVE"},
                ],
            }
        ],
        "resources": [
            {
                "id": "case-1042",
                "type": "case",
                "classification": "CONFIDENTIAL",
                "owner_agent_id": "support-agent",
            },
            {
                "id": "report-1042",
                "type": "report",
                "classification": "CONFIDENTIAL",
                "owner_agent_id": "support-agent",
                "provenance_refs": ["case-1042"],
            },
        ],
        "approved_destinations": ["support@company.example"],
    }


@pytest.fixture
def context_path(tmp_path, context_document):
    path = tmp_path / "trusted-context.json"
    path.write_text(json.dumps(context_document))
    return path


@pytest.fixture
def settings(context_path):
    # Isolate file fixtures from a developer's exported PostgreSQL runtime mode.
    # Database tests explicitly inject their resolver or override this setting.
    return Settings(_env_file=None, pdp_context_backend="file", pdp_context_path=str(context_path))


@pytest.fixture
def authorization_request():
    return {
        "request_id": "request-001",
        "session_id": "session-001",
        "action": "case.read",
        "resource": {"id": "case-1042", "type": "case"},
    }


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.getenv("AG_TEST_DATABASE_URL") else []))
def graph_database(request, tmp_path, context_document):
    """Only UUID-isolated schemas in an explicitly opted-in PG test database."""
    admin = None
    if request.param == "postgres":
        url = os.environ["AG_TEST_DATABASE_URL"]
        admin = create_engine(url, hide_parameters=True)
        schema = "graph_test_" + uuid.uuid4().hex
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(
            url,
            hide_parameters=True,
            isolation_level="REPEATABLE READ",
            connect_args={"options": f"-c search_path={schema}"},
        )
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'graph.sqlite3'}", hide_parameters=True)

        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

    try:
        Base.metadata.create_all(engine)
        sessions = sessionmaker(engine, expire_on_commit=False)
        seed_context(sessions, ContextDocument.model_validate(context_document))
        seed_graph_demo(sessions)
        yield sessions
    finally:
        engine.dispose()
        if admin is not None:
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()
