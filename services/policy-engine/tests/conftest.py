import hashlib
import json

import pytest

from agentguard_backend.config import Settings


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
