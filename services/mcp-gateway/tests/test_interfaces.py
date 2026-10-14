import asyncio

import pytest
from agentguard_contracts import AuthorizationRequest, ResourceReference, TrustedContext
from agentguard_gateway.interfaces import DisabledAuthorizationClient


def test_disabled_client_fails_closed():
    request = AuthorizationRequest(
        request_id="r",
        session_id="s",
        action="email.send",
        resource=ResourceReference(id="example", type="report"),
    )
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")
    response = asyncio.run(DisabledAuthorizationClient().authorize(request, trusted))

    assert response.policy_decision.decision == "DENY"
    assert response.policy_decision.reason_code == "NOT_IMPLEMENTED"


def test_gateway_configuration_defaults_to_local_core():
    pytest.importorskip("pydantic_settings", reason="Gateway settings dependency is not installed.")
    from agentguard_gateway.config import GatewaySettings

    assert str(GatewaySettings(_env_file=None).policy_url) == "http://127.0.0.1:8000/"
