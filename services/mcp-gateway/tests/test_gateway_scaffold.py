import asyncio

import httpx
import pytest
from agentguard_contracts import AuthorizationRequest, ResourceReference, TrustedContext
from agentguard_gateway.app import create_app
from agentguard_gateway.config import GatewaySettings
from agentguard_gateway.interfaces import DisabledAuthorizationClient


@pytest.mark.anyio
async def test_gateway_has_health_but_no_execution_surface():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        assert (await client.get("/health")).json()["enforcement_enabled"] is False
        assert (await client.post("/mcp", json={})).status_code == 404
        assert (await client.post("/v1/tools/send_email", json={})).status_code == 404


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
    assert str(GatewaySettings(_env_file=None).policy_url) == "http://127.0.0.1:8000/"
