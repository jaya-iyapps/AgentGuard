import httpx
import pytest
from agentguard_backend.app import create_app
from agentguard_backend.policy import DenyAllPolicy
from agentguard_contracts import AuthorizationRequest, ResourceReference, TrustedContext


@pytest.mark.anyio
async def test_backend_health_reports_scaffold_not_enforcement(settings):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
    ) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["mode"] == "scaffold"
        assert response.json()["enforcement_enabled"] is False
        assert (await client.post("/v1/authorize", json={})).status_code == 422


@pytest.mark.anyio
async def test_cors_permits_local_frontend_but_not_arbitrary_origins(settings):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings)), base_url="http://test"
    ) as client:
        allowed = await client.get("/health", headers={"Origin": "http://localhost:5173"})
        denied = await client.get("/health", headers={"Origin": "https://untrusted.example"})
        assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
        assert "access-control-allow-origin" not in denied.headers


def test_placeholder_always_denies_even_public_actions():
    request = AuthorizationRequest(
        request_id="r",
        session_id="s",
        action="public.read",
        resource=ResourceReference(id="public-doc", type="document"),
    )
    trusted = TrustedContext(
        agent_id="a", adapter_id="test", surface="test", resource_classification="PUBLIC"
    )
    decision = DenyAllPolicy().evaluate(request, trusted)
    assert decision.decision == "DENY"
    assert decision.reason_code == "NOT_IMPLEMENTED"
