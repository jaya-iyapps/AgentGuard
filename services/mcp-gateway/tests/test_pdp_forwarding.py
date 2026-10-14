"""Verify the complete authentication/PDP/forwarding boundary together."""

import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from agentguard_archive_mcp import create_archive_server
from agentguard_contracts import AuthorizationRequest, TrustedContext
from agentguard_contracts.canonical import request_digest
from agentguard_gateway import app as gateway_app
from agentguard_gateway.authorization import HTTPAuthorizationClient
from agentguard_gateway.config import GatewaySettings
from agentguard_gateway.interfaces import TrustedContextResolver
from agentguard_gateway.mcp_server import (
    AuthenticatedArchiveHandler,
    LocalArchiveDemo,
    McpArchiveForwarder,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


def test_app_preserves_http_pdp_client_and_selects_lazy_forwarder(monkeypatch):
    settings = GatewaySettings(
        _env_file=None,
        policy_credential=secrets.token_urlsafe(32),
        policy_agent_id="server-agent",
        policy_adapter_id="server-adapter",
        archive_mcp_url="http://127.0.0.1:8002/mcp",
    )
    original = gateway_app.create_mcp_server
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    def unexpected_connection(*_):
        pytest.fail("Creating the gateway must not contact the downstream")

    monkeypatch.setattr(gateway_app, "create_mcp_server", capture)
    monkeypatch.setattr(
        "agentguard_gateway.mcp_server.streamable_http_mcp_session", unexpected_connection
    )
    gateway_app.create_app(settings)
    assert isinstance(captured["authorization_client"], HTTPAuthorizationClient)
    assert captured["authorization_client"].settings is settings
    assert isinstance(captured["executor"], McpArchiveForwarder)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "outcome",
    [
        "allow",
        "missing_credential",
        "authentication_error",
        "pdp_error",
        "request_id",
        "digest",
        "expired",
        "policy_version",
        "deny",
    ],
)
async def test_verified_http_decision_is_required_before_actual_archive_forwarding(outcome):
    settings = GatewaySettings(
        _env_file=None,
        policy_credential=secrets.token_urlsafe(32),
        policy_agent_id="server-agent",
        policy_adapter_id="server-adapter",
    )
    trusted = TrustedContext(agent_id="server-agent", adapter_id="server-adapter", surface="mcp")
    pdp_calls = []
    factory_calls = []
    archive_calls = []

    class TestAuthenticator:
        async def authenticate(self, credential):
            assert credential == "verified-test-caller"
            if outcome == "authentication_error":
                raise RuntimeError("test identity provider unavailable")
            return trusted

    def policy(incoming):
        pdp_calls.append(incoming)
        assert incoming.headers["Authorization"] == (
            "Bearer " + settings.policy_credential.get_secret_value()
        )
        assert "agent_id" not in json.loads(incoming.content)
        pending = AuthorizationRequest.model_validate_json(incoming.content)
        now = datetime.now(timezone.utc)
        decision = {
            "decision_id": "test-decision",
            "request_id": pending.request_id,
            "decision": "ALLOW",
            "reason_code": "CG-ALLOW-001",
            "explanation": "Isolated mock policy; production archive policy is unchanged.",
            "policy_version": "pdp-v1",
            "timestamp": now.isoformat(),
        }
        headers = {
            "X-AgentGuard-Request-Digest": request_digest(pending),
            "X-AgentGuard-Decision-Expires-At": (now + timedelta(seconds=5)).isoformat(),
        }
        if outcome == "pdp_error":
            return httpx.Response(503)
        if outcome == "request_id":
            decision["request_id"] = "different-request"
        elif outcome == "digest":
            headers["X-AgentGuard-Request-Digest"] = "0" * 64
        elif outcome == "expired":
            decision["timestamp"] = (now - timedelta(seconds=10)).isoformat()
            headers["X-AgentGuard-Decision-Expires-At"] = (now - timedelta(seconds=5)).isoformat()
        elif outcome == "policy_version":
            decision["policy_version"] = "different-policy"
        elif outcome == "deny":
            decision.update(decision="DENY", reason_code="TEST-DENY")
        return httpx.Response(200, json={"policy_decision": decision}, headers=headers)

    archive = create_archive_server()

    @asynccontextmanager
    async def downstream():
        factory_calls.append(True)
        archive_app = archive.streamable_http_app()
        async with archive.session_manager.run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=archive_app),
                base_url="http://127.0.0.1:8002",
            ) as http:
                async with streamable_http_client(
                    "http://127.0.0.1:8002/mcp", http_client=http
                ) as (read, write, _):
                    async with ClientSession(read, write) as client:
                        await client.initialize()

                        class RecordingSession:
                            async def list_tools(self):
                                return await client.list_tools()

                            async def call_tool(self, name, arguments):
                                archive_calls.append((name, arguments))
                                result = await client.call_tool(name, arguments)
                                assert result.structuredContent == {
                                    "record_id": "demo-record:1",
                                    "status": "demo_archived",
                                }
                                return result

                        yield RecordingSession()

    handler = AuthenticatedArchiveHandler(
        LocalArchiveDemo(
            HTTPAuthorizationClient(settings, transport=httpx.MockTransport(policy)),
            McpArchiveForwarder(downstream),
        ),
        TrustedContextResolver(TestAuthenticator()),
    )
    result = await handler.invoke(
        record_id="demo-record:1",
        credential=None if outcome == "missing_credential" else "verified-test-caller",
        request_id="forwarding-request",
        session_id="forwarding-session",
    )
    assert bool(pdp_calls) is (outcome not in {"missing_credential", "authentication_error"})
    if outcome == "allow":
        assert result.isError is False
        assert factory_calls == [True]
        assert archive_calls == [("archive_record", {"record_id": "demo-record:1"})]
    else:
        assert result.isError is True
        assert factory_calls == []
        assert archive_calls == []
