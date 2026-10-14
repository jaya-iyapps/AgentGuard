from datetime import datetime, timezone

import httpx
import pytest

pytest.importorskip("mcp", reason="The pinned MCP SDK is required for gateway tests.")

from agentguard_contracts import AuthorizationResponse, PolicyDecision, TrustedContext
from agentguard_gateway.app import create_app
from agentguard_gateway.interfaces import DisabledAuthorizationClient
from agentguard_gateway.mcp_server import (
    InMemoryLocalArchiveStub,
    LocalArchiveDemo,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


class AllowingAuthorizationClient:
    def __init__(self, *, decision_request_id: str) -> None:
        self.decision_request_id = decision_request_id

    async def authorize(self, request, trusted):
        return AuthorizationResponse(
            policy_decision=PolicyDecision(
                decision_id="decision",
                request_id=self.decision_request_id,
                decision="ALLOW",
                reason_code="ALLOWED",
                explanation="Test authorization.",
                policy_version="test-policy",
                timestamp=datetime.now(timezone.utc),
            )
        )


class MalformedAuthorizationClient:
    async def authorize(self, request, trusted):
        return {"policy_decision": {"decision": "ALLOW"}}


class FailingAuthorizationClient:
    async def authorize(self, request, trusted):
        raise RuntimeError("authorization transport failed")


@pytest.mark.anyio
async def test_gateway_preserves_health_and_removes_other_execution_surfaces():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        assert (await client.get("/health")).json()["enforcement_enabled"] is False
        assert (await client.post("/v1/tools/send_email", json={})).status_code == 404


@pytest.mark.anyio
async def test_mcp_tools_list_and_call_deny_without_a_verified_caller():
    app = create_app()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8001"
        ) as client:
            async with streamable_http_client(
                "http://127.0.0.1:8001/mcp", http_client=client
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    result = await session.call_tool(
                        "archive_local_demonstration", {"record_id": "synthetic-record"}
                    )

    assert [tool.name for tool in tools.tools] == ["archive_local_demonstration"]
    assert "local demonstration/stub" in tools.tools[0].description.lower()
    assert tools.tools[0].inputSchema["required"] == ["record_id"]
    assert result.isError is True
    assert "AUTHENTICATION_REQUIRED" in result.content[0].text
    assert "not performed" in result.content[0].text


@pytest.mark.anyio
async def test_authorization_denial_has_no_local_archive_side_effect():
    executor = InMemoryLocalArchiveStub()
    archive_demo = LocalArchiveDemo(DisabledAuthorizationClient(), executor)
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")

    result = await archive_demo.invoke(
        record_id="synthetic-record",
        trusted=trusted,
        request_id="r",
        session_id="s",
    )

    assert result.isError is True
    assert "NOT_IMPLEMENTED" in result.content[0].text
    assert executor.archived_record_ids == []


@pytest.mark.anyio
async def test_mismatched_allow_request_id_denies_without_side_effect():
    executor = InMemoryLocalArchiveStub()
    archive_demo = LocalArchiveDemo(
        AllowingAuthorizationClient(decision_request_id="different-request"), executor
    )
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")

    result = await archive_demo.invoke(
        record_id="synthetic-record",
        trusted=trusted,
        request_id="expected-request",
        session_id="s",
    )

    assert result.isError is True
    assert "AUTHORIZATION_REQUEST_MISMATCH" in result.content[0].text
    assert executor.archived_record_ids == []


@pytest.mark.anyio
async def test_malformed_authorization_response_denies_without_side_effect():
    executor = InMemoryLocalArchiveStub()
    archive_demo = LocalArchiveDemo(MalformedAuthorizationClient(), executor)
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")

    result = await archive_demo.invoke(
        record_id="synthetic-record",
        trusted=trusted,
        request_id="r",
        session_id="s",
    )

    assert result.isError is True
    assert "AUTHORIZATION_RESPONSE_INVALID" in result.content[0].text
    assert executor.archived_record_ids == []


@pytest.mark.anyio
async def test_authorization_exception_denies_without_side_effect():
    executor = InMemoryLocalArchiveStub()
    archive_demo = LocalArchiveDemo(FailingAuthorizationClient(), executor)
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")

    result = await archive_demo.invoke(
        record_id="synthetic-record",
        trusted=trusted,
        request_id="r",
        session_id="s",
    )

    assert result.isError is True
    assert "AUTHORIZATION_UNAVAILABLE" in result.content[0].text
    assert executor.archived_record_ids == []


@pytest.mark.anyio
async def test_matching_allow_is_required_before_local_archive_side_effect():
    executor = InMemoryLocalArchiveStub()
    archive_demo = LocalArchiveDemo(AllowingAuthorizationClient(decision_request_id="r"), executor)
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")

    result = await archive_demo.invoke(
        record_id="synthetic-record",
        trusted=trusted,
        request_id="r",
        session_id="s",
    )

    assert result.isError is False
    assert executor.archived_record_ids == ["synthetic-record"]
