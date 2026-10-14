from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from agentguard_contracts import AuthorizationResponse, PolicyDecision, TrustedContext
from agentguard_gateway.mcp_server import (
    APPROVED_DOWNSTREAM_ARCHIVE_TOOL,
    LocalArchiveDemo,
    McpArchiveForwarder,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP


class ScriptedAuthorizationClient:
    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error

    async def authorize(self, request, trusted):
        if self.error is not None:
            raise self.error
        return self.response


def allow_response(request_id: str) -> AuthorizationResponse:
    return AuthorizationResponse(
        policy_decision=PolicyDecision(
            decision_id="test-decision",
            request_id=request_id,
            decision="ALLOW",
            reason_code="ALLOWED",
            explanation="Test-only authorization.",
            policy_version="test-policy",
            timestamp=datetime.now(timezone.utc),
        )
    )


def trusted_test_context() -> TrustedContext:
    return TrustedContext(agent_id="test-agent", adapter_id="test-adapter", surface="test")


class InProcessArchiveServer:
    """Test-only MCP server and official-client transport."""

    def __init__(self, *, advertised_tool: str = APPROVED_DOWNSTREAM_ARCHIVE_TOOL) -> None:
        self.calls: list[str] = []
        self.server = FastMCP("test archive MCP server")

        @self.server.tool(name=advertised_tool)
        async def archive_record(record_id: str) -> str:
            self.calls.append(record_id)
            return "archived"

    @asynccontextmanager
    async def client(self):
        app = self.server.streamable_http_app()
        async with self.server.session_manager.run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
            ) as http_client:
                async with streamable_http_client(
                    "http://127.0.0.1:8000/mcp", http_client=http_client
                ) as (read_stream, write_stream, _):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        yield session


@pytest.mark.anyio
async def test_downstream_discovery_exposes_only_the_test_server_tool():
    archive = InProcessArchiveServer()

    async with archive.client() as client:
        result = await client.list_tools()

    assert [tool.name for tool in result.tools] == [APPROVED_DOWNSTREAM_ARCHIVE_TOOL]


@pytest.mark.anyio
async def test_matching_allow_forwards_once_to_fixed_downstream_tool():
    archive = InProcessArchiveServer()
    forwarder = McpArchiveForwarder(archive.client)
    demo = LocalArchiveDemo(
        ScriptedAuthorizationClient(response=allow_response("request-1")), forwarder
    )

    result = await demo.invoke(
        record_id="record-1",
        trusted=trusted_test_context(),
        request_id="request-1",
        session_id="session-1",
    )

    assert result.isError is False
    assert archive.calls == ["record-1"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("trusted", "authorization", "request_id"),
    [
        (None, ScriptedAuthorizationClient(response=allow_response("request-1")), "request-1"),
        (
            trusted_test_context(),
            ScriptedAuthorizationClient(response=AuthorizationResponse(
                policy_decision=PolicyDecision(
                    decision_id="deny",
                    request_id="request-1",
                    decision="DENY",
                    reason_code="DENIED",
                    explanation="Test denial.",
                    policy_version="test-policy",
                    timestamp=datetime.now(timezone.utc),
                )
            )),
            "request-1",
        ),
        (trusted_test_context(), ScriptedAuthorizationClient(error=RuntimeError("PDP down")), "request-1"),
        (trusted_test_context(), ScriptedAuthorizationClient(response={"malformed": True}), "request-1"),
        (trusted_test_context(), ScriptedAuthorizationClient(response=allow_response("other")), "request-1"),
    ],
)
async def test_rejected_authorization_never_constructs_downstream_client(
    trusted, authorization, request_id
):
    archive = InProcessArchiveServer()
    factory_calls = 0

    def factory():
        nonlocal factory_calls
        factory_calls += 1
        return archive.client()

    demo = LocalArchiveDemo(authorization, McpArchiveForwarder(factory))
    result = await demo.invoke(
        record_id="record-1",
        trusted=trusted,
        request_id=request_id,
        session_id="session-1",
    )

    assert result.isError is True
    assert factory_calls == 0
    assert archive.calls == []


class RaisingDownstreamSession:
    def __init__(self) -> None:
        self.call_count = 0

    async def list_tools(self):
        return SimpleNamespace(tools=[SimpleNamespace(name=APPROVED_DOWNSTREAM_ARCHIVE_TOOL)])

    async def call_tool(self, name, arguments):
        self.call_count += 1
        raise RuntimeError("downstream transport failed")


@pytest.mark.anyio
async def test_downstream_exception_is_not_retried():
    session = RaisingDownstreamSession()

    @asynccontextmanager
    async def factory():
        yield session

    demo = LocalArchiveDemo(
        ScriptedAuthorizationClient(response=allow_response("request-1")),
        McpArchiveForwarder(factory),
    )

    result = await demo.invoke(
        record_id="record-1",
        trusted=trusted_test_context(),
        request_id="request-1",
        session_id="session-1",
    )

    assert result.isError is True
    assert session.call_count == 1
