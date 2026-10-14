from datetime import datetime, timezone

import httpx
import pytest

pytest.importorskip("mcp", reason="The pinned MCP SDK is required for gateway tests.")

from agentguard_contracts import AuthorizationResponse, PolicyDecision, TrustedContext
from agentguard_gateway.app import create_app, protect_mcp_app
from agentguard_gateway.config import GatewaySettings
from agentguard_gateway.interfaces import (
    DisabledAuthorizationClient,
    McpCallerAuthentication,
    TrustedContextResolver,
)
from agentguard_gateway.mcp_server import (
    AuthenticatedArchiveHandler,
    InMemoryLocalArchiveStub,
    LocalArchiveDemo,
    create_mcp_server,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken


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


class TestCallerAuthenticator:
    async def authenticate(self, credential: str) -> TrustedContext:
        assert credential == "verified-test-credential"
        return TrustedContext(agent_id="a", adapter_id="test", surface="mcp")


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
            async with streamable_http_client("http://127.0.0.1:8001/mcp", http_client=client) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    result = await session.call_tool(
                        "archive_local_demonstration", {"record_id": "synthetic-record"}
                    )

    assert [tool.name for tool in tools.tools] == ["archive_local_demonstration"]
    assert "demonstration only" in tools.tools[0].description.lower()
    assert "denies every call" in tools.tools[0].description.lower()
    assert tools.tools[0].inputSchema["required"] == ["record_id"]
    assert result.isError is True
    assert "AUTHENTICATION_REQUIRED" in result.content[0].text
    assert "not performed" in result.content[0].text


@pytest.mark.anyio
async def test_configured_downstream_endpoint_still_denies_without_identity():
    settings = GatewaySettings(_env_file=None, archive_mcp_url="http://127.0.0.1:65535/mcp")
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8001"
        ) as client:
            async with streamable_http_client("http://127.0.0.1:8001/mcp", http_client=client) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "archive_local_demonstration", {"record_id": "synthetic-record"}
                    )

    assert result.isError is True
    assert "AUTHENTICATION_REQUIRED" in result.content[0].text


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


@pytest.mark.anyio
async def test_authenticated_archive_handler_uses_only_authenticator_derived_context():
    executor = InMemoryLocalArchiveStub()
    handler = AuthenticatedArchiveHandler(
        LocalArchiveDemo(AllowingAuthorizationClient(decision_request_id="r"), executor),
        TrustedContextResolver(TestCallerAuthenticator()),
    )

    result = await handler.invoke(
        record_id="synthetic-record",
        credential="verified-test-credential",
        request_id="r",
        session_id="s",
    )

    assert result.isError is False
    assert executor.archived_record_ids == ["synthetic-record"]


class RecordingBearerTokenVerifier:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    async def verify_token(self, token: str) -> AccessToken | None:
        self.tokens.append(token)
        if token != "verified-bearer-token":
            return None
        return AccessToken(
            token=token,
            client_id="verified-client",
            scopes=["archive.execute"],
            subject="verified-subject",
            claims={"iss": "https://issuer.example.test"},
        )


class ServerOwnedTokenMapper:
    def __init__(self, context: TrustedContext) -> None:
        self.context = context
        self.access_tokens: list[AccessToken] = []

    async def resolve(self, access_token: AccessToken) -> TrustedContext:
        self.access_tokens.append(access_token)
        return self.context


class RecordingAllowingAuthorizationClient:
    def __init__(self) -> None:
        self.calls: list[tuple[object, TrustedContext]] = []

    async def authorize(self, request, trusted):
        self.calls.append((request, trusted))
        return AuthorizationResponse(
            policy_decision=PolicyDecision(
                decision_id="decision",
                request_id=request.request_id,
                decision="ALLOW",
                reason_code="ALLOWED",
                explanation="Test authorization.",
                policy_version="test-policy",
                timestamp=datetime.now(timezone.utc),
            )
        )


@pytest.mark.anyio
async def test_sdk_verified_bearer_maps_to_trusted_context_before_pdp_and_execution():
    trusted = TrustedContext(agent_id="mapped-agent", adapter_id="mapped-adapter", surface="mcp")
    token_verifier = RecordingBearerTokenVerifier()
    mapper = ServerOwnedTokenMapper(trusted)
    authorization = RecordingAllowingAuthorizationClient()
    executor = InMemoryLocalArchiveStub()
    server = create_mcp_server(
        authorization_client=authorization,
        executor=executor,
        caller_authentication=McpCallerAuthentication(
            token_verifier=token_verifier,
            trusted_context_mapper=mapper,
        ),
    )
    app = protect_mcp_app(
        server.streamable_http_app(),
        McpCallerAuthentication(
            token_verifier=token_verifier,
            trusted_context_mapper=mapper,
        ),
    )

    async with server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8001",
            headers={"Authorization": "Bearer verified-bearer-token"},
        ) as client:
            async with streamable_http_client("http://127.0.0.1:8001/mcp", http_client=client) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "archive_local_demonstration", {"record_id": "synthetic-record"}
                    )

    assert result.isError is False
    assert token_verifier.tokens
    assert mapper.access_tokens
    assert authorization.calls[0][1] == trusted
    assert executor.archived_record_ids == ["synthetic-record"]


@pytest.mark.anyio
async def test_sdk_authentication_rejects_missing_or_invalid_bearers_before_mcp_dispatch():
    token_verifier = RecordingBearerTokenVerifier()
    mapper = ServerOwnedTokenMapper(
        TrustedContext(agent_id="mapped-agent", adapter_id="mapped-adapter", surface="mcp")
    )
    authorization = RecordingAllowingAuthorizationClient()
    executor = InMemoryLocalArchiveStub()
    server = create_mcp_server(
        authorization_client=authorization,
        executor=executor,
        caller_authentication=McpCallerAuthentication(
            token_verifier=token_verifier,
            trusted_context_mapper=mapper,
        ),
    )
    app = protect_mcp_app(
        server.streamable_http_app(),
        McpCallerAuthentication(
            token_verifier=token_verifier,
            trusted_context_mapper=mapper,
        ),
    )

    async with server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8001"
        ) as client:
            missing = await client.post("/mcp")
            invalid = await client.post("/mcp", headers={"Authorization": "Bearer invalid"})

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert token_verifier.tokens == ["invalid"]
    assert mapper.access_tokens == []
    assert authorization.calls == []
    assert executor.archived_record_ids == []
