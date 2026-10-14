"""Fail-closed MCP tools for the AgentGuard gateway.

The default archive executor is a local demonstration/stub. An explicitly
configured forwarder contacts one approved downstream MCP tool only after
authorization succeeds.
"""

from dataclasses import dataclass, field
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import AsyncIterator, Callable, Protocol
from uuid import uuid4

from agentguard_contracts import (
    AuthorizationRequest,
    AuthorizationResponse,
    ResourceReference,
    TrustedContext,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from agentguard_gateway.interfaces import (
    AuthorizationClient,
    DisabledAuthorizationClient,
    TrustedContextResolver,
)


class LocalArchiveExecutor(Protocol):
    """An archive execution target used only after authorization succeeds."""

    async def archive(self, record_id: str) -> None:
        """Perform one demonstration archive operation."""
        ...


APPROVED_DOWNSTREAM_ARCHIVE_TOOL = "archive_record"


@asynccontextmanager
async def streamable_http_mcp_session(endpoint: str) -> AsyncIterator[ClientSession]:
    """Connect to one explicitly configured downstream Streamable HTTP endpoint."""
    async with streamable_http_client(endpoint) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@dataclass
class McpArchiveForwarder:
    """Forward the demo archive to one explicitly approved downstream MCP tool.

    The factory is deliberately lazy: constructing this executor does not create
    a downstream client.  Callers must pass through ``LocalArchiveDemo.invoke``
    and receive a matching ALLOW before the factory is called.
    """

    client_factory: Callable[[], AbstractAsyncContextManager[ClientSession]]

    @classmethod
    def from_streamable_http_endpoint(cls, endpoint: str) -> "McpArchiveForwarder":
        """Create a lazy forwarder for an explicitly configured downstream endpoint."""
        return cls(lambda: streamable_http_mcp_session(endpoint))

    async def archive(self, record_id: str) -> None:
        async with self.client_factory() as client:
            tools = await client.list_tools()
            if APPROVED_DOWNSTREAM_ARCHIVE_TOOL not in {tool.name for tool in tools.tools}:
                raise RuntimeError("approved downstream archive tool is not advertised")
            result = await client.call_tool(
                APPROVED_DOWNSTREAM_ARCHIVE_TOOL,
                {"record_id": record_id},
            )
            if result.isError:
                raise RuntimeError("downstream archive tool returned an error")


@dataclass
class InMemoryLocalArchiveStub:
    """Local demonstration/stub only; state is lost when the process exits."""

    archived_record_ids: list[str] = field(default_factory=list)

    async def archive(self, record_id: str) -> None:
        self.archived_record_ids.append(record_id)


def _denied(reason_code: str, explanation: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=f"DENIED ({reason_code}): {explanation}")],
        isError=True,
    )


def _validate_authorization_response(response: object) -> AuthorizationResponse:
    """Validate an authorization response at the gateway trust boundary."""
    # Re-validating model instances protects the gateway if a client constructed
    # one without normal Pydantic validation. Non-model responses are validated
    # directly so a future transport client can return decoded JSON safely.
    if isinstance(response, AuthorizationResponse):
        response = response.model_dump()
    return AuthorizationResponse.model_validate(response)


@dataclass
class LocalArchiveDemo:
    """Authorize a demonstration archive operation before its only side effect."""

    authorization_client: AuthorizationClient
    executor: LocalArchiveExecutor

    async def invoke(
        self,
        *,
        record_id: str,
        trusted: TrustedContext | None,
        request_id: str,
        session_id: str,
    ) -> CallToolResult:
        """Run the configured executor only after a verified caller receives ALLOW."""
        if trusted is None:
            return _denied(
                "AUTHENTICATION_REQUIRED",
                "No verified caller identity is available. The archive operation was not performed.",
            )

        request = AuthorizationRequest(
            request_id=request_id,
            session_id=session_id,
            action="archive.local_demo",
            resource=ResourceReference(id=record_id, type="local-demo-archive"),
        )
        sent_request_id = request.request_id
        try:
            raw_response = await self.authorization_client.authorize(request, trusted)
        except Exception:
            return _denied(
                "AUTHORIZATION_UNAVAILABLE",
                "Authorization failed. The archive operation was not performed.",
            )

        try:
            response = _validate_authorization_response(raw_response)
        except Exception:
            return _denied(
                "AUTHORIZATION_RESPONSE_INVALID",
                "Authorization returned an invalid response. The archive operation was not performed.",
            )

        decision = response.policy_decision
        if decision.request_id != sent_request_id:
            return _denied(
                "AUTHORIZATION_REQUEST_MISMATCH",
                "Authorization response did not match the request. The archive operation was not performed.",
            )

        if decision.decision != "ALLOW":
            return _denied(
                decision.reason_code,
                f"{decision.explanation} The archive operation was not performed.",
            )

        try:
            await self.executor.archive(record_id)
        except Exception:
            return _denied(
                "DOWNSTREAM_UNAVAILABLE",
                "The downstream archive was not confirmed and was not retried.",
            )
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text="Archive operation completed after authorization.",
                )
            ]
        )


@dataclass
class AuthenticatedArchiveHandler:
    """Keep credential resolution separate from authorization and execution."""

    archive_demo: LocalArchiveDemo
    trusted_context_resolver: TrustedContextResolver

    async def invoke(
        self,
        *,
        record_id: str,
        credential: str | None,
        request_id: str,
        session_id: str,
    ) -> CallToolResult:
        trusted = await self.trusted_context_resolver.resolve(credential)
        return await self.archive_demo.invoke(
            record_id=record_id,
            trusted=trusted,
            request_id=request_id,
            session_id=session_id,
        )


def create_mcp_server(
    authorization_client: AuthorizationClient | None = None,
    executor: LocalArchiveExecutor | None = None,
) -> FastMCP:
    """Create the gateway's MCP server with its one fail-closed demo tool."""
    archive_demo = LocalArchiveDemo(
        authorization_client=(
            authorization_client
            if authorization_client is not None
            else DisabledAuthorizationClient()
        ),
        executor=executor if executor is not None else InMemoryLocalArchiveStub(),
    )
    archive_handler = AuthenticatedArchiveHandler(archive_demo, TrustedContextResolver())
    server = FastMCP(
        "AgentGuard MCP gateway",
        instructions=(
            "The archive tool is a demonstration, not a production archive. The default executor "
            "is in-memory. A future authenticated deployment must allowlist only the separately "
            "deployed archive_record demonstration tool after verified identity and authorization."
        ),
    )

    @server.tool(
        name="archive_local_demonstration",
        description=(
            "Demonstration only. The default executor records a synthetic record in memory. "
            "This transport currently denies every call because no CallerAuthenticator is "
            "configured; a future authenticated deployment must use only the allowlisted "
            "archive_record downstream tool after authorization."
        ),
    )
    async def archive_local_demonstration(record_id: str) -> CallToolResult:
        """Request the local demonstration archive for one synthetic record."""
        # The MCP transport has no credential extractor or CallerAuthenticator. Passing
        # no credential to the explicit authentication boundary intentionally denies
        # before authorization or execution rather than inventing caller identity.
        return await archive_handler.invoke(
            record_id=record_id,
            credential=None,
            request_id=str(uuid4()),
            session_id="unresolved-mcp-session",
        )

    return server
