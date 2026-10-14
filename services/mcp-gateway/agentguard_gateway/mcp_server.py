"""Fail-closed MCP tools for the AgentGuard gateway.

The default archive executor is a local demonstration/stub. An explicitly
configured forwarder contacts one approved downstream MCP tool only after
authorization succeeds.
"""

from dataclasses import dataclass, field
from contextlib import AbstractAsyncContextManager
from typing import Callable, Protocol
from uuid import uuid4

from agentguard_contracts import (
    AuthorizationRequest,
    AuthorizationResponse,
    ResourceReference,
    TrustedContext,
)
from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from agentguard_gateway.interfaces import AuthorizationClient, DisabledAuthorizationClient


class LocalArchiveExecutor(Protocol):
    """A deliberately local, ephemeral executor for the archive demonstration."""

    async def archive(self, record_id: str) -> None:
        """Record a local demonstration archive operation."""
        ...


APPROVED_DOWNSTREAM_ARCHIVE_TOOL = "archive_record"


@dataclass
class McpArchiveForwarder:
    """Forward the demo archive to one explicitly approved downstream MCP tool.

    The factory is deliberately lazy: constructing this executor does not create
    a downstream client.  Callers must pass through ``LocalArchiveDemo.invoke``
    and receive a matching ALLOW before the factory is called.
    """

    client_factory: Callable[[], AbstractAsyncContextManager[ClientSession]]

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
    """Authorize a local demonstration archive before its only side effect."""

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
        """Run the local stub only after a verified caller receives ALLOW."""
        if trusted is None:
            return _denied(
                "AUTHENTICATION_REQUIRED",
                "No verified caller identity is available. The local demonstration/stub "
                "archive was not performed.",
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
                "Authorization failed. The local demonstration/stub archive was not performed.",
            )

        try:
            response = _validate_authorization_response(raw_response)
        except Exception:
            return _denied(
                "AUTHORIZATION_RESPONSE_INVALID",
                "Authorization returned an invalid response. The local demonstration/stub "
                "archive was not performed.",
            )

        decision = response.policy_decision
        if decision.request_id != sent_request_id:
            return _denied(
                "AUTHORIZATION_REQUEST_MISMATCH",
                "Authorization response did not match the request. The local "
                "demonstration/stub archive was not performed.",
            )

        if decision.decision != "ALLOW":
            return _denied(
                decision.reason_code,
                f"{decision.explanation} The local demonstration/stub archive was not performed.",
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
    server = FastMCP(
        "AgentGuard MCP gateway",
        instructions=(
            "The archive tool is a local demonstration/stub, not a production archive. "
            "It requires verified caller identity and authorization before any local action."
        ),
    )

    @server.tool(
        name="archive_local_demonstration",
        description=(
            "Local demonstration/stub only. Requests an in-memory archive of a synthetic "
            "record; this gateway currently denies unauthenticated calls and never archives "
            "production data or forwards to external services."
        ),
    )
    async def archive_local_demonstration(record_id: str) -> CallToolResult:
        """Request the local demonstration archive for one synthetic record."""
        # The MCP transport has no implemented CallerAuthenticator yet.  Supplying no
        # TrustedContext is intentional: it makes every transport invocation deny before
        # authorization or execution rather than inventing a caller identity.
        return await archive_demo.invoke(
            record_id=record_id,
            trusted=None,
            request_id=str(uuid4()),
            session_id="unresolved-mcp-session",
        )

    return server
