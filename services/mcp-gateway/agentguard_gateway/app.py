from contextlib import asynccontextmanager

from agentguard_contracts import HealthResponse
from fastapi import FastAPI
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import (
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from starlette.middleware.authentication import AuthenticationMiddleware

from agentguard_gateway.authorization import HTTPAuthorizationClient
from agentguard_gateway.config import GatewaySettings
from agentguard_gateway.dev_auth import (
    DevBearerTokenVerifier,
    DevCallerCredentialStore,
    DevTokenMapper,
)
from agentguard_gateway.interfaces import McpCallerAuthentication
from agentguard_gateway.mcp_server import McpArchiveForwarder, create_mcp_server


def protect_mcp_app(mcp_app, caller_authentication: McpCallerAuthentication):
    """Require verified bearer credentials and scopes before MCP dispatch."""
    if not caller_authentication.required_scopes:
        raise ValueError("At least one MCP caller scope must be required.")

    # AuthenticationMiddleware must be outermost so it populates scope['user']
    # before RequireAuthMiddleware checks the required scope.
    return AuthenticationMiddleware(
        RequireAuthMiddleware(
            AuthContextMiddleware(mcp_app),
            required_scopes=list(caller_authentication.required_scopes),
        ),
        backend=BearerAuthBackend(caller_authentication.token_verifier),
    )


def create_app(
    settings: GatewaySettings | None = None,
    *,
    caller_authentication: McpCallerAuthentication | None = None,
) -> FastAPI:
    """Create a fail-closed gateway with optional caller authentication."""
    settings = settings or GatewaySettings()

    if caller_authentication is not None and settings.caller_auth_enabled:
        raise ValueError(
            "Supply caller_authentication or enable AG_CALLER_AUTH_ENABLED, not both."
        )

    if settings.caller_auth_enabled:
        store = DevCallerCredentialStore(settings.caller_credential_store)
        verifier = DevBearerTokenVerifier(
            store,
            str(settings.caller_resource_server_url),
        )
        mapper = DevTokenMapper(
            store,
            expected_agent_id=settings.caller_expected_agent_id,
            expected_adapter_id=settings.caller_expected_adapter_id,
        )
        caller_authentication = McpCallerAuthentication(
            token_verifier=verifier,
            trusted_context_mapper=mapper,
            required_scopes=("archive.execute",),
        )

    executor = (
        McpArchiveForwarder.from_streamable_http_endpoint(
            str(settings.archive_mcp_url)
        )
        if settings.archive_mcp_url is not None
        else None
    )
    mcp_server = create_mcp_server(
        authorization_client=HTTPAuthorizationClient(settings),
        executor=executor,
        caller_authentication=caller_authentication,
    )
    mcp_app = mcp_server.streamable_http_app()
    if caller_authentication is not None:
        mcp_app = protect_mcp_app(mcp_app, caller_authentication)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with mcp_server.session_manager.run():
            yield

    app = FastAPI(
        title="AgentGuard MCP gateway",
        description=(
            "Fail-closed MCP gateway. Caller authentication is disabled by default. "
            "When enabled, verified bearer credentials and server-owned identity "
            "mapping are required before policy authorization."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(service="agentguard-gateway")

    # Keep /health outside the protected MCP mount.
    app.mount("/", mcp_app)
    return app
