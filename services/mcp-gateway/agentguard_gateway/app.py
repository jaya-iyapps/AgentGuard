from contextlib import asynccontextmanager

from agentguard_contracts import HealthResponse
from fastapi import FastAPI

from agentguard_gateway.authorization import HTTPAuthorizationClient
from agentguard_gateway.config import GatewaySettings
from agentguard_gateway.mcp_server import create_mcp_server


def create_app() -> FastAPI:
    mcp_server = create_mcp_server(authorization_client=HTTPAuthorizationClient(GatewaySettings()))
    mcp_app = mcp_server.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        # A mounted FastMCP app does not run its own lifespan.  Entering the
        # session manager here is required by the official MCP SDK transport.
        async with mcp_server.session_manager.run():
            yield

    app = FastAPI(
        title="AgentGuard MCP gateway",
        description="Fail-closed MCP gateway with a local demonstration/stub archive tool.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(service="agentguard-gateway")

    # Mount at the root so FastMCP's supported default /mcp route remains /mcp.
    # Health is registered first and therefore retains its existing endpoint.
    app.mount("/", mcp_app)

    return app
