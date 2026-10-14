"""HTTP wrapper for the separate demonstration archive MCP service."""

from contextlib import asynccontextmanager

from agentguard_contracts import HealthResponse
from fastapi import FastAPI

from agentguard_archive_mcp.config import ArchiveServerSettings
from agentguard_archive_mcp.server import create_archive_server


def create_app(settings: ArchiveServerSettings | None = None) -> FastAPI:
    """Expose archive `/health` and the supported MCP `/mcp` route."""
    archive_server = create_archive_server(settings)
    mcp_app = archive_server.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with archive_server.session_manager.run():
            yield

    app = FastAPI(
        title="AgentGuard demonstration archive MCP server",
        description="Stateless demonstration archive service; not a production archive.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(service="agentguard-archive-mcp")

    app.mount("/", mcp_app)
    return app
