from agentguard_contracts import HealthResponse
from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard MCP gateway scaffold",
        description="Health endpoint only; /mcp and sensitive tools are intentionally absent.",
        version="0.1.0",
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(service="agentguard-gateway")

    return app
