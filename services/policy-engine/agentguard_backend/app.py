from agentguard_contracts import HealthResponse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentguard_backend.config import Settings


def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(
        title="AgentGuard development scaffold",
        description="Health and documentation only. No authorization or execution endpoints exist.",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )

    @app.get("/health", response_model=HealthResponse, tags=["development"])
    async def health() -> HealthResponse:
        return HealthResponse(service=settings.service_name)

    return app
