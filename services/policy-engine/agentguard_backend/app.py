from datetime import timedelta

from agentguard_contracts import AuthorizationRequest, AuthorizationResponse, HealthResponse
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from agentguard_backend.config import Settings
from agentguard_backend.pdp.context import FileContextResolver, TrustedContextResolver
from agentguard_backend.pdp.opa import OPAClient, PolicyClient
from agentguard_backend.pdp.service import DecisionService, request_digest


def create_app(
    settings: Settings | None = None,
    resolver: TrustedContextResolver | None = None,
    opa: PolicyClient | None = None,
) -> FastAPI:
    settings = settings or Settings()
    service = DecisionService(
        resolver or FileContextResolver(settings.pdp_context_path),
        opa
        or OPAClient(
            str(settings.opa_url),
            settings.opa_decision_path,
            settings.opa_timeout_seconds,
            settings.opa_policy_version,
        ),
        settings.opa_policy_version,
    )
    app = FastAPI(
        title="AgentGuard policy decision point",
        description="OPA-backed authorization decisions. Protected actions are not executed here.",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
        expose_headers=["X-AgentGuard-Request-Digest", "X-AgentGuard-Decision-Expires-At"],
        allow_credentials=False,
    )

    @app.get("/health", response_model=HealthResponse, tags=["development"])
    async def health() -> HealthResponse:
        return HealthResponse(service=settings.service_name)

    @app.post("/v1/authorize", response_model=AuthorizationResponse, tags=["authorization"])
    async def authorize(
        body: AuthorizationRequest, request: Request, response: Response
    ) -> AuthorizationResponse:
        decision = await service.authorize(body, request.headers.get("authorization"))
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-AgentGuard-Request-Digest"] = request_digest(body)
        expiry = decision.policy_decision.timestamp + timedelta(
            seconds=settings.pdp_decision_ttl_seconds
        )
        response.headers["X-AgentGuard-Decision-Expires-At"] = expiry.isoformat()
        return decision

    return app
