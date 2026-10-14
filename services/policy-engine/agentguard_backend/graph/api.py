"""Self-scope graph reads with development bearer authentication, never a public explorer."""

from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Response

from agentguard_backend.graph.models import GraphLimits, GraphProjection, RiskAnalysis
from agentguard_backend.graph.repository import GraphAccessDenied, GraphUnavailable
from agentguard_backend.graph.service import GraphService
from agentguard_backend.pdp.context import BEARER


def graph_router(service: GraphService | None, environment: str) -> APIRouter:
    router = APIRouter(prefix="/v1/capability-graph", tags=["capability graph"])

    def query(
        authorization,
        agent_id,
        max_nodes,
        max_edges,
        max_depth,
        max_findings,
        response,
        risks=False,
    ):
        response.headers["Cache-Control"] = "no-store"
        if not BEARER.fullmatch(authorization or ""):
            raise HTTPException(
                401,
                "Verified caller required",
                headers={"Cache-Control": "no-store", "WWW-Authenticate": "Bearer"},
            )
        # The existing local bearer binding is not production authorization/RBAC.
        if service is None or environment != "development":
            raise HTTPException(
                503,
                "Graph reads require the development PostgreSQL backend",
                headers={"Cache-Control": "no-store"},
            )
        try:
            return service.query(
                authorization,
                agent_id,
                GraphLimits(
                    max_nodes=max_nodes,
                    max_edges=max_edges,
                    max_depth=max_depth,
                    max_findings=max_findings,
                ),
                risks,
            )
        except GraphAccessDenied as error:
            raise HTTPException(
                error.status_code,
                "Verified self-scope caller required",
                headers={"Cache-Control": "no-store"},
            ) from None
        except GraphUnavailable:
            raise HTTPException(
                503, "Trusted graph database unavailable", headers={"Cache-Control": "no-store"}
            ) from None

    @router.get("", response_model=GraphProjection)
    def capability_graph(
        response: Response,
        authorization: Annotated[str | None, Header()] = None,
        agent_id: Annotated[str | None, Query(min_length=1, max_length=160)] = None,
        max_nodes: Annotated[int, Query(ge=2, le=2000)] = 512,
        max_edges: Annotated[int, Query(ge=1, le=5000)] = 1024,
        max_depth: Annotated[int, Query(ge=1, le=32)] = 8,
        max_findings: Annotated[int, Query(ge=1, le=100)] = 25,
    ):
        return query(
            authorization, agent_id, max_nodes, max_edges, max_depth, max_findings, response
        )

    @router.get("/risks", response_model=RiskAnalysis)
    def capability_risks(
        response: Response,
        authorization: Annotated[str | None, Header()] = None,
        agent_id: Annotated[str | None, Query(min_length=1, max_length=160)] = None,
        max_nodes: Annotated[int, Query(ge=2, le=2000)] = 512,
        max_edges: Annotated[int, Query(ge=1, le=5000)] = 1024,
        max_depth: Annotated[int, Query(ge=1, le=32)] = 8,
        max_findings: Annotated[int, Query(ge=1, le=100)] = 25,
    ):
        return query(
            authorization, agent_id, max_nodes, max_edges, max_depth, max_findings, response, True
        )

    return router
