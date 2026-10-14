"""Graph queries are synchronous read-only work, outside the PDP critical path."""

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from pydantic import ValidationError

from agentguard_backend.graph.analyzer import analyze
from agentguard_backend.graph.models import GraphLimits, GraphProjection, RiskAnalysis
from agentguard_backend.graph.projector import NetworkXGraphBuilder
from agentguard_backend.graph.repository import GraphUnavailable, load_snapshot


class GraphService:
    def __init__(self, sessions: sessionmaker):
        self.sessions = sessions

    def query(
        self,
        authorization: str | None,
        agent_id: str | None,
        limits: GraphLimits,
        risks: bool = False,
    ) -> GraphProjection | RiskAnalysis:
        try:
            with self.sessions.begin() as session:
                snapshot = load_snapshot(session, authorization, agent_id, limits)
                builder = NetworkXGraphBuilder(snapshot, limits)
                projection = builder.project()
                return analyze(builder.network, projection, limits) if risks else projection
        except (SQLAlchemyError, ValidationError):
            raise GraphUnavailable("Trusted graph database unavailable") from None
