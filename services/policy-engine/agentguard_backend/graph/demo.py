"""Explicit synthetic graph fixture import, NOT a manifest importer or permission grant."""

import json
from pathlib import Path

from sqlalchemy import exists, select
from sqlalchemy.orm import sessionmaker

from agentguard_backend.db.models import (
    ApprovedDestination,
    GraphDestination,
    Permission,
    Revocation,
    ToolDataFlow,
    utc_now,
)
from agentguard_backend.db.provenance import trusted_lineage

FIXTURE = Path(__file__).resolve().parents[4] / "demo/fixtures/capability-graph.json"


def seed_graph_demo(sessions: sessionmaker, *, fixture_path: Path | None = None) -> None:
    document = json.loads((fixture_path or FIXTURE).read_text())
    with sessions.begin() as session:
        if session.scalar(select(exists().where(ToolDataFlow.id.is_not(None)))) or session.scalar(
            select(exists().where(GraphDestination.id.is_not(None)))
        ):
            raise ValueError("Existing graph facts preserved; use a fresh synthetic database")
        agent = document["agent_id"]
        case, classification, ancestors = trusted_lineage(session, "case-1042")
        report, report_classification, report_ancestors = trusted_lineage(session, "report-1042")
        if (
            case.owner_principal_id != agent
            or case.type != "case"
            or classification != "CONFIDENTIAL"
            or ancestors
            or report.owner_principal_id != agent
            or report.type != "report"
            or report_classification != "CONFIDENTIAL"
            or report_ancestors != ["case-1042"]
        ):
            raise ValueError(
                "Graph demo requires the exact trusted synthetic PDP fixture; no resources or permissions were invented"
            )
        address = document["destination"]["address"]
        approved = session.get(ApprovedDestination, address)
        if approved is not None and approved.active:
            raise ValueError("Demo external destination must not be PDP-approved")
        session.add(
            GraphDestination(**document["destination"], status="ACTIVE", verified_at=utc_now())
        )
        session.flush()
        for flow in document["flows"]:
            permission = session.scalar(
                select(Permission).where(
                    Permission.principal_id == agent,
                    Permission.action == flow["action"],
                    Permission.resource_id == flow["resource_id"],
                    Permission.status == "ACTIVE",
                )
            )
            if permission is None or session.scalar(
                select(exists().where(Revocation.permission_id == permission.id))
            ):
                raise ValueError(
                    "Demo requires existing active scoped permissions; no grants were added"
                )
            session.add(
                ToolDataFlow(
                    id=flow["id"],
                    permission_id=permission.id,
                    input_resource_id=flow["resource_id"],
                    destination_id=flow["destination_id"],
                    status="ACTIVE",
                    verification="DECLARED",
                    assumption=flow["assumption"],
                    evidence_ref=flow["evidence_ref"],
                )
            )
        session.flush()
