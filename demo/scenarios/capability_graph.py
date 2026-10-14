"""Synthetic, disposable SQLite + real Rego demo. No network or execution side effects."""

import argparse
import asyncio
import hashlib
import json
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from agentguard_contracts import AuthorizationRequest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from agentguard_backend.db.audit import DatabaseAuditWriter
from agentguard_backend.db.models import Base, Permission, Revocation
from agentguard_backend.db.resolver import PostgresContextResolver
from agentguard_backend.db.seed import seed_context
from agentguard_backend.graph.demo import seed_graph_demo
from agentguard_backend.graph.models import GraphLimits
from agentguard_backend.graph.service import GraphService
from agentguard_backend.pdp.models import ContextDocument, OPAResult
from agentguard_backend.pdp.service import DecisionService

POLICY = Path(__file__).resolve().parents[2] / "services/policy-engine/policies/authorize.rego"


class CliPolicy:
    def __init__(self, executable):
        self.executable = executable

    async def evaluate(self, document):
        # Real Rego execution, but explicitly NOT the live OPA HTTP transport.
        result = subprocess.run(
            [
                self.executable,
                "eval",
                "--stdin-input",
                "--data",
                str(POLICY),
                "--format=json",
                "data.agentguard.authz.decision",
            ],
            input=document.model_dump_json(),
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
        )
        return OPAResult.model_validate(
            json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
        )


async def run(executable, directory):
    credential = secrets.token_urlsafe(32)
    context = ContextDocument.model_validate(
        {
            "identities": [
                {
                    "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
                    "agent_id": "support-agent",
                    "adapter_id": "synthetic-demo",
                    "surface": "mcp",
                    "status": "ACTIVE",
                    "permissions": [
                        {"action": "case.read", "resource_id": "case-1042", "status": "ACTIVE"},
                        {"action": "email.send", "resource_id": "report-1042", "status": "ACTIVE"},
                    ],
                }
            ],
            "resources": [
                {
                    "id": "case-1042",
                    "type": "case",
                    "classification": "CONFIDENTIAL",
                    "owner_agent_id": "support-agent",
                },
                {
                    "id": "report-1042",
                    "type": "report",
                    "classification": "CONFIDENTIAL",
                    "owner_agent_id": "support-agent",
                    "provenance_refs": ["case-1042"],
                },
            ],
            "approved_destinations": ["support@company.example"],
        }
    )
    engine = create_engine(f"sqlite:///{directory}/demo.sqlite3", hide_parameters=True)

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        Base.metadata.create_all(engine)
        sessions = sessionmaker(engine, expire_on_commit=False)
        seed_context(sessions, context)
        seed_graph_demo(sessions)
        graphs = GraphService(sessions)
        header = f"Bearer {credential}"
        limits = GraphLimits()
        before = graphs.query(header, None, limits)
        analysis = graphs.query(header, None, limits, risks=True)
        assert len(analysis.findings) == 1
        pdp = DecisionService(
            PostgresContextResolver(sessions),
            CliPolicy(executable),
            "pdp-v1",
            DatabaseAuditWriter(sessions),
        )
        read = AuthorizationRequest(
            request_id="synthetic-read",
            session_id="synthetic-session",
            action="case.read",
            resource={"id": "case-1042", "type": "case"},
        )
        egress = AuthorizationRequest(
            request_id="synthetic-egress",
            session_id="synthetic-session",
            action="email.send",
            resource={"id": "report-1042", "type": "report", "asserted_classification": "PUBLIC"},
            destination="outsider@example.test",
        )
        allowed = await pdp.authorize(read, header)
        blocked = await pdp.authorize(egress, header)
        assert allowed.policy_decision.decision == "ALLOW"
        assert blocked.policy_decision.reason_code == "CG-DATA-EGRESS-001"
        with sessions.begin() as session:
            permission = session.scalar(select(Permission).where(Permission.action == "email.send"))
            session.add(
                Revocation(
                    permission_id=permission.id,
                    reason="Explicit disposable synthetic demo revocation",
                )
            )
        after = graphs.query(header, None, limits, risks=True)
        historical = graphs.query(header, None, limits)
        revoked = await pdp.authorize(egress, header)
        assert not after.findings
        assert revoked.policy_decision.reason_code == "CG-PERMISSION-REVOKED"
        assert any(edge.relationship == "DERIVED_FROM" for edge in historical.graph.edges)
        return {
            "environment": "Disposable SQLite, real OPA CLI/Rego; NOT PostgreSQL or live OPA HTTP",
            "graph": before.model_dump(mode="json"),
            "analysis": analysis.model_dump(mode="json"),
            "authorization": {
                "case_read": allowed.policy_decision.decision,
                "external_report_send": blocked.policy_decision.reason_code,
                "after_revocation": revoked.policy_decision.reason_code,
            },
            "findings_before_revocation": len(analysis.findings),
            "findings_after_revocation": len(after.findings),
            "historical_provenance_retained": True,
            "execution_evidence": "NOT_RECORDED",
        }
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full", action="store_true", help="Print the full synthetic API graph and risk envelopes"
    )
    args = parser.parse_args()
    executable = shutil.which("opa")
    if executable is None:
        raise SystemExit("OPA CLI required; this demo does not substitute mocked authorization")
    with tempfile.TemporaryDirectory(prefix="agentguard-graph-demo-") as directory:
        result = asyncio.run(run(executable, directory))
    if not args.full:
        result["nodes"] = len(result["graph"]["graph"]["nodes"])
        result["edges"] = len(result["graph"]["graph"]["edges"])
        result["finding"] = result["analysis"]["findings"][0]
        del result["graph"]
        del result["analysis"]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
