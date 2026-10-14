"""Protected API and synthetic vertical slice. No external tool side effects."""

import json
import shutil
import subprocess
from pathlib import Path

import anyio
import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from agentguard_backend.app import create_app
from agentguard_backend.db.audit import DatabaseAuditWriter
from agentguard_backend.db.models import (
    PrincipalBinding,
    Principal,
    ProvenanceEdge,
    Permission,
    Revocation,
)
from agentguard_backend.db.resolver import PostgresContextResolver
from agentguard_backend.graph.models import GraphProjection, RiskAnalysis
from agentguard_backend.graph.service import GraphService
from agentguard_backend.pdp.opa import OPAClient


@pytest.fixture(autouse=True)
async def scheduler_timer(anyio_backend):
    """Bound test duration and keep restricted-sandbox worker callbacks schedulable.

    In this sandbox, even a trivial AnyIO thread completion cannot wake the
    asyncio selector. A test-only timer fixes wakeups without replacing the
    real FastAPI threadpool, database, authentication, or graph implementation.
    """

    async def pulse():
        while True:
            await anyio.sleep(0.02)

    with anyio.fail_after(30):
        async with anyio.create_task_group() as group:
            group.start_soon(pulse)
            yield
            group.cancel_scope.cancel()


def graph_app(database, settings):
    return create_app(
        settings.model_copy(update={"env": "development"}), graph_service=GraphService(database)
    )


async def get(app, path, credential=None):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get(
            path, headers={"Authorization": f"Bearer {credential}"} if credential else {}
        )


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/v1/capability-graph", "/v1/capability-graph/risks"])
@pytest.mark.parametrize("token", [None, "short", "z" * 64])
async def test_anonymous_and_unverified_callers_cannot_read_graph(
    graph_database, settings, path, token
):
    response = await get(graph_app(graph_database, settings), path, token)
    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert "case-1042" not in response.text


@pytest.mark.anyio
async def test_self_scope_models_and_cache_control(graph_database, settings, credential):
    app = graph_app(graph_database, settings)
    response = await get(app, "/v1/capability-graph?agent_id=support-agent", credential)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    graph = GraphProjection.model_validate(response.json())
    assert graph.capabilities.agent_id == "support-agent"
    response = await get(app, "/v1/capability-graph/risks", credential)
    assert response.status_code == 200
    assert len(RiskAnalysis.model_validate(response.json()).findings) == 1
    response = await get(app, "/v1/capability-graph?agent_id=other-agent", credential)
    assert response.status_code == 403


@pytest.mark.anyio
@pytest.mark.parametrize(
    "target",
    ["principal", "binding", "unverified_binding", "principal_revocation", "binding_revocation"],
)
async def test_current_identity_state_is_checked_each_graph_request(
    graph_database, settings, credential, target
):
    app = graph_app(graph_database, settings)
    assert (await get(app, "/v1/capability-graph", credential)).status_code == 200
    with graph_database.begin() as session:
        binding = session.scalar(select(PrincipalBinding))
        if target == "principal":
            session.get(Principal, "support-agent").status = "INACTIVE"
        elif target == "binding":
            binding.status = "REVOKED"
        elif target == "unverified_binding":
            binding.verified_at = None
        elif target == "principal_revocation":
            session.add(
                Revocation(
                    principal_id="support-agent", reason="Synthetic graph principal revocation"
                )
            )
        else:
            session.add(
                Revocation(binding_id=binding.id, reason="Synthetic graph binding revocation")
            )
    assert (await get(app, "/v1/capability-graph", credential)).status_code == 401


@pytest.mark.anyio
@pytest.mark.parametrize(
    "query",
    [
        "max_depth=0",
        "max_depth=33",
        "max_nodes=1",
        "max_nodes=2001",
        "max_edges=5001",
        "max_findings=101",
        "agent_id=",
    ],
)
async def test_query_bounds_are_validated(graph_database, settings, credential, query):
    response = await get(
        graph_app(graph_database, settings), "/v1/capability-graph/risks?" + query, credential
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_file_mode_has_no_sensitive_database_explorer(settings, credential):
    response = await get(create_app(settings), "/v1/capability-graph", credential)
    assert response.status_code == 503


@pytest.mark.anyio
async def test_local_bearer_is_not_presented_as_production_graph_authorization(
    graph_database, settings, credential
):
    app = create_app(
        settings.model_copy(update={"env": "production"}),
        graph_service=GraphService(graph_database),
    )
    assert (await get(app, "/v1/capability-graph", credential)).status_code == 503


@pytest.mark.anyio
async def test_database_error_is_fail_closed_and_sanitized(graph_database, settings, credential):
    ProvenanceEdge.__table__.drop(graph_database.kw["bind"])
    response = await get(graph_app(graph_database, settings), "/v1/capability-graph", credential)
    assert response.status_code == 503
    assert response.json() == {"detail": "Trusted graph database unavailable"}
    assert credential not in response.text and "sqlite" not in response.text


@pytest.mark.anyio
async def test_graph_queries_do_not_evaluate_or_write_pdp_decisions(
    graph_database, settings, credential
):
    class NeverOPA:
        async def evaluate(self, _document):
            pytest.fail("Graph analysis must not invoke OPA")

    class NeverAudit:
        def record(self, *_args):
            pytest.fail("Graph reads must not create authorization audit records")

    app = create_app(
        settings.model_copy(update={"env": "development"}),
        opa=NeverOPA(),
        audit=NeverAudit(),
        graph_service=GraphService(graph_database),
    )
    assert (await get(app, "/v1/capability-graph/risks", credential)).status_code == 200


@pytest.mark.anyio
async def test_postgres_app_factory_wires_graph_service(
    graph_database, settings, credential, monkeypatch
):
    monkeypatch.setattr(
        "agentguard_backend.db.engine.postgres_sessions", lambda *_args: graph_database
    )
    configured = settings.model_copy(
        update={
            "pdp_context_backend": "postgres",
            "env": "development",
            "database_url": SecretStr("postgresql+psycopg://unused/test"),
        }
    )
    assert (
        await get(create_app(configured), "/v1/capability-graph", credential)
    ).status_code == 200


@pytest.mark.anyio
async def test_graph_potential_pdp_real_rego_denial_and_revocation(
    graph_database, settings, credential, authorization_request
):
    executable = shutil.which("opa")
    if executable is None:
        pytest.skip("OPA CLI required for the synthetic graph/PDP real Rego vertical slice")
    policy = Path(__file__).resolve().parents[1] / "policies/authorize.rego"

    def handler(request):
        result = subprocess.run(
            [
                executable,
                "eval",
                "--stdin-input",
                "--data",
                str(policy),
                "--format=json",
                "data.agentguard.authz.decision",
            ],
            input=json.dumps(json.loads(request.content)["input"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
        return httpx.Response(200, json={"result": value})

    opa = OPAClient(
        str(settings.opa_url),
        settings.opa_decision_path,
        settings.opa_timeout_seconds,
        settings.opa_policy_version,
        transport=httpx.MockTransport(handler),
    )
    app = create_app(
        settings.model_copy(update={"env": "development"}),
        resolver=PostgresContextResolver(graph_database),
        opa=opa,
        audit=DatabaseAuditWriter(graph_database),
        graph_service=GraphService(graph_database),
    )
    headers = {"Authorization": f"Bearer {credential}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        potential = await client.get("/v1/capability-graph/risks", headers=headers)
        assert len(potential.json()["findings"]) == 1
        read = await client.post("/v1/authorize", headers=headers, json=authorization_request)
        assert read.json()["policy_decision"]["decision"] == "ALLOW"
        body = {
            **authorization_request,
            "request_id": "graph-egress",
            "action": "email.send",
            "resource": {
                "id": "report-1042",
                "type": "report",
                "asserted_classification": "PUBLIC",
            },
            "destination": "outsider@example.test",
            "context": {"classification": "PUBLIC", "agent_id": "other-agent"},
        }
        denied = await client.post("/v1/authorize", headers=headers, json=body)
        assert denied.json()["policy_decision"]["decision"] == "DENY"
        assert denied.json()["policy_decision"]["reason_code"] == "CG-DATA-EGRESS-001"
        audited = (await client.get("/v1/capability-graph", headers=headers)).json()
        assert len(audited["policy_decisions"]) == 2
        assert audited["execution_evidence"] == "NOT_RECORDED"
        with graph_database.begin() as session:
            permission = session.scalar(select(Permission).where(Permission.action == "email.send"))
            session.add(Revocation(permission_id=permission.id, reason="Synthetic demo revocation"))
        after = await client.get("/v1/capability-graph/risks", headers=headers)
        assert after.json()["findings"] == []
        revoked = await client.post("/v1/authorize", headers=headers, json=body)
        assert revoked.json()["policy_decision"]["reason_code"] == "CG-PERMISSION-REVOKED"
        historical = (await client.get("/v1/capability-graph", headers=headers)).json()
        assert any(edge["relationship"] == "DERIVED_FROM" for edge in historical["graph"]["edges"])
