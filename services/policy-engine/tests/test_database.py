import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from agentguard_backend.app import create_app
from agentguard_backend.db.audit import DatabaseAuditWriter
from agentguard_backend.db.engine import postgres_sessions
from agentguard_backend.db.models import (
    AuthorizationAudit,
    Base,
    Permission,
    Principal,
    PrincipalBinding,
    ProvenanceEdge,
    Resource,
    Revocation,
    utc_now,
)
from agentguard_backend.db.provenance import InconsistentProvenance, create_report, trusted_lineage
from agentguard_backend.db.resolver import PostgresContextResolver
from agentguard_backend.db.seed import seed_context
from agentguard_backend.pdp.context import ContextUnavailable
from agentguard_backend.pdp.models import ContextDocument
from agentguard_backend.pdp.opa import OPAClient
from agentguard_contracts import AuthorizationRequest

DATABASES = ["sqlite"] + (["postgres"] if os.getenv("AG_TEST_DATABASE_URL") else [])


@pytest.fixture(params=DATABASES)
def database(request, tmp_path, context_document):
    admin_engine = None
    if request.param == "postgres":
        url = os.environ["AG_TEST_DATABASE_URL"]
        admin_engine = create_engine(url, hide_parameters=True)
        schema = "pdp_test_" + uuid.uuid4().hex
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(
            url,
            hide_parameters=True,
            isolation_level="REPEATABLE READ",
            connect_args={"options": f"-c search_path={schema}"},
        )
    else:
        engine = create_engine(
            f"sqlite:///{tmp_path / 'test-context.sqlite3'}", hide_parameters=True
        )

        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

    try:
        Base.metadata.create_all(engine)
        sessions = sessionmaker(engine, expire_on_commit=False)
        seed_context(sessions, ContextDocument.model_validate(context_document))
        yield sessions
    finally:
        engine.dispose()
        if admin_engine is not None:
            # Delete only the UUID-named schema this fixture created in the opt-in test database.
            with admin_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin_engine.dispose()


def resolved(database, credential, authorization_request):
    request = AuthorizationRequest.model_validate(authorization_request)
    return PostgresContextResolver(database).resolve(f"Bearer {credential}", request)


def test_verified_database_context_ignores_agent_claims(
    database, credential, authorization_request
):
    authorization_request.update(context={"agent_id": "admin", "classification": "PUBLIC"})
    authorization_request["resource"]["asserted_classification"] = "PUBLIC"
    facts = resolved(database, credential, authorization_request)
    assert facts.identity.agent_id == "support-agent"
    assert facts.identity.verified is True
    assert facts.permission_status == "ACTIVE"
    assert facts.resource.classification == "CONFIDENTIAL"


@pytest.mark.parametrize("credential_value", [None, "short", "z" * 64])
def test_invalid_credentials_do_not_resolve(database, authorization_request, credential_value):
    request = AuthorizationRequest.model_validate(authorization_request)
    header = f"Bearer {credential_value}" if credential_value else None
    assert not PostgresContextResolver(database).resolve(header, request).identity.verified


def test_derived_report_stores_and_inherits_confidential_classification(database):
    with database.begin() as session:
        report = create_report(session, "new-report", "support-agent", ["case-1042"])
        assert report.classification == "CONFIDENTIAL"
    with database.begin() as session:
        report, classification, parents = trusted_lineage(session, "new-report")
        assert report.classification == classification == "CONFIDENTIAL"
        assert parents == ["case-1042"]


def test_multihop_inheritance_and_source_reclassification(database):
    with database.begin() as session:
        create_report(session, "summary", "support-agent", ["report-1042"])
        session.get(Resource, "case-1042").classification = "RESTRICTED"
    with database.begin() as session:
        _, classification, ancestors = trusted_lineage(session, "summary")
        assert classification == "RESTRICTED"
        assert ancestors == ["case-1042", "report-1042"]


def test_multiple_inputs_inherit_the_highest_label(database):
    with database.begin() as session:
        session.add(
            Resource(
                id="public-guide",
                type="document",
                owner_principal_id="support-agent",
                classification="PUBLIC",
                origin="SOURCE",
                verified_at=utc_now(),
            )
        )
        session.flush()
        report = create_report(
            session, "combined-report", "support-agent", ["public-guide", "case-1042"]
        )
        assert report.classification == "CONFIDENTIAL"
    with database() as session:
        _, classification, parents = trusted_lineage(session, "combined-report")
        assert classification == "CONFIDENTIAL"
        assert parents == ["case-1042", "public-guide"]


@pytest.mark.parametrize("target", ["principal", "binding", "permission"])
def test_revocations_override_active_flags_each_request(
    database, credential, authorization_request, target
):
    assert resolved(database, credential, authorization_request).permission_status == "ACTIVE"
    with database.begin() as session:
        principal = session.get(Principal, "support-agent")
        binding = session.scalar(select(PrincipalBinding))
        permission = session.scalar(select(Permission).where(Permission.action == "case.read"))
        values = {
            "principal": {"principal_id": principal.id},
            "binding": {"binding_id": binding.id},
            "permission": {"permission_id": permission.id},
        }
        session.add(Revocation(reason="Synthetic revocation test", **values[target]))
    facts = resolved(database, credential, authorization_request)
    if target == "permission":
        assert facts.permission_status == "REVOKED"
    else:
        assert facts.identity.status == "REVOKED"


def test_missing_and_inactive_permissions_are_current(database, credential, authorization_request):
    with database.begin() as session:
        permission = session.scalar(select(Permission).where(Permission.action == "case.read"))
        permission.status = "INACTIVE"
    assert resolved(database, credential, authorization_request).permission_status == "INACTIVE"
    with database.begin() as session:
        session.delete(session.scalar(select(Permission).where(Permission.action == "case.read")))
    assert resolved(database, credential, authorization_request).permission_status == "MISSING"


@pytest.mark.parametrize("corruption", ["missing_parent", "cycle", "unverified", "owner"])
def test_inconsistent_provenance_fails_closed(
    database, credential, authorization_request, corruption
):
    authorization_request.update(
        action="email.send", resource={"id": "report-1042", "type": "report"}
    )
    with database.begin() as session:
        if corruption == "missing_parent":
            session.delete(session.get(ProvenanceEdge, ("case-1042", "report-1042")))
        elif corruption == "cycle":
            create_report(session, "cycle-report", "support-agent", ["report-1042"])
            session.add(ProvenanceEdge(parent_id="cycle-report", child_id="report-1042"))
        elif corruption == "unverified":
            session.get(Resource, "case-1042").verified_at = None
        else:
            session.add(Principal(id="another-agent", status="ACTIVE"))
            session.flush()
            session.get(Resource, "case-1042").owner_principal_id = "another-agent"
    with pytest.raises(ContextUnavailable):
        resolved(database, credential, authorization_request)


def test_report_creation_is_atomic_on_invalid_source(database):
    with pytest.raises(InconsistentProvenance), database.begin() as session:
        create_report(session, "invalid-report", "support-agent", ["missing-case"])
    with database() as session:
        assert session.get(Resource, "invalid-report") is None


def test_database_error_and_missing_resource_fail_closed(
    database, credential, authorization_request
):
    request = AuthorizationRequest.model_validate(
        {**authorization_request, "resource": {"id": "unknown", "type": "case"}}
    )
    with pytest.raises(ContextUnavailable):
        PostgresContextResolver(database).resolve(f"Bearer {credential}", request)
    Base.metadata.drop_all(database.kw["bind"])
    with pytest.raises(ContextUnavailable):
        resolved(database, credential, authorization_request)


def test_uniqueness_and_revocation_constraints(database):
    with pytest.raises(IntegrityError), database.begin() as session:
        binding = session.scalar(select(PrincipalBinding))
        session.add(
            PrincipalBinding(
                principal_id=binding.principal_id,
                adapter_id="duplicate",
                surface="mcp",
                credential_sha256=binding.credential_sha256,
                status="ACTIVE",
                verified_at=utc_now(),
            )
        )
    with pytest.raises(IntegrityError), database.begin() as session:
        session.add(Revocation(reason="No target"))


def mock_opa(settings, handler):
    return OPAClient(
        str(settings.opa_url),
        settings.opa_decision_path,
        settings.opa_timeout_seconds,
        settings.opa_policy_version,
        transport=httpx.MockTransport(handler),
    )


def opa_response(binding, decision="ALLOW", reason_code="CG-ALLOW-001"):
    return httpx.Response(
        200,
        json={
            "result": {
                "decision": decision,
                "reason_code": reason_code,
                "explanation": "Synthetic OPA result",
                "policy_version": "pdp-v1",
                "request_id": binding["request_id"],
                "action": binding["action"],
                "request_digest": binding["request_digest"],
            }
        },
    )


@pytest.mark.anyio
async def test_database_endpoint_classification_and_audit(
    database, settings, credential, authorization_request
):
    authorization_request.update(
        action="email.send",
        destination="outsider@example.test",
        resource={"id": "report-1042", "type": "report", "asserted_classification": "PUBLIC"},
        context={"agent_id": "admin"},
        provenance_refs=["fake-public"],
    )

    def handler(request):
        document = json.loads(request.content)["input"]
        facts = document["facts"]
        assert facts["resource"]["classification"] == "CONFIDENTIAL"
        assert facts["resource"]["provenance_refs"] == ["case-1042"]
        return opa_response(document["request"], "DENY", "CG-DATA-EGRESS-001")

    app = create_app(
        settings,
        resolver=PostgresContextResolver(database),
        opa=mock_opa(settings, handler),
        audit=DatabaseAuditWriter(database),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/authorize",
            json=authorization_request,
            headers={"Authorization": f"Bearer {credential}"},
        )
    decision = response.json()["policy_decision"]
    assert decision["decision"] == "DENY"
    with database() as session:
        audit = session.get(AuthorizationAudit, decision["decision_id"])
        assert audit.principal_id == "support-agent"
        assert audit.resource_classification == "CONFIDENTIAL"
        assert audit.provenance_refs == ["case-1042"]
        assert audit.request_digest == response.headers["X-AgentGuard-Request-Digest"]


@pytest.mark.anyio
async def test_audit_failure_prevents_allow(database, settings, credential, authorization_request):
    def handler(request):
        binding = json.loads(request.content)["input"]["request"]
        return opa_response(binding)

    AuthorizationAudit.__table__.drop(database.kw["bind"])
    app = create_app(
        settings,
        resolver=PostgresContextResolver(database),
        opa=mock_opa(settings, handler),
        audit=DatabaseAuditWriter(database),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/authorize",
            json=authorization_request,
            headers={"Authorization": f"Bearer {credential}"},
        )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == "CG-AUDIT-UNAVAILABLE"


@pytest.mark.anyio
async def test_allow_is_audited_and_next_request_observes_revocation(
    database, settings, credential, authorization_request
):
    def handler(request):
        document = json.loads(request.content)["input"]
        binding = document["request"]
        revoked = document["facts"]["permission_status"] == "REVOKED"
        return opa_response(
            binding,
            "DENY" if revoked else "ALLOW",
            "CG-PERMISSION-REVOKED" if revoked else "CG-ALLOW-001",
        )

    app = create_app(
        settings,
        resolver=PostgresContextResolver(database),
        opa=mock_opa(settings, handler),
        audit=DatabaseAuditWriter(database),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        before = await client.post(
            "/v1/authorize",
            json=authorization_request,
            headers={"Authorization": f"Bearer {credential}"},
        )
        with database.begin() as session:
            grant = session.scalar(select(Permission).where(Permission.action == "case.read"))
            session.add(Revocation(permission_id=grant.id, reason="Test active-session revocation"))
        after = await client.post(
            "/v1/authorize",
            json=authorization_request,
            headers={"Authorization": f"Bearer {credential}"},
        )
    assert before.json()["policy_decision"]["decision"] == "ALLOW"
    assert after.json()["policy_decision"]["decision"] == "DENY"
    with database() as session:
        first = session.get(AuthorizationAudit, before.json()["policy_decision"]["decision_id"])
        second = session.get(AuthorizationAudit, after.json()["policy_decision"]["decision_id"])
        assert first.decision == "ALLOW" and first.permission_status == "ACTIVE"
        assert second.decision == "DENY" and second.permission_status == "REVOKED"


def test_unverified_binding_cannot_claim_a_verified_principal(
    database, credential, authorization_request
):
    with database.begin() as session:
        session.scalar(select(PrincipalBinding)).verified_at = None
    assert not resolved(database, credential, authorization_request).identity.verified


def test_seed_preserves_existing_database(database, context_document):
    with pytest.raises(ValueError, match="preserved"):
        seed_context(database, ContextDocument.model_validate(context_document))


@pytest.mark.anyio
async def test_postgres_setting_wires_database_resolver_and_required_audit(
    database, settings, credential, authorization_request, monkeypatch
):
    monkeypatch.setattr("agentguard_backend.db.engine.postgres_sessions", lambda *_args: database)
    configured = settings.model_copy(
        update={
            "pdp_context_backend": "postgres",
            "pdp_context_path": "",
            "database_url": SecretStr("postgresql+psycopg://unused/test"),
        }
    )

    def handler(request):
        return opa_response(json.loads(request.content)["input"]["request"])

    app = create_app(configured, opa=mock_opa(settings, handler))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/authorize",
                json=authorization_request,
                headers={"Authorization": f"Bearer {credential}"},
            )
        decision = response.json()["policy_decision"]
        assert decision["decision"] == "ALLOW"
        with database() as session:
            assert session.get(AuthorizationAudit, decision["decision_id"]).decision == "ALLOW"


@pytest.mark.parametrize("url", ["", "sqlite:///untrusted.db", "postgresql+psycopg2://localhost"])
def test_runtime_rejects_missing_or_non_postgresql_configuration(url):
    with pytest.raises(ValueError):
        postgres_sessions(url)


@pytest.mark.anyio
async def test_database_facts_with_real_rego(database, settings, credential, authorization_request):
    executable = shutil.which("opa")
    if executable is None:
        pytest.skip("OPA CLI required to evaluate database facts against the unchanged real Rego")
    policy = Path(__file__).resolve().parents[1] / "policies" / "authorize.rego"

    def handler(request):
        # Real policy evaluation without TCP sockets. HTTP client validation still runs;
        # this is not a live OPA HTTP transport test.
        input_document = json.loads(request.content)["input"]
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
            input=json.dumps(input_document),
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
        return httpx.Response(200, json={"result": value})

    app = create_app(
        settings,
        resolver=PostgresContextResolver(database),
        opa=mock_opa(settings, handler),
        audit=DatabaseAuditWriter(database),
    )
    headers = {"Authorization": f"Bearer {credential}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        read = await client.post("/v1/authorize", json=authorization_request, headers=headers)
        assert read.json()["policy_decision"]["decision"] == "ALLOW"
        egress = {
            **authorization_request,
            "request_id": "database-rego-egress",
            "action": "email.send",
            "destination": "outsider@example.test",
            "resource": {
                "id": "report-1042",
                "type": "report",
                "asserted_classification": "PUBLIC",
            },
        }
        blocked = await client.post("/v1/authorize", json=egress, headers=headers)
        assert blocked.json()["policy_decision"]["reason_code"] == "CG-DATA-EGRESS-001"
        with database.begin() as session:
            grant = session.scalar(select(Permission).where(Permission.action == "case.read"))
            session.add(Revocation(permission_id=grant.id, reason="Real Rego revocation test"))
        revoked = await client.post("/v1/authorize", json=authorization_request, headers=headers)
        assert revoked.json()["policy_decision"]["reason_code"] == "CG-PERMISSION-REVOKED"
