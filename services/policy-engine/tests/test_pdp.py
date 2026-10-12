import json
from datetime import datetime

import httpx
import pytest

from agentguard_backend.app import create_app
from agentguard_backend.pdp.models import OPAResult
from agentguard_backend.pdp.opa import OPAClient
from agentguard_backend.pdp.service import request_digest
from agentguard_contracts import AuthorizationRequest, AuthorizationResponse


def opa_client(settings, handler):
    return OPAClient(
        str(settings.opa_url),
        settings.opa_decision_path,
        settings.opa_timeout_seconds,
        settings.opa_policy_version,
        transport=httpx.MockTransport(handler),
    )


def result_for(document, decision="ALLOW", reason="CG-ALLOW-001"):
    request = document["request"]
    return {
        "decision": decision,
        "reason_code": reason,
        "explanation": "Synthetic OPA result",
        "policy_version": "pdp-v1",
        "request_id": request["request_id"],
        "action": request["action"],
        "request_digest": request["request_digest"],
    }


async def post(app, body, credential=None):
    headers = {"Authorization": f"Bearer {credential}"} if credential else {}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.post("/v1/authorize", json=body, headers=headers)


@pytest.mark.anyio
async def test_authorized_read_and_correlated_response(settings, credential, authorization_request):
    captured = []

    def handler(request):
        assert request.url.path == "/v1/data/agentguard/authz/decision"
        document = json.loads(request.content)["input"]
        captured.append(document)
        return httpx.Response(200, json={"result": result_for(document)})

    app = create_app(settings, opa=opa_client(settings, handler))
    response = await post(app, authorization_request, credential)
    parsed = AuthorizationResponse.model_validate(response.json())
    assert response.status_code == 200
    assert parsed.policy_decision.decision == "ALLOW"
    assert parsed.policy_decision.request_id == authorization_request["request_id"]
    assert parsed.policy_decision.decision_id
    digest = request_digest(AuthorizationRequest.model_validate(authorization_request))
    assert response.headers["X-AgentGuard-Request-Digest"] == digest
    expires = datetime.fromisoformat(response.headers["X-AgentGuard-Decision-Expires-At"])
    assert (expires - parsed.policy_decision.timestamp).total_seconds() == 5
    assert response.headers["Cache-Control"] == "no-store"
    assert captured[0]["facts"]["identity"]["agent_id"] == "support-agent"
    assert captured[0]["facts"]["resource"]["classification"] == "CONFIDENTIAL"


@pytest.mark.anyio
@pytest.mark.parametrize("credential_value", [None, "short", "z" * 64])
async def test_missing_or_invalid_identity_denies_before_opa(
    settings, authorization_request, credential_value
):
    def handler(_request):
        pytest.fail("Unverified callers must not reach OPA")

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)),
        authorization_request,
        credential_value,
    )
    decision = response.json()["policy_decision"]
    assert decision["decision"] == "DENY"
    assert decision["reason_code"] == "CG-IDENTITY-UNVERIFIED"


@pytest.mark.anyio
async def test_confidential_egress_ignores_caller_claims(settings, credential, authorization_request):
    authorization_request.update(
        action="email.send",
        destination="outsider@example.test",
        resource={
            "id": "report-1042", "type": "report", "asserted_classification": "PUBLIC"
        },
        provenance_refs=["fake-public-source"],
        context={"agent_id": "admin", "classification": "PUBLIC"},
    )

    def handler(request):
        document = json.loads(request.content)["input"]
        assert document["facts"]["resource"]["classification"] == "CONFIDENTIAL"
        assert document["facts"]["resource"]["provenance_refs"] == ["case-1042"]
        assert document["facts"]["identity"]["agent_id"] == "support-agent"
        assert document["facts"]["destination"] == {"valid": True, "approved": False}
        assert "asserted_classification" not in request.content.decode()
        return httpx.Response(
            200, json={"result": result_for(document, "DENY", "CG-DATA-EGRESS-001")}
        )

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.json()["policy_decision"]["reason_code"] == "CG-DATA-EGRESS-001"
    assert response.json()["policy_decision"]["decision"] == "DENY"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "status,reason",
    [
        ("MISSING", "CG-PERMISSION-MISSING"),
        ("INACTIVE", "CG-PERMISSION-INACTIVE"),
        ("REVOKED", "CG-PERMISSION-REVOKED"),
    ],
)
async def test_current_permission_state(
    settings, context_path, context_document, credential, authorization_request, status, reason
):
    if status == "MISSING":
        context_document["identities"][0]["permissions"] = []
    else:
        context_document["identities"][0]["permissions"][0]["status"] = status
    context_path.write_text(json.dumps(context_document))

    def handler(request):
        document = json.loads(request.content)["input"]
        assert document["facts"]["permission_status"] == status
        return httpx.Response(200, json={"result": result_for(document, "DENY", reason)})

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == reason


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["timeout", "connection", "http"])
async def test_opa_unavailable_is_structured_deny(
    settings, credential, authorization_request, failure
):
    def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        if failure == "connection":
            raise httpx.ConnectError("synthetic unreachable core", request=request)
        return httpx.Response(503)

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.status_code == 200
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == "CG-OPA-UNAVAILABLE"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "another-request"),
        ("action", "admin.delete"),
        ("request_digest", "another-digest"),
        ("policy_version", "unexpected-version"),
        ("reason_code", "UNKNOWN_ALLOW"),
    ],
)
async def test_mismatched_allow_never_escapes_as_allow(
    settings, credential, authorization_request, field, value
):
    def handler(request):
        result = result_for(json.loads(request.content)["input"])
        result[field] = value
        return httpx.Response(200, json={"result": result})

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["request_id"] == "request-001"
    assert response.json()["policy_decision"]["reason_code"] == "CG-OPA-INVALID"


@pytest.mark.anyio
async def test_coordinator_rechecks_injected_policy_client(
    settings, credential, authorization_request
):
    class UncorrelatedClient:
        async def evaluate(self, document):
            result = result_for(document.model_dump(mode="json"))
            result["action"] = "another-action"
            return OPAResult.model_validate(result)

    response = await post(
        create_app(settings, opa=UncorrelatedClient()), authorization_request, credential
    )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == "CG-OPA-INVALID"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload", [{}, {"result": None}, {"result": True}, {"result": {"decision": "ALLOW"}}]
)
async def test_undefined_or_malformed_opa_result_denies(
    settings, credential, authorization_request, payload
):
    def handler(_request):
        return httpx.Response(200, json=payload)

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == "CG-OPA-INVALID"


@pytest.mark.anyio
async def test_bad_context_configuration_denies(
    settings, context_path, credential, authorization_request
):
    context_path.write_text("not JSON")

    def handler(_request):
        pytest.fail("Unverified configuration must never reach OPA")

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == "CG-CONTEXT-UNAVAILABLE"


@pytest.mark.anyio
async def test_revocation_affects_next_request_in_same_session(
    settings, context_path, context_document, credential, authorization_request
):
    def handler(request):
        document = json.loads(request.content)["input"]
        revoked = document["facts"]["permission_status"] == "REVOKED"
        result = result_for(
            document,
            "DENY" if revoked else "ALLOW",
            "CG-PERMISSION-REVOKED" if revoked else "CG-ALLOW-001",
        )
        return httpx.Response(200, json={"result": result})

    app = create_app(settings, opa=opa_client(settings, handler))
    before = await post(app, authorization_request, credential)
    context_document["identities"][0]["permissions"][0]["status"] = "REVOKED"
    context_path.write_text(json.dumps(context_document))
    after = await post(app, authorization_request, credential)
    assert before.json()["policy_decision"]["decision"] == "ALLOW"
    assert after.json()["policy_decision"]["decision"] == "DENY"
    assert after.json()["policy_decision"]["reason_code"] == "CG-PERMISSION-REVOKED"
    before_id = before.json()["policy_decision"]["decision_id"]
    after_id = after.json()["policy_decision"]["decision_id"]
    assert before_id != after_id


@pytest.mark.anyio
async def test_non_json_opa_response_denies(settings, credential, authorization_request):
    def handler(_request):
        return httpx.Response(200, text="not JSON")

    response = await post(
        create_app(settings, opa=opa_client(settings, handler)), authorization_request, credential
    )
    assert response.json()["policy_decision"]["decision"] == "DENY"
    assert response.json()["policy_decision"]["reason_code"] == "CG-OPA-INVALID"


def test_digest_binds_action_and_all_model_defaults(authorization_request):
    initial = AuthorizationRequest.model_validate(authorization_request)
    reordered = AuthorizationRequest.model_validate(
        {**authorization_request, "context": {}, "provenance_refs": [], "destination": None}
    )
    different = initial.model_copy(update={"action": "email.send"})
    assert request_digest(initial) == request_digest(reordered)
    assert request_digest(initial) != request_digest(different)


@pytest.mark.anyio
async def test_extra_identity_fields_are_rejected(settings, credential, authorization_request):
    authorization_request["agent_id"] = "admin"
    response = await post(create_app(settings), authorization_request, credential)
    assert response.status_code == 422
