"""Cross-service protocol tests, without enabling unauthenticated MCP execution."""

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from agentguard_backend.app import create_app
from agentguard_backend.config import Settings
from agentguard_backend.pdp.models import OPAResult
from agentguard_contracts import AuthorizationRequest, TrustedContext
from agentguard_contracts.canonical import request_digest
from agentguard_gateway.authorization import AuthorizationRejected, HTTPAuthorizationClient
from agentguard_gateway.config import GatewaySettings
from agentguard_gateway.mcp_server import InMemoryLocalArchiveStub, LocalArchiveDemo
from pydantic import SecretStr


@pytest.fixture
def gateway_settings():
    return GatewaySettings(
        _env_file=None,
        policy_url="http://backend:8000",
        policy_credential=secrets.token_urlsafe(32),
        policy_agent_id="support-agent",
        policy_adapter_id="mcp-adapter",
    )


@pytest.fixture
def trusted():
    return TrustedContext(agent_id="support-agent", adapter_id="mcp-adapter", surface="mcp")


@pytest.fixture
def authorization_request():
    return AuthorizationRequest(
        request_id="gateway-request",
        session_id="gateway-session",
        action="case.read",
        resource={"id": "case-1042", "type": "case"},
        context={"label": "Unicode résumé"},
    )


def decision_response(request):
    issued = datetime.now(timezone.utc)
    return {
        "contract_version": "1.0.0",
        "policy_decision": {
            "decision_id": "test-decision",
            "request_id": request.request_id,
            "decision": "ALLOW",
            "reason_code": "CG-ALLOW-001",
            "explanation": "Synthetic test decision.",
            "policy_version": "pdp-v1",
            "timestamp": issued.isoformat(),
        },
    }, {
        "X-AgentGuard-Request-Digest": request_digest(request),
        "X-AgentGuard-Decision-Expires-At": (issued + timedelta(seconds=5)).isoformat(),
    }


@pytest.mark.anyio
@pytest.mark.parametrize("decision", ["ALLOW", "DENY"])
async def test_gateway_uses_backend_authentication_and_canonical_headers(
    tmp_path, gateway_settings, trusted, authorization_request, decision
):
    request = authorization_request
    credential = gateway_settings.policy_credential.get_secret_value()
    context = tmp_path / "context.json"
    context.write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
                        "agent_id": trusted.agent_id,
                        "adapter_id": trusted.adapter_id,
                        "surface": "mcp",
                        "status": "ACTIVE",
                        "permissions": [
                            {"action": "case.read", "resource_id": "case-1042", "status": "ACTIVE"}
                        ],
                    }
                ],
                "resources": [
                    {
                        "id": "case-1042",
                        "type": "case",
                        "classification": "CONFIDENTIAL",
                        "owner_agent_id": trusted.agent_id,
                    }
                ],
            }
        )
    )

    class TestPolicy:
        async def evaluate(self, document):
            assert document.facts.identity.agent_id == trusted.agent_id
            assert document.request.request_digest == request_digest(request)
            return OPAResult(
                decision=decision,
                reason_code="CG-ALLOW-001" if decision == "ALLOW" else "TEST-DENY",
                explanation="Test-only policy transport.",
                policy_version="pdp-v1",
                request_id=document.request.request_id,
                action=document.request.action,
                request_digest=document.request.request_digest,
            )

    backend = create_app(
        Settings(_env_file=None, pdp_context_backend="file", pdp_context_path=str(context)),
        opa=TestPolicy(),
    )
    client = HTTPAuthorizationClient(gateway_settings, transport=httpx.ASGITransport(app=backend))
    result = await client.authorize(request, trusted)
    assert result.policy_decision.decision == decision
    # Invalid credentials are rejected by the actual backend before OPA evaluation.
    gateway_settings.policy_credential = SecretStr(secrets.token_urlsafe(32))
    result = await client.authorize(request, trusted)
    assert result.policy_decision.decision == "DENY"
    assert result.policy_decision.reason_code == "CG-IDENTITY-UNVERIFIED"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure",
    [
        "request_id",
        "digest",
        "missing_digest",
        "policy_version",
        "expired",
        "future",
        "naive_timestamp",
        "naive_expiry",
        "missing_expiry",
        "bad_expiry",
        "long_ttl",
        "non_utc",
        "empty_decision_id",
        "allow_reason",
        "malformed",
        "http_error",
        "redirect",
        "timeout",
    ],
)
async def test_invalid_pdp_decision_never_executes(gateway_settings, trusted, failure):
    def respond(incoming):
        assert str(incoming.url) == "http://backend:8000/v1/authorize"
        assert incoming.headers["Authorization"] == (
            "Bearer " + gateway_settings.policy_credential.get_secret_value()
        )
        sent = AuthorizationRequest.model_validate_json(incoming.content)
        assert "agent_id" not in json.loads(incoming.content)
        body, headers = decision_response(sent)
        decision = body["policy_decision"]
        now = datetime.now(timezone.utc)
        if failure == "request_id":
            decision["request_id"] = "another-request"
        elif failure == "digest":
            headers["X-AgentGuard-Request-Digest"] = "0" * 64
        elif failure == "missing_digest":
            headers.pop("X-AgentGuard-Request-Digest")
        elif failure == "policy_version":
            decision["policy_version"] = "other-policy"
        elif failure == "expired":
            decision["timestamp"] = (now - timedelta(seconds=10)).isoformat()
            headers["X-AgentGuard-Decision-Expires-At"] = (now - timedelta(seconds=5)).isoformat()
        elif failure == "future":
            decision["timestamp"] = (now + timedelta(seconds=2)).isoformat()
        elif failure == "naive_timestamp":
            decision["timestamp"] = now.replace(tzinfo=None).isoformat()
        elif failure == "naive_expiry":
            headers["X-AgentGuard-Decision-Expires-At"] = now.replace(tzinfo=None).isoformat()
        elif failure == "missing_expiry":
            headers.pop("X-AgentGuard-Decision-Expires-At")
        elif failure == "bad_expiry":
            headers["X-AgentGuard-Decision-Expires-At"] = "invalid"
        elif failure == "long_ttl":
            headers["X-AgentGuard-Decision-Expires-At"] = (now + timedelta(seconds=60)).isoformat()
        elif failure == "non_utc":
            decision["timestamp"] = now.astimezone(timezone(timedelta(hours=1))).isoformat()
        elif failure == "empty_decision_id":
            decision["decision_id"] = ""
        elif failure == "allow_reason":
            decision["reason_code"] = "TEST-DENY"
        elif failure == "malformed":
            return httpx.Response(200, content=b"not-json", headers=headers)
        elif failure == "http_error":
            return httpx.Response(503)
        elif failure == "redirect":
            return httpx.Response(307, headers={"Location": "https://untrusted.example"})
        elif failure == "timeout":
            raise httpx.ReadTimeout("test timeout")
        return httpx.Response(200, json=body, headers=headers)

    client = HTTPAuthorizationClient(gateway_settings, transport=httpx.MockTransport(respond))
    executor = InMemoryLocalArchiveStub()
    result = await LocalArchiveDemo(client, executor).invoke(
        record_id="synthetic-record", trusted=trusted, request_id="request", session_id="session"
    )
    assert result.isError is True
    assert executor.archived_record_ids == []


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["credential", "agent", "adapter", "surface"])
async def test_binding_mismatch_never_contacts_pdp(
    gateway_settings, trusted, authorization_request, failure
):
    request = authorization_request
    if failure == "credential":
        gateway_settings.policy_credential = SecretStr("")
    else:
        field = {"agent": "agent_id", "adapter": "adapter_id", "surface": "surface"}[failure]
        trusted = trusted.model_copy(update={field: "untrusted"})

    def unexpected(_):
        pytest.fail("Invalid binding contacted the PDP")

    client = HTTPAuthorizationClient(gateway_settings, transport=httpx.MockTransport(unexpected))
    with pytest.raises(AuthorizationRejected):
        await client.authorize(request, trusted)
