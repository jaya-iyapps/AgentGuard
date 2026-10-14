import asyncio

import pytest
from agentguard_contracts import AuthorizationRequest, ResourceReference, TrustedContext
from agentguard_gateway.interfaces import DisabledAuthorizationClient, TrustedContextResolver


def test_disabled_client_fails_closed():
    request = AuthorizationRequest(
        request_id="r",
        session_id="s",
        action="email.send",
        resource=ResourceReference(id="example", type="report"),
    )
    trusted = TrustedContext(agent_id="a", adapter_id="test", surface="test")
    response = asyncio.run(DisabledAuthorizationClient().authorize(request, trusted))

    assert response.policy_decision.decision == "DENY"
    assert response.policy_decision.reason_code == "NOT_IMPLEMENTED"


def test_gateway_configuration_defaults_to_local_core():
    pytest.importorskip("pydantic_settings", reason="Gateway settings dependency is not installed.")
    from agentguard_gateway.config import GatewaySettings

    assert str(GatewaySettings(_env_file=None).policy_url) == "http://127.0.0.1:8000/"
    assert GatewaySettings(_env_file=None).archive_mcp_url is None


class RecordingAuthenticator:
    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.credentials: list[str] = []

    async def authenticate(self, credential: str):
        self.credentials.append(credential)
        if self.error is not None:
            raise self.error
        return self.response


def test_trusted_context_resolver_rejects_absent_credentials_without_authentication():
    authenticator = RecordingAuthenticator(
        response=TrustedContext(agent_id="a", adapter_id="x", surface="mcp")
    )

    result = asyncio.run(TrustedContextResolver(authenticator).resolve(None))

    assert result is None
    assert authenticator.credentials == []


@pytest.mark.parametrize(
    ("response", "error"),
    [
        ({"agent_id": "caller-controlled"}, None),
        (None, RuntimeError("identity provider unavailable")),
    ],
)
def test_trusted_context_resolver_fails_closed_on_invalid_or_unavailable_authentication(
    response, error
):
    authenticator = RecordingAuthenticator(response=response, error=error)

    result = asyncio.run(TrustedContextResolver(authenticator).resolve("credential"))

    assert result is None
    assert authenticator.credentials == ["credential"]


def test_trusted_context_resolver_revalidates_authenticator_result():
    invalid_model = TrustedContext.model_construct(
        agent_id="agent", adapter_id="adapter", surface="untrusted-surface"
    )

    result = asyncio.run(
        TrustedContextResolver(RecordingAuthenticator(invalid_model)).resolve("credential")
    )

    assert result is None


def test_trusted_context_resolver_returns_verified_context():
    expected = TrustedContext(agent_id="agent", adapter_id="adapter", surface="mcp")

    result = asyncio.run(
        TrustedContextResolver(RecordingAuthenticator(expected)).resolve("credential")
    )

    assert result == expected
