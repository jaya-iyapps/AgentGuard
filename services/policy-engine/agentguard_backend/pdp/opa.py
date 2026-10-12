"""OPA Data API client. Undefined, malformed, or uncorrelated decisions fail closed."""

from typing import Protocol

import httpx
from pydantic import ValidationError

from agentguard_backend.pdp.models import OPAResult, PolicyInput


class OPAUnavailable(Exception):
    """OPA request failed or timed out."""


class InvalidOPADecision(Exception):
    """OPA returned an undefined, malformed, or uncorrelated result."""


def validate_result(result: OPAResult, document: PolicyInput, policy_version: str) -> None:
    if (
        result.request_id != document.request.request_id
        or result.action != document.request.action
        or result.request_digest != document.request.request_digest
        or result.policy_version != policy_version
        or (result.decision == "ALLOW" and result.reason_code != "CG-ALLOW-001")
    ):
        raise InvalidOPADecision("Decision does not match the request or policy version")


class PolicyClient(Protocol):
    async def evaluate(self, document: PolicyInput) -> OPAResult:
        ...


class OPAClient:
    def __init__(
        self,
        url: str,
        path: str,
        timeout: float,
        policy_version: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.endpoint = f"{url.rstrip('/')}/v1/data/{path}"
        self.timeout = timeout
        self.policy_version = policy_version
        self.transport = transport

    async def evaluate(self, document: PolicyInput) -> OPAResult:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                transport=self.transport,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    self.endpoint, json={"input": document.model_dump(mode="json")}
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OPAUnavailable("OPA request failed") from exc
        try:
            payload = response.json()
            if not isinstance(payload, dict) or "result" not in payload:
                raise InvalidOPADecision("OPA decision is undefined")
            result = OPAResult.model_validate(payload["result"])
        except (ValueError, ValidationError) as exc:
            raise InvalidOPADecision("OPA decision is malformed") from exc
        validate_result(result, document, self.policy_version)
        return result
