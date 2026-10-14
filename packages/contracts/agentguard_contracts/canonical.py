"""Canonical request binding shared by the PDP and its enforcement clients."""

import hashlib
import json

from agentguard_contracts import AuthorizationRequest


def request_digest(request: AuthorizationRequest) -> str:
    canonical = json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
