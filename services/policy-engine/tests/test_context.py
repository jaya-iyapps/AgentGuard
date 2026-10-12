import json

import pytest
from pydantic import ValidationError

from agentguard_backend.pdp.context import ContextUnavailable, FileContextResolver
from agentguard_backend.pdp.models import ContextDocument
from agentguard_contracts import AuthorizationRequest


def test_next_resolution_observes_revocation(
    context_path, context_document, credential, authorization_request
):
    resolver = FileContextResolver(str(context_path))
    request = AuthorizationRequest.model_validate(authorization_request)
    assert resolver.resolve(f"Bearer {credential}", request).permission_status == "ACTIVE"
    context_document["identities"][0]["permissions"][0]["status"] = "REVOKED"
    context_path.write_text(json.dumps(context_document))
    assert resolver.resolve(f"Bearer {credential}", request).permission_status == "REVOKED"


@pytest.mark.parametrize(
    "destination,approved",
    [
        ("support@company.example", True),
        ("SUPPORT@COMPANY.EXAMPLE", True),
        ("support@company.example.attacker.test", False),
        ("outsider@company.example", False),
        ("support@company.example\n", False),
        ("support@company.example,outsider@example.test", False),
    ],
)
def test_destination_requires_exact_approved_address(
    context_path, credential, authorization_request, destination, approved
):
    request = AuthorizationRequest.model_validate(
        {**authorization_request, "destination": destination}
    )
    facts = FileContextResolver(str(context_path)).resolve(f"Bearer {credential}", request)
    assert facts.destination.approved is approved


def test_no_config_is_fail_closed(credential, authorization_request):
    request = AuthorizationRequest.model_validate(authorization_request)
    with pytest.raises(ContextUnavailable):
        FileContextResolver("").resolve(f"Bearer {credential}", request)


@pytest.mark.parametrize("duplicate", ["credential", "resource", "permission"])
def test_ambiguous_configuration_is_rejected(context_document, duplicate):
    if duplicate == "credential":
        context_document["identities"].append(context_document["identities"][0])
    elif duplicate == "resource":
        context_document["resources"].append(context_document["resources"][0])
    else:
        grants = context_document["identities"][0]["permissions"]
        grants.append(grants[0])
    with pytest.raises(ValidationError):
        ContextDocument.model_validate(context_document)
