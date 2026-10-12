import json
from pathlib import Path

import agentguard_contracts as contracts
import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = json.loads((ROOT / "demo/fixtures/contracts.json").read_text())


@pytest.mark.parametrize("name", EXAMPLES)
def test_examples_match_pydantic_and_json_schema(name):
    model = getattr(contracts, name)
    model.model_validate(EXAMPLES[name])
    schema = json.loads((ROOT / f"packages/contracts/schemas/{name}.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(EXAMPLES[name])


@pytest.mark.parametrize("field", ["agent_id", "principal", "trusted_context"])
def test_request_cannot_claim_authenticated_identity(field):
    with pytest.raises(ValidationError):
        contracts.AuthorizationRequest.model_validate(
            {**EXAMPLES["AuthorizationRequest"], field: "admin"}
        )


def test_asserted_classification_is_separate_from_verified_context():
    request = contracts.AuthorizationRequest.model_validate(EXAMPLES["AuthorizationRequest"])
    trusted = contracts.TrustedContext.model_validate(EXAMPLES["TrustedContext"])
    assert request.resource.asserted_classification == "PUBLIC"
    assert trusted.resource_classification == "CONFIDENTIAL"


def test_decision_rejects_unknown_outcomes():
    example = {**EXAMPLES["AuthorizationResponse"]["policy_decision"], "decision": "MAYBE"}
    with pytest.raises(ValidationError):
        contracts.PolicyDecision.model_validate(example)
