"""Real OPA checks: explicitly skipped if the CLI or an opt-in HTTP server is absent."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from agentguard_backend.app import create_app

POLICIES = Path(__file__).resolve().parents[1] / "policies"


def test_real_rego_suite():
    executable = shutil.which("opa")
    if executable is None:
        pytest.skip("OPA CLI not installed; run make opa-test or the OPA CI job")
    result = subprocess.run(
        [executable, "test", str(POLICIES), "--verbose"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.anyio
async def test_real_opa_http_authorization(
    settings, context_path, context_document, credential, authorization_request
):
    url = os.getenv("AG_TEST_OPA_URL")
    if not url:
        pytest.skip("Set AG_TEST_OPA_URL to explicitly test a running local OPA server")
    settings = settings.model_copy(update={"opa_url": url})
    app = create_app(settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/authorize",
            json=authorization_request,
            headers={"Authorization": f"Bearer {credential}"},
        )
        assert response.json()["policy_decision"]["decision"] == "ALLOW", response.text
        egress = {
            **authorization_request,
            "request_id": "egress-001",
            "action": "email.send",
            "resource": {"id": "report-1042", "type": "report"},
            "destination": "outsider@example.test",
        }
        response = await client.post(
            "/v1/authorize", json=egress, headers={"Authorization": f"Bearer {credential}"}
        )
        assert response.json()["policy_decision"]["reason_code"] == "CG-DATA-EGRESS-001", (
            response.text
        )
        context_document["identities"][0]["permissions"][0]["status"] = "REVOKED"
        context_path.write_text(json.dumps(context_document))
        response = await client.post(
            "/v1/authorize",
            json=authorization_request,
            headers={"Authorization": f"Bearer {credential}"},
        )
        assert response.json()["policy_decision"]["reason_code"] == "CG-PERMISSION-REVOKED", (
            response.text
        )
