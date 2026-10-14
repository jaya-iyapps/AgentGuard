import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from agentguard_contracts import TrustedContext
from mcp.server.auth.provider import AccessToken

from agentguard_gateway.dev_auth import (
    CallerCredential,
    CallerCredentialStoreFile,
    DevBearerTokenVerifier,
    DevCallerCredentialStore,
    DevTokenMapper,
    generate_caller_token,
    hash_caller_token,
)


def write_store(path: Path, credentials: list[CallerCredential]) -> None:
    document = CallerCredentialStoreFile(version=1, credentials=credentials)
    path.write_text(document.model_dump_json(), encoding="utf-8")


def make_credential(
    token: str,
    *,
    credential_id: str = "test-caller",
    expires_at: datetime | None = None,
    active: bool = True,
    revoked_at: datetime | None = None,
    scopes: list[str] | None = None,
    agent_id: str = "support-agent",
    adapter_id: str = "local-mcp-adapter",
) -> CallerCredential:
    return CallerCredential(
        credential_id=credential_id,
        token_sha256=hash_caller_token(token),
        agent_id=agent_id,
        adapter_id=adapter_id,
        surface="mcp",
        scopes=scopes if scopes is not None else ["archive.execute"],
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(hours=1),
        active=active,
        revoked_at=revoked_at,
    )


def make_mapper(path: Path) -> DevTokenMapper:
    return DevTokenMapper(
        DevCallerCredentialStore(path),
        expected_agent_id="support-agent",
        expected_adapter_id="local-mcp-adapter",
    )


def test_generated_token_has_256_bits_of_entropy():
    token = generate_caller_token()
    assert len(token) >= 43
    assert all(character.isalnum() or character in "_-" for character in token)


def test_hash_is_sha256_and_differs_from_token():
    token = generate_caller_token()
    digest = hash_caller_token(token)
    assert len(digest) == 64
    assert digest != token
    assert all(character in "0123456789abcdef" for character in digest)


def test_valid_token_returns_access_token(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token)])

    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    result = asyncio.run(verifier.verify_token(token))

    assert isinstance(result, AccessToken)
    assert result.client_id == "test-caller"
    assert result.scopes == ["archive.execute"]
    assert result.resource == "http://127.0.0.1:8001/mcp"
    assert result.expires_at is not None


def test_unknown_token_is_rejected(tmp_path):
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(generate_caller_token())])
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    assert asyncio.run(verifier.verify_token(generate_caller_token())) is None


def test_malformed_token_is_rejected(tmp_path):
    path = tmp_path / "credentials.json"
    write_store(path, [])
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    assert asyncio.run(verifier.verify_token("invalid token!")) is None


def test_expired_token_is_rejected(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(
        path,
        [
            make_credential(
                token,
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
        ],
    )
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    assert asyncio.run(verifier.verify_token(token)) is None


def test_inactive_token_is_rejected(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token, active=False)])
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    assert asyncio.run(verifier.verify_token(token)) is None


def test_revoked_token_is_rejected(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(
        path,
        [make_credential(token, revoked_at=datetime.now(timezone.utc))],
    )
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    assert asyncio.run(verifier.verify_token(token)) is None


def test_missing_scope_is_rejected(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token, scopes=["other.scope"])])
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")
    assert asyncio.run(verifier.verify_token(token)) is None


def test_rotation_rejects_old_token_and_accepts_new_token(tmp_path):
    old_token = generate_caller_token()
    new_token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(old_token)])
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")

    assert asyncio.run(verifier.verify_token(old_token)) is not None
    write_store(path, [make_credential(new_token)])
    assert asyncio.run(verifier.verify_token(old_token)) is None
    assert asyncio.run(verifier.verify_token(new_token)) is not None


def test_revocation_takes_effect_on_next_lookup(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    credential = make_credential(token)
    write_store(path, [credential])
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")

    assert asyncio.run(verifier.verify_token(token)) is not None
    write_store(
        path,
        [
            credential.model_copy(
                update={
                    "active": False,
                    "revoked_at": datetime.now(timezone.utc),
                }
            )
        ],
    )
    assert asyncio.run(verifier.verify_token(token)) is None


@pytest.mark.parametrize("contents", ["{invalid json", '{"version": 99}'])
def test_malformed_store_fails_closed(tmp_path, contents, caplog):
    path = tmp_path / "credentials.json"
    path.write_text(contents, encoding="utf-8")
    verifier = DevBearerTokenVerifier(DevCallerCredentialStore(path), "http://127.0.0.1:8001/mcp")

    assert asyncio.run(verifier.verify_token(generate_caller_token())) is None
    assert "caller credential store could not be loaded" in caplog.text.lower()


def test_missing_store_fails_closed(tmp_path):
    verifier = DevBearerTokenVerifier(
        DevCallerCredentialStore(tmp_path / "missing.json"),
        "http://127.0.0.1:8001/mcp",
    )
    assert asyncio.run(verifier.verify_token(generate_caller_token())) is None


def test_store_contains_hash_not_raw_token(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token)])
    stored = path.read_text(encoding="utf-8")

    assert token not in stored
    assert hash_caller_token(token) in stored
    assert json.loads(stored)["version"] == 1


def test_mapper_uses_server_owned_identity(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token, credential_id="approved-caller")])
    access_token = AccessToken(token=token, client_id="approved-caller", scopes=["archive.execute"])

    result = asyncio.run(make_mapper(path).resolve(access_token))

    assert result == TrustedContext(
        agent_id="support-agent",
        adapter_id="local-mcp-adapter",
        surface="mcp",
    )


def test_mapper_rejects_token_mismatch(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token, credential_id="approved-caller")])
    access_token = AccessToken(
        token=generate_caller_token(),
        client_id="approved-caller",
        scopes=["archive.execute"],
    )

    with pytest.raises(ValueError):
        asyncio.run(make_mapper(path).resolve(access_token))


def test_mapper_rejects_revoked_credential(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    credential = make_credential(token, credential_id="approved-caller")
    write_store(path, [credential])
    access_token = AccessToken(token=token, client_id="approved-caller", scopes=["archive.execute"])

    write_store(
        path,
        [
            credential.model_copy(
                update={
                    "active": False,
                    "revoked_at": datetime.now(timezone.utc),
                }
            )
        ],
    )

    with pytest.raises(ValueError):
        asyncio.run(make_mapper(path).resolve(access_token))


def test_mapper_rejects_identity_mismatch(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(
        path,
        [
            make_credential(
                token,
                credential_id="approved-caller",
                agent_id="different-agent",
            )
        ],
    )
    access_token = AccessToken(token=token, client_id="approved-caller", scopes=["archive.execute"])

    with pytest.raises(ValueError):
        asyncio.run(make_mapper(path).resolve(access_token))


def test_mapper_rejects_missing_identity_configuration(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token, credential_id="approved-caller")])
    mapper = DevTokenMapper(
        DevCallerCredentialStore(path),
        expected_agent_id="",
        expected_adapter_id="local-mcp-adapter",
    )
    access_token = AccessToken(token=token, client_id="approved-caller", scopes=["archive.execute"])

    with pytest.raises(ValueError):
        asyncio.run(mapper.resolve(access_token))


def test_mapper_rejects_missing_scope(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(
        path,
        [
            make_credential(
                token,
                credential_id="approved-caller",
                scopes=["other.scope"],
            )
        ],
    )
    access_token = AccessToken(token=token, client_id="approved-caller", scopes=["archive.execute"])

    with pytest.raises(ValueError):
        asyncio.run(make_mapper(path).resolve(access_token))


def test_mapper_rejects_expired_access_token(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token, credential_id="approved-caller")])
    access_token = AccessToken(
        token=token,
        client_id="approved-caller",
        scopes=["archive.execute"],
        expires_at=int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp()),
    )

    with pytest.raises(ValueError):
        asyncio.run(make_mapper(path).resolve(access_token))


def test_mapper_rejects_unknown_credential_id(tmp_path):
    token = generate_caller_token()
    path = tmp_path / "credentials.json"
    write_store(path, [make_credential(token)])
    access_token = AccessToken(token=token, client_id="unknown-caller", scopes=["archive.execute"])

    with pytest.raises(ValueError):
        asyncio.run(make_mapper(path).resolve(access_token))
