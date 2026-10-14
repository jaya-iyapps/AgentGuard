"""Development-only opaque MCP caller-token authentication."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from agentguard_contracts import TrustedContext
from mcp.server.auth.provider import AccessToken, TokenVerifier
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)

_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,256}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_REQUIRED_SCOPE = "archive.execute"


def generate_caller_token() -> str:
    """Generate a token with at least 256 bits of random entropy."""
    return secrets.token_urlsafe(32)


def hash_caller_token(token: str) -> str:
    """Return the SHA-256 hexadecimal digest of a caller token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class CallerCredential(BaseModel):
    """Server-owned caller credential and identity binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_id: str = Field(min_length=1, max_length=100)
    token_sha256: str = Field(pattern=_SHA256_PATTERN.pattern)
    agent_id: str = Field(min_length=1, max_length=200)
    adapter_id: str = Field(min_length=1, max_length=200)
    surface: Literal["mcp"]
    scopes: list[str] = Field(min_length=1)
    expires_at: datetime
    active: bool
    revoked_at: datetime | None = None

    @field_validator("expires_at", "revoked_at")
    @classmethod
    def require_timezone_aware_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Credential timestamps must include a timezone.")
        return value.astimezone(timezone.utc)


class CallerCredentialStoreFile(BaseModel):
    """Versioned credential-store document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    credentials: list[CallerCredential]


class DevCallerCredentialStore:
    """Read the server-owned credential store without indefinite caching."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> CallerCredentialStoreFile:
        document = json.loads(self.path.read_text(encoding="utf-8"))
        return CallerCredentialStoreFile.model_validate(document)

    def find_by_token(self, token: str) -> CallerCredential | None:
        if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
            return None

        store = self.load()
        digest = hash_caller_token(token)
        matches = [
            record
            for record in store.credentials
            if hmac.compare_digest(digest, record.token_sha256)
        ]

        if len(matches) != 1:
            return None

        record = matches[0]
        now = datetime.now(timezone.utc)

        if not record.active or record.revoked_at is not None:
            return None
        if record.expires_at <= now:
            return None
        if _REQUIRED_SCOPE not in record.scopes:
            return None

        return record

    def find_active_by_id(self, credential_id: str) -> CallerCredential | None:
        store = self.load()
        matches = [record for record in store.credentials if record.credential_id == credential_id]

        if len(matches) != 1:
            return None

        record = matches[0]
        now = datetime.now(timezone.utc)

        if not record.active or record.revoked_at is not None:
            return None
        if record.expires_at <= now:
            return None

        return record


class DevBearerTokenVerifier(TokenVerifier):
    """Verify opaque development caller tokens; never use the PDP credential."""

    def __init__(
        self,
        credential_store: DevCallerCredentialStore,
        resource_server_url: str,
    ) -> None:
        self.credential_store = credential_store
        self.resource_server_url = resource_server_url
        self._store_error_logged = False

    def _log_store_error_once(self) -> None:
        if not self._store_error_logged:
            logger.error("MCP caller credential store could not be loaded; authentication denied.")
            self._store_error_logged = True

    async def verify_token(self, token: str) -> AccessToken | None:
        if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
            return None

        try:
            record = self.credential_store.find_by_token(token)
        except (OSError, ValueError, TypeError, ValidationError):
            self._log_store_error_once()
            return None

        if record is None:
            return None

        return AccessToken(
            token=token,
            client_id=record.credential_id,
            scopes=record.scopes,
            expires_at=int(record.expires_at.timestamp()),
            resource=self.resource_server_url,
        )


class DevTokenMapper:
    """Resolve a verified token to an approved server-owned identity."""

    def __init__(
        self,
        credential_store: DevCallerCredentialStore,
        *,
        expected_agent_id: str,
        expected_adapter_id: str,
    ) -> None:
        self.credential_store = credential_store
        self.expected_agent_id = expected_agent_id
        self.expected_adapter_id = expected_adapter_id

    async def resolve(self, access_token: AccessToken) -> TrustedContext:
        if not isinstance(access_token, AccessToken):
            raise ValueError("An SDK-verified access token is required.")

        if not self.expected_agent_id or not self.expected_adapter_id:
            raise ValueError("The approved AgentGuard identity is not configured.")

        if not access_token.client_id or not access_token.token:
            raise ValueError("Access-token credential metadata is missing.")

        record = self.credential_store.find_active_by_id(access_token.client_id)
        if record is None:
            raise ValueError("The caller credential is inactive or unknown.")

        digest = hash_caller_token(access_token.token)
        if not hmac.compare_digest(digest, record.token_sha256):
            raise ValueError("The token no longer matches its server-owned binding.")

        if _REQUIRED_SCOPE not in record.scopes or _REQUIRED_SCOPE not in access_token.scopes:
            raise ValueError("The required caller scope is missing.")

        if (
            record.agent_id != self.expected_agent_id
            or record.adapter_id != self.expected_adapter_id
            or record.surface != "mcp"
        ):
            raise ValueError("The caller identity does not match the approved binding.")

        now = int(datetime.now(timezone.utc).timestamp())
        if access_token.expires_at is not None and access_token.expires_at <= now:
            raise ValueError("The verified access token has expired.")

        return TrustedContext(
            agent_id=record.agent_id,
            adapter_id=record.adapter_id,
            surface="mcp",
        )
