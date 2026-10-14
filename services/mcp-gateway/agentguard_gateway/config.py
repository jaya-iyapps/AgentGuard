from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AG_",
        env_file=".env",
        extra="ignore",
    )

    policy_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8000")
    policy_credential: SecretStr = SecretStr("")
    policy_agent_id: str = ""
    policy_adapter_id: str = ""
    policy_version: str = Field(default="pdp-v1", min_length=1)
    policy_timeout_seconds: float = Field(default=2.0, gt=0, le=30)

    archive_mcp_url: AnyHttpUrl | None = None
    mcp_transport: Literal["streamable-http", "stdio"] = "streamable-http"

    # Development-only opaque caller-token authentication.
    caller_auth_enabled: bool = False
    caller_credential_store: Path | None = None
    caller_resource_server_url: AnyHttpUrl | None = None
    caller_expected_agent_id: str = ""
    caller_expected_adapter_id: str = ""

    @model_validator(mode="after")
    def validate_caller_auth_configuration(self):
        if self.caller_auth_enabled:
            if self.caller_credential_store is None:
                raise ValueError(
                    "AG_CALLER_CREDENTIAL_STORE is required when caller "
                    "authentication is enabled."
                )
            if not self.caller_credential_store.is_absolute():
                raise ValueError(
                    "AG_CALLER_CREDENTIAL_STORE must be an absolute path."
                )
            if self.caller_resource_server_url is None:
                raise ValueError(
                    "AG_CALLER_RESOURCE_SERVER_URL is required when caller "
                    "authentication is enabled."
                )
            if not self.caller_expected_agent_id.strip():
                raise ValueError(
                    "AG_CALLER_EXPECTED_AGENT_ID is required when caller "
                    "authentication is enabled."
                )
            if not self.caller_expected_adapter_id.strip():
                raise ValueError(
                    "AG_CALLER_EXPECTED_ADAPTER_ID is required when caller "
                    "authentication is enabled."
                )
        return self
