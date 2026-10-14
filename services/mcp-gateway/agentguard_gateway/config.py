from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AG_", env_file=".env", extra="ignore")

    policy_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8000")
    policy_credential: SecretStr = SecretStr("")
    policy_agent_id: str = ""
    policy_adapter_id: str = ""
    policy_version: str = Field(default="pdp-v1", min_length=1)
    policy_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    mcp_transport: Literal["streamable-http", "stdio"] = "streamable-http"
