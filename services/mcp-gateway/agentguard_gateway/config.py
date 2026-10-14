from typing import Literal

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AG_", env_file=".env", extra="ignore")

    policy_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8000")
    archive_mcp_url: AnyHttpUrl | None = None
    mcp_transport: Literal["streamable-http", "stdio"] = "streamable-http"
