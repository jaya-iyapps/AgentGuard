from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AG_", env_file=".env", extra="ignore")

    env: str = "development"
    service_name: str = "agentguard-backend"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    opa_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8181")
    opa_decision_path: str = Field(
        default="agentguard/authz/decision", pattern=r"^[a-z][a-z0-9_/]+$"
    )
    opa_timeout_seconds: float = Field(default=1.0, gt=0, le=30)
    opa_policy_version: str = "pdp-v1"
    pdp_context_path: str = ""
    pdp_decision_ttl_seconds: int = Field(default=5, ge=1, le=15)
    pdp_context_backend: Literal["file", "postgres"] = "file"
    database_url: SecretStr = SecretStr("")
    database_timeout_seconds: int = Field(default=3, ge=1, le=30)

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
