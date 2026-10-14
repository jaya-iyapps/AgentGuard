from ipaddress import IPv4Address, IPv6Address

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ArchiveServerSettings(BaseSettings):
    """Local transport settings for the separate demonstration archive service."""

    model_config = SettingsConfigDict(env_prefix="AG_ARCHIVE_", env_file=".env", extra="ignore")

    host: IPv4Address | IPv6Address = IPv4Address("127.0.0.1")
    port: int = Field(default=8002, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def host_must_be_loopback(cls, host: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
        if not host.is_loopback:
            raise ValueError("the unauthenticated demonstration archive must bind to loopback")
        return host
