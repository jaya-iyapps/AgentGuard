from contextlib import asynccontextmanager

import httpx
import pytest
from pydantic import ValidationError

from agentguard_archive_mcp import create_archive_server
from agentguard_archive_mcp.app import create_app
from agentguard_archive_mcp.config import ArchiveServerSettings
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def archive_client():
    server = create_archive_server()
    app = server.streamable_http_app()
    async with server.session_manager.run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8002"
        ) as http_client:
            async with streamable_http_client(
                "http://127.0.0.1:8002/mcp", http_client=http_client
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    yield session


@pytest.mark.anyio
async def test_archive_server_discovers_only_archive_record():
    async with archive_client() as client:
        result = await client.list_tools()

    assert [tool.name for tool in result.tools] == ["archive_record"]
    assert result.tools[0].inputSchema["required"] == ["record_id"]


@pytest.mark.anyio
async def test_archive_server_returns_deterministic_demo_result():
    async with archive_client() as client:
        result = await client.call_tool("archive_record", {"record_id": "demo-record:1"})

    assert result.isError is False
    assert result.structuredContent == {"record_id": "demo-record:1", "status": "demo_archived"}


@pytest.mark.anyio
async def test_archive_server_rejects_invalid_record_id():
    async with archive_client() as client:
        result = await client.call_tool("archive_record", {"record_id": "invalid record"})

    assert result.isError is True


@pytest.mark.anyio
async def test_archive_app_preserves_health_and_mcp_route():
    app = create_app()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8002"
        ) as client:
            health = await client.get("/health")

    assert health.status_code == 200
    assert health.json()["service"] == "agentguard-archive-mcp"


def test_archive_server_configuration_rejects_non_loopback_host():
    with pytest.raises(ValidationError, match="must bind to loopback"):
        ArchiveServerSettings(_env_file=None, host="0.0.0.0")
