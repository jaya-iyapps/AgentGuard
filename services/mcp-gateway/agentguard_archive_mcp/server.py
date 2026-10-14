"""A separate deterministic archive MCP server for integration demonstrations.

This server does not persist data, authenticate callers, or provide a production
archive capability. Deployments must put it behind their own authenticated and
authorized gateway rather than exposing it as a production archive service.
"""

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from agentguard_archive_mcp.config import ArchiveServerSettings


DemoRecordId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description="Synthetic demonstration record identifier.",
    ),
]


def create_archive_server(settings: ArchiveServerSettings | None = None) -> FastMCP:
    """Create the separate, stateless demonstration archive MCP server."""
    settings = settings or ArchiveServerSettings()
    server = FastMCP(
        "AgentGuard demonstration archive",
        instructions=(
            "Demonstration only: archive_record validates a synthetic record identifier and "
            "returns a deterministic result. It does not persist data or archive production records."
        ),
        host=str(settings.host),
        port=settings.port,
    )

    @server.tool(
        name="archive_record",
        description=(
            "Validate a synthetic record identifier and return a deterministic demonstration "
            "archive result. This is not a production archive operation."
        ),
    )
    async def archive_record(record_id: DemoRecordId) -> dict[str, str]:
        return {"record_id": record_id, "status": "demo_archived"}

    return server
