"""Run the HTTP wrapper for the separate demonstration archive server."""

import uvicorn

from agentguard_archive_mcp.config import ArchiveServerSettings


if __name__ == "__main__":  # pragma: no cover - process entry point
    settings = ArchiveServerSettings()
    uvicorn.run(
        "agentguard_archive_mcp.app:create_app",
        factory=True,
        host=str(settings.host),
        port=settings.port,
    )
