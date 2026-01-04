"""MCP server for Obsidian with full Canvas support."""

import logging
import os

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .client import ObsidianClient
from .tools import ALL_HANDLERS

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create server instance
app = Server("obsidian-mcp")

# Global client instance (lazy initialization)
_client: ObsidianClient | None = None


def get_client() -> ObsidianClient:
    """Get or create the Obsidian client."""
    global _client
    if _client is None:
        api_key = os.getenv("OBSIDIAN_API_KEY", "")
        protocol = os.getenv("OBSIDIAN_PROTOCOL", "http")
        host = os.getenv("OBSIDIAN_HOST", "127.0.0.1")
        port = int(os.getenv("OBSIDIAN_PORT", "27123"))
        verify_ssl = os.getenv("OBSIDIAN_VERIFY_SSL", "false").lower() == "true"

        _client = ObsidianClient(
            api_key=api_key,
            protocol=protocol,
            host=host,
            port=port,
            verify_ssl=verify_ssl,
        )
        logger.info(f"Created Obsidian client: {_client.base_url}")
    return _client


@app.list_tools()
async def list_tools():
    """List all available tools."""
    return [handler.get_tool() for handler in ALL_HANDLERS]


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    """Call a tool by name with the given arguments."""
    handler = next((h for h in ALL_HANDLERS if h.name == name), None)
    if handler is None:
        raise ValueError(f"Unknown tool: {name}")

    client = get_client()
    return await handler.run(arguments, client)


async def main():
    """Run the MCP server."""
    logger.info("Starting obsidian-mcp server...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
