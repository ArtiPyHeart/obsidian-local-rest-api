"""Obsidian MCP Server with full Canvas support."""

import asyncio
from .server import main as server_main


def main():
    """Entry point for the MCP server."""
    asyncio.run(server_main())
