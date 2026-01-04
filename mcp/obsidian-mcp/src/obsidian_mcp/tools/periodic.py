"""Periodic notes tool handler."""

import json
from collections.abc import Sequence

from mcp.types import EmbeddedResource, ImageContent, TextContent

from ..client import ObsidianAPIError, ObsidianClient
from .base import ToolHandler

# Error code to helpful message mapping
PLUGIN_HINTS = {
    40461: (
        "Periodic note does not exist. "
        "Make sure the Periodic Notes plugin is installed and configured: "
        "https://github.com/liamcain/obsidian-periodic-notes"
    ),
    40400: (
        "Periodic notes endpoint not found. "
        "Please install the Periodic Notes plugin: "
        "https://github.com/liamcain/obsidian-periodic-notes"
    ),
    40070: (
        "Query processing failed. "
        "The 'changes' operation requires the Dataview plugin: "
        "https://github.com/blacksmithgu/obsidian-dataview"
    ),
}


class PeriodicHandler(ToolHandler):
    """Operations for periodic notes and recent changes."""

    name = "obsidian_periodic"
    description = """Periodic notes and recent changes operations.
- config: Get periodic notes configuration (folders, formats, enabled status)
- get: Get current periodic note (daily/weekly/monthly/quarterly/yearly)
- recent: Get most recent periodic notes of a type
- changes: Get recently modified files in the vault (requires Dataview plugin)"""

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["config", "get", "recent", "changes"],
                    "description": "Operation to perform",
                },
                "period": {
                    "type": "string",
                    "enum": ["daily", "weekly", "monthly", "quarterly", "yearly"],
                    "description": "Period type (required for get/recent)",
                },
                "include_metadata": {
                    "type": "boolean",
                    "description": "Include metadata with content (for 'get' operation)",
                    "default": False,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (for recent/changes, default: 5/10)",
                    "minimum": 1,
                    "maximum": 100,
                },
                "include_content": {
                    "type": "boolean",
                    "description": "Include note content (for 'recent' operation)",
                    "default": False,
                },
                "days": {
                    "type": "integer",
                    "description": "Days to look back (for 'changes' operation, default: 90)",
                    "minimum": 1,
                },
            },
            "required": ["operation"],
        }

    async def run(
        self, args: dict, client: ObsidianClient
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        operation = args["operation"]

        try:
            if operation == "config":
                result = await client.get_periodic_config()
                return [TextContent(type="text", text=json.dumps(result, indent=2))]

            elif operation == "get":
                period = args.get("period")
                if not period:
                    raise ValueError("period is required for get operation")
                include_metadata = args.get("include_metadata", False)
                result = await client.get_periodic_note(period, include_metadata)
                if isinstance(result, dict):
                    return [TextContent(type="text", text=json.dumps(result, indent=2))]
                return [TextContent(type="text", text=result)]

            elif operation == "recent":
                period = args.get("period")
                if not period:
                    raise ValueError("period is required for recent operation")
                limit = args.get("limit", 5)
                include_content = args.get("include_content", False)
                results = await client.get_recent_periodic_notes(
                    period, limit, include_content
                )
                return [TextContent(type="text", text=json.dumps(results, indent=2))]

            elif operation == "changes":
                limit = args.get("limit", 10)
                days = args.get("days", 90)
                results = await client.get_recent_changes(limit, days)
                return [TextContent(type="text", text=json.dumps(results, indent=2))]

            else:
                raise ValueError(f"Unknown operation: {operation}")

        except ObsidianAPIError as e:
            # Check if we have a helpful hint for this error code
            hint = PLUGIN_HINTS.get(e.code)
            if hint:
                return [TextContent(type="text", text=f"Error: {hint}")]
            # Re-raise if no specific hint available
            raise
