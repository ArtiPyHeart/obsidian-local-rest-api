"""Search tool handler."""

import json
from collections.abc import Sequence

from mcp.types import EmbeddedResource, ImageContent, TextContent

from ..client import ObsidianClient
from .base import ToolHandler


class SearchHandler(ToolHandler):
    """Search for documents in the vault."""

    name = "obsidian_search"
    description = """Search for documents in the vault.
- query_type "simple": Text search across all files (including Canvas text nodes)
- query_type "complex": JsonLogic query for advanced filtering

Simple search returns matches with context. Results include isCanvas/nodeId for Canvas files.

Complex search examples:
- {"glob": ["*.md", {"var": "path"}]} - all markdown files
- {"and": [{"glob": ["*.md", {"var": "path"}]}, {"regexp": ["keyword", {"var": "content"}]}]}"""

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "query_type": {
                    "type": "string",
                    "enum": ["simple", "complex"],
                    "description": "Type of search query",
                },
                "query": {
                    "description": "Search query - string for simple, object for complex (JsonLogic)",
                },
                "context_length": {
                    "type": "integer",
                    "description": "Context length for simple search (default: 100)",
                    "default": 100,
                },
            },
            "required": ["query_type", "query"],
        }

    async def run(
        self, args: dict, client: ObsidianClient
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        query_type = args["query_type"]
        query = args["query"]

        if query_type == "simple":
            if not isinstance(query, str):
                raise ValueError("query must be a string for simple search")
            context_length = args.get("context_length", 100)
            results = await client.search_simple(query, context_length)
        else:  # complex
            if not isinstance(query, dict):
                raise ValueError("query must be an object for complex search")
            results = await client.search_complex(query)

        return [TextContent(type="text", text=json.dumps(results, indent=2))]
