"""Content patching tool handler."""

from collections.abc import Sequence

from mcp.types import EmbeddedResource, ImageContent, TextContent

from ..client import ObsidianClient
from .base import ToolHandler


class PatchHandler(ToolHandler):
    """Insert content relative to heading, block reference, or frontmatter."""

    name = "obsidian_patch"
    description = """Insert content into an existing note relative to a heading, block reference, or frontmatter field.
- target_type: "heading" | "block" | "frontmatter"
- operation: "append" | "prepend" | "replace"
- target: The identifier (heading path like "## Section", block ref, or frontmatter field)"""

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to the file (relative to vault root)",
                },
                "target_type": {
                    "type": "string",
                    "enum": ["heading", "block", "frontmatter"],
                    "description": "Type of target to patch",
                },
                "target": {
                    "type": "string",
                    "description": "Target identifier (heading path, block reference, or frontmatter field)",
                },
                "operation": {
                    "type": "string",
                    "enum": ["append", "prepend", "replace"],
                    "description": "Operation to perform",
                },
                "content": {
                    "type": "string",
                    "description": "Content to insert",
                },
            },
            "required": ["filepath", "target_type", "target", "operation", "content"],
        }

    async def run(
        self, args: dict, client: ObsidianClient
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        await client.patch_content(
            path=args["filepath"],
            target_type=args["target_type"],
            target=args["target"],
            operation=args["operation"],
            content=args["content"],
        )
        return [
            TextContent(
                type="text",
                text=f"Successfully patched {args['filepath']} at {args['target_type']}:{args['target']}",
            )
        ]
