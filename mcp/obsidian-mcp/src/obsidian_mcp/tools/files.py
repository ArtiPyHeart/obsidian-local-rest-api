"""File operations tool handler."""

import json
from collections.abc import Sequence

from mcp.types import EmbeddedResource, ImageContent, TextContent

from ..client import ObsidianClient
from .base import ToolHandler


class FilesHandler(ToolHandler):
    """Unified file operations: list, get, batch_get, put, append, delete."""

    name = "obsidian_files"
    description = """File operations for Obsidian vault.
Operations:
- list: List files in a directory (use path="" for root)
- get: Get content of a single file
- batch_get: Get contents of multiple files concatenated
- put: Create or overwrite a file
- append: Append content to a file
- delete: Delete a file"""

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["list", "get", "batch_get", "put", "append", "delete"],
                    "description": "The operation to perform",
                },
                "path": {
                    "type": "string",
                    "description": "File or directory path (relative to vault root)",
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of file paths for batch_get operation",
                },
                "content": {
                    "type": "string",
                    "description": "Content for put/append operations",
                },
            },
            "required": ["operation"],
        }

    async def run(
        self, args: dict, client: ObsidianClient
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        operation = args["operation"]
        path = args.get("path", "")

        if operation == "list":
            files = await client.list_files(path)
            return [TextContent(type="text", text=json.dumps(files, indent=2))]

        elif operation == "get":
            if not path:
                raise ValueError("path is required for get operation")
            content = await client.get_file(path)
            return [TextContent(type="text", text=content)]

        elif operation == "batch_get":
            paths = args.get("paths", [])
            if not paths:
                raise ValueError("paths is required for batch_get operation")
            content = await client.get_files_batch(paths)
            return [TextContent(type="text", text=content)]

        elif operation == "put":
            if not path:
                raise ValueError("path is required for put operation")
            content = args.get("content", "")
            await client.put_file(path, content)
            return [TextContent(type="text", text=f"Successfully created/updated {path}")]

        elif operation == "append":
            if not path:
                raise ValueError("path is required for append operation")
            content = args.get("content", "")
            await client.append_file(path, content)
            return [TextContent(type="text", text=f"Successfully appended to {path}")]

        elif operation == "delete":
            if not path:
                raise ValueError("path is required for delete operation")
            await client.delete_file(path)
            return [TextContent(type="text", text=f"Successfully deleted {path}")]

        else:
            raise ValueError(f"Unknown operation: {operation}")
