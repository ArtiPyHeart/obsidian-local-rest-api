"""Canvas operations tool handlers."""

import json
from collections.abc import Sequence

from mcp.types import EmbeddedResource, ImageContent, TextContent

from ..client import ObsidianClient
from .base import ToolHandler


class CanvasReadHandler(ToolHandler):
    """Read Canvas file with structure and metadata."""

    name = "obsidian_canvas_read"
    description = """Get Canvas file structure and metadata.
Returns nodes, edges, and optionally metadata (node counts, types, referenced files)."""

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to .canvas file (relative to vault root)",
                },
                "include_metadata": {
                    "type": "boolean",
                    "description": "Include metadata (node counts, types, referenced files)",
                    "default": True,
                },
            },
            "required": ["filepath"],
        }

    async def run(
        self, args: dict, client: ObsidianClient
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        filepath = args["filepath"]
        include_metadata = args.get("include_metadata", True)
        result = await client.get_canvas(filepath, include_metadata)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]


class CanvasWriteHandler(ToolHandler):
    """Add, update, or delete Canvas nodes and edges."""

    name = "obsidian_canvas_write"
    description = """Modify Canvas nodes and edges.

Single operations (target_type: "node" or "edge"):
- add: Create a new node/edge
- update: Modify an existing node/edge (requires id)
- delete: Remove a node/edge (requires id)

Batch operations (target_type: "nodes" or "edges"):
- Provide add/update/delete arrays in a single request

Node types: text, file, link, group
Required fields for new nodes: id, node_type, x, y, width, height
Type-specific: text (text), file (file), link (url), group (label)"""

    def get_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to .canvas file",
                },
                "target_type": {
                    "type": "string",
                    "enum": ["node", "edge", "nodes", "edges"],
                    "description": "Target type (singular for single ops, plural for batch)",
                },
                "operation": {
                    "type": "string",
                    "enum": ["add", "update", "delete"],
                    "description": "Operation for single target_type (node/edge)",
                },
                "id": {
                    "type": "string",
                    "description": "Element ID (required for update/delete)",
                },
                # Node fields
                "node_type": {
                    "type": "string",
                    "enum": ["text", "file", "link", "group"],
                    "description": "Node type (for add node)",
                },
                "x": {"type": "number", "description": "X position"},
                "y": {"type": "number", "description": "Y position"},
                "width": {"type": "number", "description": "Width"},
                "height": {"type": "number", "description": "Height"},
                "text": {"type": "string", "description": "Text content (text node)"},
                "file": {"type": "string", "description": "File path (file node)"},
                "url": {"type": "string", "description": "URL (link node)"},
                "label": {"type": "string", "description": "Label (group node)"},
                "color": {"type": "string", "description": "Color (1-6)"},
                # Edge fields
                "fromNode": {"type": "string", "description": "Source node ID (edge)"},
                "toNode": {"type": "string", "description": "Target node ID (edge)"},
                "fromSide": {
                    "type": "string",
                    "enum": ["top", "right", "bottom", "left"],
                },
                "toSide": {
                    "type": "string",
                    "enum": ["top", "right", "bottom", "left"],
                },
                # Batch fields
                "add": {
                    "type": "array",
                    "description": "Nodes/edges to add (batch)",
                },
                "update": {
                    "type": "object",
                    "description": "ID -> updates mapping (batch)",
                },
                "delete": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs to delete (batch)",
                },
            },
            "required": ["filepath", "target_type"],
        }

    async def run(
        self, args: dict, client: ObsidianClient
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        filepath = args["filepath"]
        target_type = args["target_type"]

        # Batch operations
        if target_type in ("nodes", "edges"):
            operations = {
                k: args[k] for k in ("add", "update", "delete") if k in args
            }
            result = await client.canvas_batch(filepath, target_type, operations)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        # Single operations
        operation = args.get("operation")
        if not operation:
            raise ValueError("operation is required for single node/edge operations")

        if target_type == "node":
            if operation == "add":
                node = self._build_node(args)
                result = await client.canvas_add_node(filepath, node)
            elif operation == "update":
                node_id = args.get("id")
                if not node_id:
                    raise ValueError("id is required for update operation")
                updates = self._build_node_updates(args)
                result = await client.canvas_update_node(filepath, node_id, updates)
            else:  # delete
                node_id = args.get("id")
                if not node_id:
                    raise ValueError("id is required for delete operation")
                result = await client.canvas_delete_node(filepath, node_id)

        else:  # edge
            if operation == "add":
                edge = self._build_edge(args)
                result = await client.canvas_add_edge(filepath, edge)
            elif operation == "update":
                edge_id = args.get("id")
                if not edge_id:
                    raise ValueError("id is required for update operation")
                updates = self._build_edge_updates(args)
                result = await client.canvas_update_edge(filepath, edge_id, updates)
            else:  # delete
                edge_id = args.get("id")
                if not edge_id:
                    raise ValueError("id is required for delete operation")
                result = await client.canvas_delete_edge(filepath, edge_id)

        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    def _build_node(self, args: dict) -> dict:
        """Build node dict for add operation."""
        node_type = args.get("node_type")
        if not node_type:
            raise ValueError("node_type is required for add node")

        node = {
            "id": args.get("id"),
            "type": node_type,
            "x": args.get("x"),
            "y": args.get("y"),
            "width": args.get("width"),
            "height": args.get("height"),
        }

        # Validate required fields
        for field in ("id", "x", "y", "width", "height"):
            if node.get(field) is None:
                raise ValueError(f"{field} is required for add node")

        # Type-specific fields
        if node_type == "text":
            node["text"] = args.get("text", "")
        elif node_type == "file":
            if "file" not in args:
                raise ValueError("file is required for file node")
            node["file"] = args["file"]
        elif node_type == "link":
            if "url" not in args:
                raise ValueError("url is required for link node")
            node["url"] = args["url"]
        elif node_type == "group":
            if "label" in args:
                node["label"] = args["label"]

        if "color" in args:
            node["color"] = args["color"]

        return node

    def _build_node_updates(self, args: dict) -> dict:
        """Build updates dict for node update operation."""
        update_fields = [
            "x", "y", "width", "height", "text", "file", "url", "label", "color"
        ]
        return {k: args[k] for k in update_fields if k in args}

    def _build_edge(self, args: dict) -> dict:
        """Build edge dict for add operation."""
        edge = {
            "id": args.get("id"),
            "fromNode": args.get("fromNode"),
            "toNode": args.get("toNode"),
        }

        for field in ("id", "fromNode", "toNode"):
            if not edge.get(field):
                raise ValueError(f"{field} is required for add edge")

        for field in ("fromSide", "toSide", "color", "label"):
            if field in args:
                edge[field] = args[field]

        return edge

    def _build_edge_updates(self, args: dict) -> dict:
        """Build updates dict for edge update operation."""
        update_fields = ["fromNode", "toNode", "fromSide", "toSide", "color", "label"]
        return {k: args[k] for k in update_fields if k in args}
