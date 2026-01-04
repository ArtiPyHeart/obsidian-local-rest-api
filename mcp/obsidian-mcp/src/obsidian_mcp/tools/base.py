"""Base class for tool handlers."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING

from mcp.types import EmbeddedResource, ImageContent, TextContent, Tool

if TYPE_CHECKING:
    from ..client import ObsidianClient


class ToolHandler(ABC):
    """Abstract base class for MCP tool handlers."""

    name: str
    description: str

    @abstractmethod
    def get_schema(self) -> dict:
        """Return the JSON schema for the tool's input."""
        ...

    @abstractmethod
    async def run(
        self, args: dict, client: "ObsidianClient"
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        """Execute the tool with the given arguments."""
        ...

    def get_tool(self) -> Tool:
        """Return the MCP Tool definition."""
        return Tool(
            name=self.name,
            description=self.description,
            inputSchema=self.get_schema(),
        )
