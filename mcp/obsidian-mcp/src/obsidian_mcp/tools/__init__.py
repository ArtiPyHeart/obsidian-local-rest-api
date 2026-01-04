"""Tool handlers for obsidian-mcp."""

from .base import ToolHandler
from .canvas import CanvasReadHandler, CanvasWriteHandler
from .files import FilesHandler
from .patch import PatchHandler
from .periodic import PeriodicHandler
from .search import SearchHandler

__all__ = [
    "ToolHandler",
    "FilesHandler",
    "PatchHandler",
    "SearchHandler",
    "PeriodicHandler",
    "CanvasReadHandler",
    "CanvasWriteHandler",
]

# All tool handlers (6 tools total)
ALL_HANDLERS: list[ToolHandler] = [
    FilesHandler(),
    PatchHandler(),
    SearchHandler(),
    PeriodicHandler(),
    CanvasReadHandler(),
    CanvasWriteHandler(),
]
