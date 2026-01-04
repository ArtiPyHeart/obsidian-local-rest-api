"""Async REST API client for Obsidian Local REST API."""

import os
import urllib.parse
from typing import Any

import httpx


class ObsidianAPIError(Exception):
    """Exception raised for Obsidian API errors."""

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"Error {code}: {message}")


class ObsidianClient:
    """Async client for Obsidian Local REST API with Canvas support."""

    def __init__(
        self,
        api_key: str | None = None,
        protocol: str | None = None,
        host: str | None = None,
        port: int | None = None,
        verify_ssl: bool = False,
    ):
        self.api_key = api_key or os.getenv("OBSIDIAN_API_KEY", "")
        if not self.api_key:
            raise ValueError("OBSIDIAN_API_KEY is required")

        protocol = protocol or os.getenv("OBSIDIAN_PROTOCOL", "http").lower()
        self.protocol = "http" if protocol == "http" else "https"
        self.host = host or os.getenv("OBSIDIAN_HOST", "127.0.0.1")
        self.port = port or int(os.getenv("OBSIDIAN_PORT", "27123"))
        self.verify_ssl = verify_ssl
        self.timeout = httpx.Timeout(10.0, connect=5.0)

    @property
    def base_url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if extra:
            headers.update(extra)
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        json: Any = None,
        data: str | bytes | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Make an async HTTP request."""
        async with httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout
        ) as client:
            url = f"{self.base_url}{path}"
            response = await client.request(
                method,
                url,
                headers=self._headers(headers),
                json=json,
                content=data,
                params=params,
            )
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    raise ObsidianAPIError(
                        error_data.get("errorCode", response.status_code),
                        error_data.get("message", response.text),
                    )
                except (ValueError, KeyError):
                    raise ObsidianAPIError(response.status_code, response.text)
            return response

    # ==================== File Operations ====================

    async def list_files(self, path: str = "") -> list[str]:
        """List files in a directory."""
        url_path = f"/vault/{path}/" if path else "/vault/"
        response = await self._request("GET", url_path)
        return response.json().get("files", [])

    async def get_file(self, path: str) -> str:
        """Get file contents."""
        response = await self._request("GET", f"/vault/{path}")
        return response.text

    async def get_files_batch(self, paths: list[str]) -> str:
        """Get multiple files concatenated with headers."""
        results = []
        for path in paths:
            try:
                content = await self.get_file(path)
                results.append(f"# {path}\n\n{content}\n\n---\n\n")
            except ObsidianAPIError as e:
                results.append(f"# {path}\n\nError: {e.message}\n\n---\n\n")
        return "".join(results)

    async def put_file(self, path: str, content: str) -> None:
        """Create or update a file."""
        await self._request(
            "PUT",
            f"/vault/{path}",
            headers={"Content-Type": "text/markdown"},
            data=content.encode("utf-8"),
        )

    async def append_file(self, path: str, content: str) -> None:
        """Append content to a file."""
        await self._request(
            "POST",
            f"/vault/{path}",
            headers={"Content-Type": "text/markdown"},
            data=content.encode("utf-8"),
        )

    async def delete_file(self, path: str) -> None:
        """Delete a file."""
        await self._request("DELETE", f"/vault/{path}")

    # ==================== Patch Operations ====================

    async def patch_content(
        self,
        path: str,
        target_type: str,
        target: str,
        operation: str,
        content: str,
    ) -> None:
        """Patch content relative to heading/block/frontmatter."""
        await self._request(
            "PATCH",
            f"/vault/{path}",
            headers={
                "Content-Type": "text/markdown",
                "Target-Type": target_type,
                "Target": urllib.parse.quote(target),
                "Operation": operation,
            },
            data=content.encode("utf-8"),
        )

    # ==================== Search Operations ====================

    async def search_simple(
        self, query: str, context_length: int = 100
    ) -> list[dict[str, Any]]:
        """Simple text search."""
        response = await self._request(
            "POST",
            "/search/simple/",
            params={"query": query, "contextLength": context_length},
        )
        return response.json()

    async def search_complex(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        """Complex JsonLogic search."""
        response = await self._request(
            "POST",
            "/search/",
            headers={"Content-Type": "application/vnd.olrapi.jsonlogic+json"},
            json=query,
        )
        return response.json()

    # ==================== Periodic Notes ====================

    async def get_periodic_config(self) -> dict[str, Any]:
        """Get periodic notes configuration."""
        response = await self._request("GET", "/periodic/config/")
        return response.json()

    async def get_periodic_note(
        self, period: str, include_metadata: bool = False
    ) -> str | dict[str, Any]:
        """Get current periodic note."""
        headers = {}
        if include_metadata:
            headers["Accept"] = "application/vnd.olrapi.note+json"
        response = await self._request("GET", f"/periodic/{period}/", headers=headers)
        if include_metadata:
            return response.json()
        return response.text

    async def get_recent_periodic_notes(
        self, period: str, limit: int = 5, include_content: bool = False
    ) -> list[dict[str, Any]]:
        """Get recent periodic notes."""
        response = await self._request(
            "GET",
            f"/periodic/{period}/recent",
            params={"limit": limit, "includeContent": include_content},
        )
        return response.json()

    async def get_recent_changes(
        self, limit: int = 10, days: int = 90
    ) -> list[dict[str, Any]]:
        """Get recently modified files using Dataview DQL."""
        dql_query = f"""TABLE file.mtime
WHERE file.mtime >= date(today) - dur({days} days)
SORT file.mtime DESC
LIMIT {limit}"""
        response = await self._request(
            "POST",
            "/search/",
            headers={"Content-Type": "application/vnd.olrapi.dataview.dql+txt"},
            data=dql_query.encode("utf-8"),
        )
        return response.json()

    # ==================== Canvas Operations ====================

    async def get_canvas(
        self, path: str, include_metadata: bool = True
    ) -> dict[str, Any]:
        """Get Canvas structure and optionally metadata."""
        headers = {}
        if include_metadata:
            headers["Accept"] = "application/vnd.olrapi.canvas+json"
        response = await self._request("GET", f"/vault/{path}", headers=headers)
        return response.json()

    async def create_canvas(
        self,
        path: str,
        nodes: list[dict[str, Any]] | None = None,
        edges: list[dict[str, Any]] | None = None,
    ) -> None:
        """Create a new Canvas file."""
        canvas_data = {"nodes": nodes or [], "edges": edges or []}
        await self._request(
            "PUT",
            f"/vault/{path}",
            headers={"Content-Type": "application/json"},
            json=canvas_data,
        )

    async def canvas_patch(
        self,
        path: str,
        target_type: str,
        operation: str | None = None,
        target: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generic Canvas PATCH operation."""
        headers = {
            "Content-Type": "application/vnd.olrapi.canvas.patch+json",
            "Target-Type": target_type,
        }
        if operation:
            headers["Operation"] = operation
        if target:
            headers["Target"] = urllib.parse.quote(target)

        response = await self._request(
            "PATCH", f"/vault/{path}", headers=headers, json=body or {}
        )
        return response.json()

    async def canvas_add_node(self, path: str, node: dict[str, Any]) -> dict[str, Any]:
        """Add a node to Canvas."""
        return await self.canvas_patch(path, "node", "add", body=node)

    async def canvas_update_node(
        self, path: str, node_id: str, updates: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a Canvas node."""
        return await self.canvas_patch(path, "node", "update", target=node_id, body=updates)

    async def canvas_delete_node(self, path: str, node_id: str) -> dict[str, Any]:
        """Delete a Canvas node."""
        return await self.canvas_patch(path, "node", "delete", target=node_id)

    async def canvas_add_edge(self, path: str, edge: dict[str, Any]) -> dict[str, Any]:
        """Add an edge to Canvas."""
        return await self.canvas_patch(path, "edge", "add", body=edge)

    async def canvas_update_edge(
        self, path: str, edge_id: str, updates: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a Canvas edge."""
        return await self.canvas_patch(path, "edge", "update", target=edge_id, body=updates)

    async def canvas_delete_edge(self, path: str, edge_id: str) -> dict[str, Any]:
        """Delete a Canvas edge."""
        return await self.canvas_patch(path, "edge", "delete", target=edge_id)

    async def canvas_batch(
        self, path: str, target_type: str, operations: dict[str, Any]
    ) -> dict[str, Any]:
        """Batch Canvas operations (add/update/delete multiple nodes or edges)."""
        return await self.canvas_patch(path, target_type, body=operations)
