# obsidian-api-mcp

MCP server for Obsidian with full Canvas support.

## Features

- **Async architecture** - Uses `httpx.AsyncClient` for non-blocking HTTP requests
- **Coarse-grained tools** - 6 tools instead of 16+ to reduce context overhead
- **Full Canvas support** - Read, create, and modify Canvas nodes and edges
- **Canvas search** - Search results include Canvas text nodes with metadata

## Installation

### From PyPI (recommended)

```bash
# Using uvx (recommended)
uvx obsidian-api-mcp

# Or install with pip
pip install obsidian-api-mcp
```

### From source

```bash
git clone https://github.com/ArtiPyHeart/obsidian-local-rest-api.git
cd obsidian-local-rest-api/mcp/obsidian-mcp
uv pip install -e .
```

## Configuration

Set environment variables (or use a `.env` file):

| Variable | Description | Default |
|----------|-------------|---------|
| `OBSIDIAN_API_KEY` | API key from Local REST API plugin | (required) |
| `OBSIDIAN_HOST` | Obsidian host | `127.0.0.1` |
| `OBSIDIAN_PORT` | Obsidian port | `27123` |
| `OBSIDIAN_PROTOCOL` | Protocol (`http` or `https`) | `http` |
| `OBSIDIAN_VERIFY_SSL` | Verify SSL certificates | `false` |

## Claude Desktop Configuration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "obsidian-api-mcp": {
      "command": "uvx",
      "args": ["obsidian-api-mcp"],
      "env": {
        "OBSIDIAN_API_KEY": "your-api-key",
        "OBSIDIAN_HOST": "127.0.0.1",
        "OBSIDIAN_PORT": "27123",
        "OBSIDIAN_PROTOCOL": "http"
      }
    }
  }
}
```

## Tools

### 1. `obsidian_files` - File Operations

Unified file operations for the Obsidian vault.

**Operations:**
- `list` - List files in a directory (use `path=""` for root)
- `get` - Get content of a single file
- `batch_get` - Get contents of multiple files concatenated
- `put` - Create or overwrite a file
- `append` - Append content to a file
- `delete` - Delete a file

```json
{
  "operation": "get",
  "path": "notes/example.md"
}
```

### 2. `obsidian_patch` - Content Insertion

Insert content relative to a heading, block reference, or frontmatter field.

**Target types:**
- `heading` - Target a heading path (use `::` as delimiter for nested headings)
- `block` - Target a block reference (without `^` prefix)
- `frontmatter` - Target a frontmatter field name

**Operations:** `append`, `prepend`, `replace`

**Heading example** (note: use full heading path):
```json
{
  "filepath": "note.md",
  "target_type": "heading",
  "target": "Main Title::Tasks",
  "operation": "append",
  "content": "\n- [ ] New task"
}
```

**Frontmatter example:**
```json
{
  "filepath": "note.md",
  "target_type": "frontmatter",
  "target": "status",
  "operation": "replace",
  "content": "published"
}
```

**Block reference example:**
```json
{
  "filepath": "note.md",
  "target_type": "block",
  "target": "my-block-id",
  "operation": "append",
  "content": "\nAdditional content"
}
```

### 3. `obsidian_search` - Search

Search for documents in the vault.

**Query types:**
- `simple` - Text search across all files (including Canvas text nodes)
- `complex` - JsonLogic query for advanced filtering

```json
{
  "query_type": "simple",
  "query": "project ideas",
  "context_length": 100
}
```

```json
{
  "query_type": "complex",
  "query": {"glob": ["*.md", {"var": "path"}]}
}
```

### 4. `obsidian_periodic` - Periodic Notes

Operations for periodic notes and recent changes.

> **Note:** Requires [Periodic Notes](https://github.com/liamcain/obsidian-periodic-notes) plugin for `get`/`recent` operations, and [Dataview](https://github.com/blacksmithgu/obsidian-dataview) plugin for `changes` operation.

**Operations:**
- `config` - Get periodic notes configuration (folders, formats, enabled status)
- `get` - Get current periodic note (daily/weekly/monthly/quarterly/yearly)
- `recent` - Get most recent periodic notes of a type
- `changes` - Get recently modified files (requires Dataview plugin)

**Get configuration:**
```json
{
  "operation": "config"
}
```

**Get current periodic note:**
```json
{
  "operation": "get",
  "period": "daily",
  "include_metadata": true
}
```

**Get recent periodic notes:**
```json
{
  "operation": "recent",
  "period": "daily",
  "limit": 5,
  "include_content": true
}
```

**Get recently changed files:**
```json
{
  "operation": "changes",
  "limit": 10,
  "days": 30
}
```

### 5. `obsidian_canvas_read` - Read Canvas

Get Canvas file structure and metadata.

```json
{
  "filepath": "my-canvas.canvas",
  "include_metadata": true
}
```

### 6. `obsidian_canvas_write` - Modify Canvas

Add, update, or delete Canvas nodes and edges.

**Target types:**
- `node` / `edge` - Single operations (requires `operation`)
- `nodes` / `edges` - Batch operations

**Node types:** `text`, `file`, `link`, `group`

**Single node add:**
```json
{
  "filepath": "my-canvas.canvas",
  "target_type": "node",
  "operation": "add",
  "id": "node1",
  "node_type": "text",
  "x": 0,
  "y": 0,
  "width": 200,
  "height": 100,
  "text": "Hello World"
}
```

**Single node update:**
```json
{
  "filepath": "my-canvas.canvas",
  "target_type": "node",
  "operation": "update",
  "id": "node1",
  "text": "Updated text"
}
```

**Single edge add:**
```json
{
  "filepath": "my-canvas.canvas",
  "target_type": "edge",
  "operation": "add",
  "id": "edge1",
  "fromNode": "node1",
  "toNode": "node2",
  "fromSide": "right",
  "toSide": "left"
}
```

**Batch operations:**
```json
{
  "filepath": "my-canvas.canvas",
  "target_type": "nodes",
  "add": [
    {"id": "n1", "type": "text", "x": 0, "y": 0, "width": 200, "height": 100, "text": "Node 1"},
    {"id": "n2", "type": "text", "x": 300, "y": 0, "width": 200, "height": 100, "text": "Node 2"}
  ],
  "update": {
    "existing_node_id": {"text": "Updated content"}
  },
  "delete": ["old_node_id"]
}
```

## Requirements

- Python 3.11+
- Obsidian with [Local REST API](https://github.com/coddingtonbear/obsidian-local-rest-api) plugin installed

## License

MIT
