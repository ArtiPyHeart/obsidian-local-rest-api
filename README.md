# Local REST API for Obsidian

See our interactive docs: https://coddingtonbear.github.io/obsidian-local-rest-api/

Have you ever needed to automate interacting with your notes? This plugin gives Obsidian a REST API you can interact with your notes from other tools so you can automate what you need to automate.

This plugin provides a secure HTTPS interface gated behind api key authentication that allows you to:

- Read, create, update or delete existing notes. There's even a `PATCH` HTTP method for inserting content into a particular section of a note.
- List notes stored in your vault.
- Create and fetch periodic notes.
- Execute commands and list what commands are available.
- **Full Canvas support** - Read and modify Canvas files (nodes and edges).
- **Periodic notes configuration** - Get periodic notes settings and recent notes.

This is particularly useful if you need to interact with Obsidian from a browser extension like [Obsidian Web](https://chrome.google.com/webstore/detail/obsidian-web/edoacekkjanmingkbkgjndndibhkegad).

## Installation

### Via BRAT (Recommended)

1. Install the [BRAT plugin](https://github.com/TfTHacker/obsidian42-brat) from Obsidian Community Plugins
2. Open BRAT settings and click "Add Beta plugin"
3. Enter: `ArtiPyHeart/obsidian-local-rest-api`
4. Click "Add Plugin" and enable it

### Manual Installation

1. Download the latest release from [Releases](https://github.com/ArtiPyHeart/obsidian-local-rest-api/releases)
2. Extract to your vault's `.obsidian/plugins/obsidian-local-rest-api/` folder
3. Reload Obsidian and enable the plugin

## MCP Server

For AI integration (Claude, etc.), use our MCP server: [obsidian-api-mcp](https://github.com/ArtiPyHeart/obsidian-mcp)

```bash
uvx obsidian-api-mcp
```

## Credits

This was inspired by [Vinzent03](https://github.com/Vinzent03)'s [advanced-uri plugin](https://github.com/Vinzent03/obsidian-advanced-uri) with hopes of expanding the automation options beyond the limitations of custom URL schemes.
