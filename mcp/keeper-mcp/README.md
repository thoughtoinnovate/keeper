# Keeper MCP Server (Rust)

This server exposes Keeper CLI commands as MCP tools and makes the tool/API docs available as a resource.

## Build
```bash
cargo build --release
```

## Example mcp.json
```json
{
  "server": "keeper",
  "command": "/path/to/keeper-mcp/target/release/keeper-mcp",
  "env": {
    "KEEPER_VAULT": "/home/user/.keeper",
    "KEEPER_PASSWORD": "env:KEEPER_PASSWORD",
    "KEEPER_READONLY": "false",
    "KEEPER_ALLOW_PASSWORD_OPS": "false",
    "KEEPER_AUTO_START": "true"
  }
}
```

## Docs Resource
The MCP server exposes:
- `keeper://docs` → `MCP_AGENT_GUIDE.md`

