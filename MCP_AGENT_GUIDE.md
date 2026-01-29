# Keeper MCP Tool/API Docs (Design-First)

This document is a **tool/API reference** for using Keeper via MCP. It assumes a `keeper-mcp` server that exposes Keeper commands as tools.

## 1) Overview
The MCP server exposes Keeper operations as tools. Categories:

- **Read**: status, get items, timeline
- **Write**: create/update/mark/delete items
- **Session**: start/stop daemon
- **Security** (optional): password rotation / recovery

## 2) Configuration (mcp.json)
Vault location is configurable in MCP config. Example:

```json
{
  "server": "keeper",
  "command": "/path/to/keeper-mcp",
  "env": {
    "KEEPER_VAULT": "/home/user/.keeper",
    "KEEPER_PASSWORD": "env:KEEPER_PASSWORD",
    "KEEPER_READONLY": "true",
    "KEEPER_ALLOW_PASSWORD_OPS": "false",
    "KEEPER_AUTO_START": "true"
  }
}
```

### Key Environment Flags
- `KEEPER_VAULT`: default vault path (dir or `vault.db`)
- `KEEPER_PASSWORD`: password source for auto‑start (literal or `env:VAR`)
- `KEEPER_READONLY`: `true/false` (default `true`)
- `KEEPER_ALLOW_PASSWORD_OPS`: enable `passwd` / `recover`
- `KEEPER_AUTO_START`: auto‑start the daemon if not running

**Password behavior (important):**
- The MCP server is non‑interactive and **will not prompt** for passwords.
- If `KEEPER_AUTO_START=true`, the server must have `KEEPER_PASSWORD` set.
- For new vault creation, the server will submit the password **twice** (create + confirm).
- If no password is configured, auto‑start will fail with an error.

## 3) Tool List
These are the tools exposed by default:

- `keeper.status`  
- `keeper.start` / `keeper.stop`  
- `keeper.note`  
- `keeper.get`  
- `keeper.update`  
- `keeper.mark`  
- `keeper.delete`  
- `keeper.undo`  
- `keeper.archive`  
- `keeper.dash_due_timeline`  
- (optional) `keeper.passwd`, `keeper.recover`

## 4) Tool/API Reference

### Common Input Fields
- `vault` (string, optional): override the default vault path.

### keeper.status
**Description:** Check daemon status.  
**Input:** `{ "vault": "…" }` (optional)  
**Output:** `{ stdout, stderr, exit_code }`

### keeper.start
**Description:** Start daemon. May use configured password source.  
**Input:** `{ "vault": "…" }` (optional)  
**Output:** `{ stdout, stderr, exit_code }`

### keeper.stop
**Description:** Stop daemon and wipe key from RAM.  
**Input:** `{ "vault": "…" }` (optional)

### keeper.note
**Description:** Create a note/task.  
**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "content": { "type": "string" },
    "bucket": { "type": "string" },
    "priority": { "type": "string", "enum": ["p1","p2","p3","none"] },
    "due": { "type": "string", "description": "YYYY-MM-DD|today|tomorrow" },
    "vault": { "type": "string" }
  },
  "required": ["content"]
}
```

### keeper.get
**Description:** Retrieve items.  
**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "bucket": { "type": "string" },
    "all": { "type": "boolean" },
    "notes": { "type": "boolean" },
    "vault": { "type": "string" }
  }
}
```

### keeper.update
**Description:** Update item attributes by id.  
**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "integer" },
    "content": { "type": "string" },
    "bucket": { "type": "string" },
    "priority": { "type": "string", "enum": ["p1","p2","p3","none"] },
    "due": { "type": "string", "description": "YYYY-MM-DD|today|tomorrow|clear" },
    "vault": { "type": "string" }
  },
  "required": ["id"]
}
```

### keeper.mark
**Description:** Set status (`open|done|deleted`).  
**Input:** `{ "id": 123, "status": "done", "vault": "…" }`

### keeper.delete
**Description:** Soft‑delete an item or archive all.  
**Input:** `{ "id": 123 }` or `{ "all": true }` plus optional `vault`.

### keeper.undo
**Description:** Undo last archive or specific id.  
**Input:** `{ "id": 123 }` (optional), `vault`.

### keeper.archive
**Description:** List archived items.  
**Input:** `{ "vault": "…" }`

### keeper.dash_due_timeline
**Description:** Due‑date timeline (next 15 days).  
**Input:** `{ "mermaid": false, "vault": "…" }`

### keeper.passwd (optional)
**Description:** Rotate password (requires current password).  
**Input:** `{ "current": "…", "new": "…", "vault": "…" }`

### keeper.recover (optional)
**Description:** Reset password using recovery code.  
**Input:** `{ "code": "…", "new": "…", "vault": "…" }`

## 5) Usage Flow (Agent)
1. Call `keeper.status`
2. If down and `KEEPER_AUTO_START=true`, call `keeper.start`
3. Perform reads/writes via tools
4. Avoid password ops unless explicitly enabled

## 6) Safety Expectations
- **Read‑only mode** should be respected unless explicitly disabled.
- **No implicit deletion**; the agent should ask before calling `delete` or `archive`.
- **Password ops** should only be allowed if `KEEPER_ALLOW_PASSWORD_OPS=true`.
- Prefer **update** over re‑creating tasks to preserve IDs.

## 7) Input Rules
For date inputs:
- Accept `YYYY-MM-DD`, `today`, `tomorrow`
- Invalid dates should produce a hard error (no silent fallback)

For priority:
- `p1`, `p2`, `p3`, `none`

## 8) Vault Selection
The MCP server uses `KEEPER_VAULT` by default.  
Each tool can optionally override with a `vault` parameter if supported.

## 9) Error Handling
- If daemon is down and auto‑start disabled: return a clear error to the user.
- If password is missing: return “Auto‑start requires password source.”
- If invalid due date: return “Invalid due date: …”
- If request rejected in read‑only mode: return “Read‑only mode enabled.”

## 10) Optional Enhancements
Future improvements for agent use:
- Structured JSON output for `get` (parse tables into objects)
- Tool capability discovery based on config (hide write tools)
- Rate limiting / audit logging
