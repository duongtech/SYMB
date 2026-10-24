# SYMB Installation & Agent Configuration

## Automated Setup (Recommended)

Run the one-command setup wizard:

```bash
npx symb-agents setup
```

The wizard detects installed agents and updates their config files automatically:
- **Claude Code**: Updates `claude.json` / `~/.claude.json`
- **Cursor**: Updates `.cursor/mcp.json` or Global Cursor Settings
- **Antigravity**: Updates MCP settings in `%USERPROFILE%\.gemini\antigravity\mcp`
- **Gemini CLI**: Updates `gemini.json`
- **Codex**: Updates Codex Agent MCP manifest

---

## Manual Agent Configuration

### 1. Claude Desktop / Claude Code
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "symb": {
      "command": "npx",
      "args": ["-y", "symb-agents"]
    }
  }
}
```

### 2. Cursor IDE
Add to your project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "symb": {
      "command": "npx",
      "args": ["-y", "symb-agents"]
    }
  }
}
```

### 3. Google Antigravity
Add to your Antigravity MCP settings:

```json
{
  "mcpServers": {
    "symb": {
      "command": "npx",
      "args": ["-y", "symb-agents"]
    }
  }
}
```

---

## Python Solver Environment Setup

While SYMB can operate in mock/lightweight mode without Python, high-performance symbolic execution requires the native solver backends:

```bash
pip install angr z3-solver triton
```
