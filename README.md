# Prompt Panda 🐼

A secure, lightweight AI assistant that runs entirely on your laptop using [Ollama](https://ollama.com). No cloud, no telemetry, no open ports.

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com/download) installed and running

## Install

```bash
# 1. Install Ollama and pull a model
ollama pull llama3.2

# 2. Install Prompt Panda
pip install -e .

# 3. Run
prompt-panda
```

That's it. On first run, the sandbox directory and audit log are created automatically.

## Configuration

Edit `config.yaml` to customise behaviour. Key options:

| Option | Default | Description |
|---|---|---|
| `ollama.model` | `llama3.2` | Any model installed in Ollama |
| `sandbox.root` | `~/ai_sandbox` | All file ops restricted to this path |
| `security.hitl_destructive` | `true` | Confirm before shell/write operations |
| `security.ipi_filter` | `true` | Block prompt injection attempts |
| `security.url_allowlist` | `[]` | Restrict web fetches to listed domains |
| `tools.shell` | `true` | Enable shell tool (always needs confirmation) |
| `tools.email` | `false` | Email tool — disabled by default |

## Security features

### Prompt injection protection
Every user message is checked against a set of regex rules before being sent to the LLM. Attempts to override instructions, reassign roles, or spoof authority are blocked and logged.

### Path sandboxing
All file operations are restricted to the configured sandbox directory. Path traversal attempts (`../`, `%2e%2e`, etc.) are blocked at the tool level.

### URL security
Every outbound web request is logged to the audit database — domain, status code, response size, and session ID. Internal/private addresses are always blocked (SSRF prevention). You can restrict fetches to an allowlist of domains in `config.yaml`.

### Human-in-the-loop (HITL)
Shell commands, file writes, and email sends require explicit confirmation before executing. You see exactly what Prompt Panda wants to do before it happens.

### Audit log
All activity is recorded in a local SQLite database (`~/prompt_panda_audit.db`). This includes every message, tool call, blocked URL, and IPI detection. The log is append-only and never transmitted anywhere.

## Checking the audit log

```bash
# View recent events
sqlite3 ~/prompt_panda_audit.db "SELECT ts, kind, summary FROM log ORDER BY ts DESC LIMIT 20;"

# View all URL fetches
sqlite3 ~/prompt_panda_audit.db "SELECT ts, domain, blocked, status_code FROM url_fetch_log ORDER BY ts DESC;"

# View blocked URLs only
sqlite3 ~/prompt_panda_audit.db "SELECT ts, url, block_reason FROM url_fetch_log WHERE blocked=1;"
```

## Email

```yaml
tools:
  email: true

email:
  imap_host: 127.0.0.1
  imap_port: 1143
  imap_ssl: false
  username: you@proton.me
  password: your-bridge-password
```

**Available operations:**

| Tool | Description |
|---|---|
| `email_inbox` | List recent messages. Supports `folder`, `limit`, `unread` params |
| `email_read` | Read full message content by UID |
| `email_search` | Search by text (`query`), sender (`from_`), or date (`since`) |
| `email_folders` | List all available folders/labels |
| `email_delete` | Hard delete a message by UID |
| `email_send` | Send email with `to`, `subject`, `body` (and optional `cc`, `bcc` |

**Example prompts:**
- "Check my inbox for unread messages"
- "Search for emails from alice@example.com this week"
- "Read email the latest email from alice@example.com"
- "What folders do I have?"

## Optional integrations

### Telegram (polling — no open ports)
```bash
pip install -e ".[telegram]"
prompt-panda --telegram
```
Set `messaging.telegram.enabled: true` and add your bot token to `config.yaml`.

If `messaging.telegram.allowed_users` is set, only those Telegram user IDs can use the bot.

### Telegram troubleshooting

**Error:** `telegram.error.Conflict: terminated by other getUpdates request`

This means more than one bot process is polling with the same token.

```bash
# Stop any existing Telegram bot processes
pkill -f "prompt-panda --telegram"

# Start exactly one process
prompt-panda --telegram
```

If you use a process manager (LaunchAgent, systemd, Docker, etc.), make sure it runs only a single replica.

## Project structure

```
prompt-panda/
├── prompt_panda/
│   ├── __init__.py
│   ├── agent_core.py   # main loop, tool dispatch, Ollama integration
│   ├── ipi_filter.py   # prompt injection detection
│   └── audit_log.py    # SQLite audit log
├── main.py             # CLI entry point
├── config.yaml         # configuration
└── pyproject.toml      # package metadata and dependencies
```

## Addressed vulnerabilities

Prompt Panda directly addresses the known OpenClaw security issues:

| Vulnerability | Fix |
|---|---|
| WebSocket localhost hijack | No exposed WebSocket — no gateway process |
| Indirect prompt injection | IPI regex filter on all user input |
| Malicious plugin execution | No plugin system — tools are code-defined only |
| Silent data exfiltration | Every URL fetch logged; allowlist available |
| Unauthenticated exposed port | No open ports — Telegram|
| Path traversal | `_safe_path()` sandbox enforcement |
| SSRF | Internal address blocklist on all web fetches |
