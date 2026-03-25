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

## Optional integrations

### Telegram (polling — no open ports)
```bash
pip install -e ".[telegram]"
```
Set `messaging.telegram.enabled: true` and add your bot token to `config.yaml`.

### Discord
```bash
pip install -e ".[discord]"
```
Set `messaging.discord.enabled: true` and add your bot token to `config.yaml`.

### Web UI
```bash
pip install -e ".[web]"
```
Access at `http://localhost:8080` (localhost only).

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
| Unauthenticated exposed port | No open ports — Telegram/Discord use polling |
| Path traversal | `_safe_path()` sandbox enforcement |
| SSRF | Internal address blocklist on all web fetches |
