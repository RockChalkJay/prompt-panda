# audit_log.py — append-only SQLite audit log
# Uses Python stdlib only. Single file, zero config.
from __future__ import annotations
import json
import os
import sqlite3
import time
import uuid
from typing import Any, Optional


class AuditLog:
    def __init__(self, db_path: str) -> None:
        self.db_path = os.path.expanduser(db_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init()

    def _init(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS log (
                id         TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                ts         REAL NOT NULL,
                kind       TEXT NOT NULL,
                summary    TEXT NOT NULL,
                detail     TEXT
            );

            CREATE TABLE IF NOT EXISTS url_fetch_log (
                id         TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                ts         REAL NOT NULL,
                url        TEXT NOT NULL,
                domain     TEXT NOT NULL,
                blocked    INTEGER NOT NULL DEFAULT 0,
                block_reason TEXT,
                status_code  INTEGER,
                response_len INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_log_session  ON log(session_id);
            CREATE INDEX IF NOT EXISTS idx_log_kind     ON log(kind);
            CREATE INDEX IF NOT EXISTS idx_url_domain   ON url_fetch_log(domain);
            CREATE INDEX IF NOT EXISTS idx_url_session  ON url_fetch_log(session_id);
        """)
        self.conn.commit()

    # ── General event log ─────────────────────

    def write(
        self,
        session_id: str,
        kind: str,
        summary: str,
        detail: Any = "",
    ) -> str:
        """
        Log a general event. kind is one of:
          message      — user sent a message
          ipi_block    — IPI filter triggered
          tool_call    — tool executed successfully
          tool_deny    — tool blocked (ACL, HITL rejected, param violation)
          url_fetch    — outbound web request (see also log_url_fetch)
          error        — unexpected error
        Returns the audit id.
        """
        audit_id = str(uuid.uuid4())
        if not isinstance(detail, str):
            detail = json.dumps(detail)
        self.conn.execute(
            "INSERT INTO log VALUES (?,?,?,?,?,?)",
            (audit_id, session_id, time.time(), kind, summary[:500], detail[:2000]),
        )
        self.conn.commit()
        return audit_id

    # ── URL fetch log — the exfiltration gap fix ──

    def log_url_fetch(
        self,
        session_id: str,
        url: str,
        blocked: bool,
        block_reason: Optional[str] = None,
        status_code: Optional[int] = None,
        response_len: Optional[int] = None,
    ) -> None:
        """
        Records every URL the agent attempts to fetch — allowed or blocked.
        This is the primary defence against silent data exfiltration:
        every outbound request is traceable to a session and timestamp.
        """
        import urllib.parse
        domain = urllib.parse.urlparse(url).hostname or "unknown"

        self.conn.execute(
            "INSERT INTO url_fetch_log VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                session_id,
                time.time(),
                url[:2000],
                domain,
                int(blocked),
                block_reason,
                status_code,
                response_len,
            ),
        )
        self.conn.commit()

    # ── Query helpers (for web UI / CLI review) ──

    def recent(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, session_id, ts, kind, summary FROM log "
            "ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"id": r[0], "session_id": r[1], "ts": r[2], "kind": r[3], "summary": r[4]}
            for r in rows
        ]

    def recent_urls(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts, url, domain, blocked, block_reason, status_code "
            "FROM url_fetch_log ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "ts": r[0], "url": r[1], "domain": r[2],
                "blocked": bool(r[3]), "block_reason": r[4], "status_code": r[5],
            }
            for r in rows
        ]

    def blocked_urls(self) -> list[dict]:
        """All URLs that were blocked — useful for reviewing exfiltration attempts."""
        rows = self.conn.execute(
            "SELECT ts, session_id, url, block_reason "
            "FROM url_fetch_log WHERE blocked=1 ORDER BY ts DESC",
        ).fetchall()
        return [
            {"ts": r[0], "session_id": r[1], "url": r[2], "block_reason": r[3]}
            for r in rows
        ]
