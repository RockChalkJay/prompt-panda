# email_adapter.py

from __future__ import annotations
import email
import email.header
import email.mime.text
import imaplib
import re
import smtplib
import textwrap
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _decode_header(raw: str) -> str:
    """Decode RFC2047-encoded email headers (=?utf-8?...?=) to plain text."""
    parts = email.header.decode_header(raw or "")
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded).strip()


def _extract_body(msg: email.message.Message) -> str:
    """
    Extract plain-text body from an email.Message.
    Prefers text/plain over text/html.
    Strips quoted reply text (lines starting with '>') to keep output concise.
    """
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body = payload.decode(charset, errors="replace")
                    break
            elif ct == "text/html" and not body and "attachment" not in cd:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    raw_html = payload.decode(charset, errors="replace")
                    # Strip HTML tags for LLM consumption
                    body = re.sub(r"<[^>]+>", " ", raw_html)
                    body = re.sub(r"\s+", " ", body).strip()
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace")

    # Strip quoted reply lines
    lines = [l for l in body.splitlines() if not l.startswith(">")]
    body = "\n".join(lines).strip()

    return body[:3000]  # cap for LLM context


def _format_message(uid: str, msg: email.message.Message, include_body: bool = False) -> str:
    """Format a message as a readable summary string."""
    subject = _decode_header(msg.get("Subject", "(no subject)"))
    sender  = _decode_header(msg.get("From", "unknown"))
    date    = msg.get("Date", "unknown date")
    lines = [
        f"UID:     {uid}",
        f"From:    {sender}",
        f"Date:    {date}",
        f"Subject: {subject}",
    ]
    if include_body:
        body = _extract_body(msg)
        lines.append(f"\n{body}")
    return "\n".join(lines)


# ─────────────────────────────────────────────
# IMAP connection manager
# ─────────────────────────────────────────────

class IMAPConnection:
    """
    Thin context manager around imaplib.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool,
    ) -> None:
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.use_ssl  = use_ssl
        self._conn: Optional[imaplib.IMAP4] = None

    def __enter__(self) -> "IMAPConnection":
        if self.use_ssl:
            self._conn = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            self._conn = imaplib.IMAP4(self.host, self.port)
        self._conn.login(self.username, self.password)
        return self

    def __exit__(self, *_) -> None:
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    @property
    def conn(self) -> imaplib.IMAP4:
        if self._conn is None:
            raise RuntimeError("Not connected — use as context manager")
        return self._conn


# ─────────────────────────────────────────────
# Email tool runners
# ─────────────────────────────────────────────

def _make_connection(config) -> IMAPConnection:
    """Build an IMAPConnection from config."""
    return IMAPConnection(
        host=config.email_imap_host,
        port=config.email_imap_port,
        username=config.email_username,
        password=config.email_password,
        use_ssl=config.email_imap_ssl,
    )


def run_email_inbox(params: dict, config, audit, session_id: str, **_) -> str:
    """
    List recent messages from a mailbox folder.
    params:
      folder  — IMAP folder name (default: INBOX)
      limit   — number of messages to return (default: 10, max: 25)
      unread  — if true, only return unread messages (default: false)
    """
    folder = params.get("folder", "INBOX")
    limit  = min(int(params.get("limit", 10)), 25)
    unread_only = str(params.get("unread", "false")).lower() == "true"

    audit.write(session_id, "tool_call",
                f"email_inbox folder={folder} limit={limit} unread={unread_only}")

    try:
        with _make_connection(config) as imap:
            status, _ = imap.conn.select(folder, readonly=True)
            if status != "OK":
                return f"Error: could not open folder {folder!r}"

            search_criteria = "UNSEEN" if unread_only else "ALL"
            status, data = imap.conn.search(None, search_criteria)
            if status != "OK":
                return "Error: inbox search failed"

            uid_list = data[0].split()
            if not uid_list:
                return f"No {'unread ' if unread_only else ''}messages in {folder}."

            # Most recent first
            recent_uids = uid_list[-limit:][::-1]
            results = []

            for uid in recent_uids:
                status, msg_data = imap.conn.fetch(uid, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if not isinstance(raw, bytes):
                    continue
                msg = email.message_from_bytes(raw)
                results.append(_format_message(uid.decode(), msg, include_body=False))

            if not results:
                return "No messages found."

            header = f"Showing {len(results)} {'unread ' if unread_only else ''}message(s) from {folder}:\n"
            return header + "\n\n---\n\n".join(results)

    except ConnectionRefusedError:
        return (
            "Could not connect to the IMAP server. "
        )
    except Exception as e:
        quit
        # Check if it's an IMAP error by examining exception type
        if type(e).__name__ == 'error':
            return f"IMAP error: {e}"
        return f"Email error: {e}"


def run_email_read(params: dict, config, audit, session_id: str, **_) -> str:
    """
    Read the full content of a specific message by UID.
    params:
      uid     — message UID (from email_inbox results)
      folder  — IMAP folder (default: INBOX)
    """
    uid    = str(params.get("uid", "")).strip()
    folder = params.get("folder", "INBOX")

    if not uid:
        return "Error: uid is required"

    audit.write(session_id, "tool_call", f"email_read uid={uid} folder={folder}")

    try:
        with _make_connection(config) as imap:
            status, _ = imap.conn.select(folder, readonly=True)
            if status != "OK":
                return f"Error: could not open folder {folder!r}"

            status, msg_data = imap.conn.fetch(uid.encode(), "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                return f"Error: message UID {uid} not found"

            raw = msg_data[0][1]
            if not isinstance(raw, bytes):
                return "Error: unexpected message format"

            msg = email.message_from_bytes(raw)
            return _format_message(uid, msg, include_body=True)

    except ConnectionRefusedError:
        return (
            "Could not connect to IMAP server."
        )
    except Exception as e:
        # Check if it's an IMAP error by examining exception type
        if type(e).__name__ == 'error':
            return f"IMAP error: {e}"
        return f"Email error: {e}"


def run_email_search(params: dict, config, audit, session_id: str, **_) -> str:
    """
    Search email using IMAP search criteria.
    params:
      query   — search terms (searches subject and body text)
      folder  — IMAP folder (default: INBOX)
      from_   — filter by sender address (optional)
      since   — filter by date e.g. '01-Jan-2025' (optional)
      limit   — max results (default: 10, max: 25)
    """
    query   = params.get("query", "").strip()
    folder  = params.get("folder", "INBOX")
    from_   = params.get("from_", "").strip()
    since   = params.get("since", "").strip()
    limit   = min(int(params.get("limit", 10)), 25)

    if not query and not from_ and not since:
        return "Error: provide at least one of: query, from_, since"

    # Build IMAP search criteria
    # IMAP TEXT searches subject + body; FROM filters sender
    criteria_parts = []
    if query:
        # IMAP requires search terms to be quoted
        safe_query = query.replace('"', '')
        criteria_parts.append(f'TEXT "{safe_query}"')
    if from_:
        safe_from = from_.replace('"', '')
        criteria_parts.append(f'FROM "{safe_from}"')
    if since:
        criteria_parts.append(f'SINCE {since}')

    criteria = " ".join(criteria_parts) if criteria_parts else "ALL"

    audit.write(session_id, "tool_call",
                f"email_search criteria={criteria!r} folder={folder}")

    try:
        with _make_connection(config) as imap:
            status, _ = imap.conn.select(folder, readonly=True)
            if status != "OK":
                return f"Error: could not open folder {folder!r}"

            status, data = imap.conn.search(None, criteria)
            if status != "OK":
                return f"Error: search failed for criteria: {criteria!r}"

            uid_list = data[0].split()
            if not uid_list:
                return f"No messages found matching: {criteria}"

            # Most recent first, capped at limit
            recent_uids = uid_list[-limit:][::-1]
            results = []

            for uid in recent_uids:
                status, msg_data = imap.conn.fetch(uid, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if not isinstance(raw, bytes):
                    continue
                msg = email.message_from_bytes(raw)
                subject = msg["Subject"]
                results.append(_format_message(uid.decode(), msg, include_body=False))

            if not results:
                return "No messages found."

            header = (
                f"Found {len(uid_list)} message(s) total, "
                f"showing {len(results)} most recent:\n"
            )
            return header + "\n\n---\n\n".join(results)

    except ConnectionRefusedError:
        return (
            "Could not connect to IMAP server."
        )
    except Exception as e:
        # Check if it's an IMAP error by examining exception type
        if type(e).__name__ == 'error':
            return f"IMAP error: {e}"
        return f"Email error: {e}"


def run_email_folders(params: dict, config, audit, session_id: str, **_) -> str:
    """List all available IMAP folders/labels."""
    audit.write(session_id, "tool_call", "email_folders")
    try:
        with _make_connection(config) as imap:
            status, folders = imap.conn.list()
            if status != "OK":
                return "Error: could not list folders"
            names = []
            for f in folders:
                if isinstance(f, bytes):
                    # IMAP LIST response: (\Flags) "delimiter" "Name"
                    parts = f.decode(errors="replace").split('"')
                    if len(parts) >= 3:
                        names.append(parts[-2])
            return "Available folders:\n" + "\n".join(f"  {n}" for n in sorted(names))
    except ConnectionRefusedError:
        return (
            "Could not connect to IMAP server."
        )
    except Exception as e:
        return f"Email error: {e}"


def run_email_delete(params: dict, config, audit, session_id: str, **_) -> str:
    """
    Delete a message by UID. Moves it to the Trash/Deleted Items folder.
    params:
      uid     — message UID (from email_inbox results)
      folder  — IMAP folder (default: INBOX)
      permanent — if true, permanently delete (default: false, moves to trash)
    """
    uid = str(params.get("uid", "")).strip()
    folder = params.get("folder", "INBOX")
    permanent = str(params.get("permanent", "false")).lower() == "true"

    if not uid:
        return "Error: uid is required"

    audit.write(session_id, "tool_call",
                f"email_delete uid={uid} folder={folder} permanent={permanent}")

    try:
        with _make_connection(config) as imap:
            status, _ = imap.conn.select(folder)
            if status != "OK":
                print(f"Error: could not open folder {folder!r}")
                return f"Error: could not open folder {folder!r}"

            # Mark for deletion
            status, _ = imap.conn.store(uid.encode(), "+FLAGS", "\\Deleted")
            if status != "OK":
                return f"Error: could not mark message UID {uid} for deletion"

            # Expunge (permanently remove marked messages)
            if permanent:
                status, _ = imap.conn.expunge()
                if status != "OK":
                    return "Error: expunge failed"
                return f"Message UID {uid} permanently deleted from {folder}."
            else:
                return f"Message UID {uid} moved to trash (marked for deletion in {folder})."

    except ConnectionRefusedError:
        return (
            "Could not connect to email server. "
            "Check connection settings and try again."
        )
    except Exception as e:
        # Check if it's an IMAP error by examining exception type
        if type(e).__name__ == 'error':
            return f"IMAP error: {e}"
        return f"Email error: {e}"


def run_email_send(params: dict, config, audit, session_id: str, **_) -> str:
    """
    Send an email via SMTP.
    params:
      to      — recipient email address (required)
      subject — email subject (required)
      body    — email body text (required)
      cc      — comma-separated CC addresses (optional)
      bcc     — comma-separated BCC addresses (optional)
    """
    to = params.get("to", "").strip()
    subject = params.get("subject", "").strip()
    body = params.get("body", "").strip()
    cc = params.get("cc", "").strip()
    bcc = params.get("bcc", "").strip()

    if not to or not subject or not body:
        return "Error: to, subject, and body are required"

    audit.write(session_id, "tool_call",
                f"email_send to={to} subject={subject[:50]}")

    try:
        # Build recipient list
        recipients = [to]
        if cc:
            recipients.extend([a.strip() for a in cc.split(",")])
        if bcc:
            recipients.extend([a.strip() for a in bcc.split(",")])

        # Create message
        msg = email.mime.text.MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = config.email_username
        msg["To"] = to
        if cc:
            msg["CC"] = cc

        # Connect to SMTP and send
        if config.email_smtp_ssl:
            smtp = smtplib.SMTP_SSL(config.email_smtp_host, config.email_smtp_port)
        else:
            smtp = smtplib.SMTP(config.email_smtp_host, config.email_smtp_port)
            smtp.starttls()

        smtp.login(config.email_username, config.email_password)
        print("sending")
        smtp.sendmail(config.email_username, recipients, msg.as_string())
        smtp.quit()

        return f"Email sent to {to}"

    except smtplib.SMTPAuthenticationError:
        return f"SMTP authentication failed. Check username/password."
    except smtplib.SMTPException as e:
        return f"SMTP error: {e}"
    except ConnectionRefusedError:
        return (
            "Could not connect to SMTP server. "
            "Check SMTP host and port in config."
        )
    except Exception as e:
        return f"Email error: {e}"
