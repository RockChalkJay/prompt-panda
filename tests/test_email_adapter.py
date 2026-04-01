"""
tests/test_email_adapter.py
===========================
Unit and integration tests for prompt_panda/email_adapter.py

Layers
------
1. Pure unit tests  — helpers with no I/O (_decode_header, _extract_body, etc.)
2. Mock tests       — IMAP/SMTP interactions mocked with unittest.mock
3. Integration      — marked @pytest.mark.integration; require a live IMAP server
                      (e.g. ProtonMail Bridge or a local Greenmail / Dovecot instance)

Run unit + mock tests only (the normal default):
    pytest tests/test_email_adapter.py

Run integration tests (needs a real server):
    pytest tests/test_email_adapter.py -m integration \
        --imap-host=127.0.0.1 --imap-port=1143 \
        --imap-user=you@proton.me --imap-pass=bridge-password

Install test deps:
    pip install pytest pytest-mock
"""

from __future__ import annotations

import email as email_module
import email.mime.multipart
import email.mime.text
import imaplib
import smtplib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

# ── Import the module under test ─────────────────────────────────────────────
# Adjust the import path to match your project layout.
# If you run pytest from the repo root with prompt_panda/ as a package:
from prompt_panda.email_adapter import (
    _decode_header,
    _extract_body,
    _format_message,
    run_email_inbox,
    run_email_read,
    run_email_search,
    run_email_folders,
    run_email_delete,
    run_email_send,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def cfg():
    """Minimal config object — mirrors the attributes read by email_adapter."""
    return SimpleNamespace(
        email_imap_host="127.0.0.1",
        email_imap_port=1143,
        email_imap_ssl=False,
        email_smtp_host="127.0.0.1",
        email_smtp_port=1025,
        email_smtp_ssl=False,
        email_username="panda@example.com",
        email_password="secret",
    )


@pytest.fixture
def audit():
    """Mock AuditLog — we verify it was called but don't hit SQLite."""
    return MagicMock()


# ── Email message factories ───────────────────────────────────────────────────

def make_plain_email(
    subject: str = "Test Subject",
    from_: str = "alice@example.com",
    body: str = "Hello, world!",
    date: str = "Mon, 01 Jan 2024 12:00:00 +0000",
) -> bytes:
    msg = email_module.mime.text.MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = from_
    msg["Date"] = date
    return msg.as_bytes()


def make_multipart_email(
    text_body: str | None = "Plain text body",
    html_body: str | None = "<p>HTML body</p>",
) -> bytes:
    msg = email_module.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = "Multipart"
    msg["From"] = "bob@example.com"
    msg["Date"] = "Tue, 02 Jan 2024 08:00:00 +0000"
    if text_body:
        msg.attach(email_module.mime.text.MIMEText(text_body, "plain"))
    if html_body:
        msg.attach(email_module.mime.text.MIMEText(html_body, "html"))
    return msg.as_bytes()


def make_imap_conn(
    uid_list: list[bytes] | None = None,
    raw_email: bytes | None = None,
    select_status: str = "OK",
    search_status: str = "OK",
    fetch_status: str = "OK",
    folder_list: list[bytes] | None = None,
    store_status: str = "OK",
    expunge_status: str = "OK",
) -> MagicMock:
    """
    Return a MagicMock that looks like an imaplib.IMAP4 instance.
    Plug into: mock_imap4_cls.return_value = make_imap_conn(...)
    """
    raw = raw_email or make_plain_email()
    uids = uid_list if uid_list is not None else [b"1", b"2", b"3"]
    uid_bytes = b" ".join(uids)

    conn = MagicMock()
    conn.select.return_value = (select_status, [b"3"])
    conn.search.return_value = (search_status, [uid_bytes])
    conn.fetch.return_value = (fetch_status, [(b"1 (RFC822 {42})", raw)])
    conn.list.return_value = (
        "OK",
        folder_list
        or [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "Sent"',
            b'(\\HasNoChildren) "/" "Trash"',
        ],
    )
    conn.store.return_value = (store_status, [b"1"])
    conn.expunge.return_value = (expunge_status, [b"1"])
    conn.logout.return_value = ("BYE", [])
    return conn


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Pure unit tests — helpers (no I/O)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecodeHeader:
    def test_plain_ascii(self):
        assert _decode_header("Hello World") == "Hello World"

    def test_empty_string(self):
        assert _decode_header("") == ""

    def test_none_like_fallback(self):
        # The function does `or ""` so None-ish values become ""
        assert _decode_header(None) == ""   # type: ignore[arg-type]

    def test_rfc2047_utf8_encoded(self):
        # "=?utf-8?b?...?=" encodes "Pröject Üncode"
        encoded = "=?utf-8?b?UHLDtmpla3Qgw5xuY29kZQ==?="
        result = _decode_header(encoded)
        assert "Prö" in result or "ncode" in result  # decoded, not raw

    def test_rfc2047_quoted_printable(self):
        encoded = "=?utf-8?q?caf=C3=A9?="
        result = _decode_header(encoded)
        assert result == "café"

    def test_mixed_encoded_and_plain(self):
        # Header with both encoded and plain parts
        mixed = "=?utf-8?q?Hello?= World"
        result = _decode_header(mixed)
        assert "Hello" in result
        assert "World" in result


class TestExtractBody:
    def test_simple_plain_text(self):
        raw = make_plain_email(body="Simple body text")
        msg = email_module.message_from_bytes(raw)
        assert _extract_body(msg) == "Simple body text"

    def test_multipart_prefers_plain_over_html(self):
        raw = make_multipart_email(text_body="Plain wins", html_body="<p>HTML loses</p>")
        msg = email_module.message_from_bytes(raw)
        body = _extract_body(msg)
        assert "Plain wins" in body
        assert "<p>" not in body

    def test_multipart_html_fallback_when_no_plain(self):
        raw = make_multipart_email(text_body=None, html_body="<p>Only HTML here</p>")
        msg = email_module.message_from_bytes(raw)
        body = _extract_body(msg)
        assert "Only HTML here" in body
        assert "<p>" not in body  # tags stripped

    def test_strips_quoted_reply_lines(self):
        body_with_quotes = "Thanks!\n\n> On Mon wrote:\n> original message\n\nCheers"
        raw = make_plain_email(body=body_with_quotes)
        msg = email_module.message_from_bytes(raw)
        result = _extract_body(msg)
        assert "> On Mon wrote:" not in result
        assert "Thanks!" in result
        assert "Cheers" in result

    def test_caps_at_3000_chars(self):
        long_body = "x" * 5000
        raw = make_plain_email(body=long_body)
        msg = email_module.message_from_bytes(raw)
        assert len(_extract_body(msg)) == 3000

    def test_empty_message(self):
        msg = email_module.message_from_string("")
        result = _extract_body(msg)
        assert result == ""


class TestFormatMessage:
    def test_summary_without_body(self):
        raw = make_plain_email(subject="My Subject", from_="alice@example.com")
        msg = email_module.message_from_bytes(raw)
        result = _format_message("42", msg, include_body=False)
        assert "UID:     42" in result
        assert "My Subject" in result
        assert "alice@example.com" in result
        # Body should not appear
        assert "Hello, world!" not in result

    def test_summary_with_body(self):
        raw = make_plain_email(body="Read me carefully")
        msg = email_module.message_from_bytes(raw)
        result = _format_message("7", msg, include_body=True)
        assert "Read me carefully" in result

    def test_no_subject_fallback(self):
        msg = email_module.message_from_string("From: x@example.com\n\nBody")
        result = _format_message("1", msg, include_body=False)
        assert "(no subject)" in result


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Early-return / input-validation tests (no I/O needed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEarlyValidation:
    def test_read_requires_uid(self, cfg, audit):
        result = run_email_read({}, cfg, audit, "sess-1")
        assert "uid is required" in result.lower()
        audit.write.assert_not_called()  # Logged only after validation passes

    def test_search_requires_at_least_one_criterion(self, cfg, audit):
        result = run_email_search({}, cfg, audit, "sess-1")
        assert "provide at least one" in result.lower()

    def test_send_requires_to_subject_body(self, cfg, audit):
        result = run_email_send({"to": "x@y.com"}, cfg, audit, "sess-1")
        assert "required" in result.lower()

        result = run_email_send({"to": "x@y.com", "subject": "Hi"}, cfg, audit, "sess-1")
        assert "required" in result.lower()

    def test_delete_requires_uid(self, cfg, audit):
        result = run_email_delete({}, cfg, audit, "sess-1")
        assert "uid is required" in result.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. IMAP mock tests — run_email_inbox
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunEmailInbox:
    PATCH = "prompt_panda.email_adapter.imaplib.IMAP4"

    def test_happy_path_returns_formatted_messages(self, cfg, audit):
        raw = make_plain_email(subject="Hello Panda", from_="alice@example.com")
        conn = make_imap_conn(uid_list=[b"1"], raw_email=raw)

        with patch(self.PATCH, return_value=conn):
            result = run_email_inbox({"limit": "1"}, cfg, audit, "sess-1")

        assert "Hello Panda" in result
        assert "alice@example.com" in result
        audit.write.assert_called_once()

    def test_empty_inbox(self, cfg, audit):
        conn = make_imap_conn(uid_list=[])

        with patch(self.PATCH, return_value=conn):
            result = run_email_inbox({}, cfg, audit, "sess-1")

        assert "No" in result

    def test_unread_only_uses_unseen_criteria(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"5"])

        with patch(self.PATCH, return_value=conn):
            run_email_inbox({"unread": "true"}, cfg, audit, "sess-1")

        conn.search.assert_called_once_with(None, "UNSEEN")

    def test_all_messages_use_all_criteria(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"1"])

        with patch(self.PATCH, return_value=conn):
            run_email_inbox({}, cfg, audit, "sess-1")

        conn.search.assert_called_once_with(None, "ALL")

    def test_limit_is_capped_at_25(self, cfg, audit):
        # Build 30 UIDs; the adapter should only fetch 25
        uids = [str(i).encode() for i in range(1, 31)]
        conn = make_imap_conn(uid_list=uids)

        with patch(self.PATCH, return_value=conn):
            run_email_inbox({"limit": "99"}, cfg, audit, "sess-1")

        # fetch should have been called at most 25 times
        assert conn.fetch.call_count <= 25

    def test_bad_folder_returns_error(self, cfg, audit):
        conn = make_imap_conn(select_status="NO")

        with patch(self.PATCH, return_value=conn):
            result = run_email_inbox({"folder": "NoSuchFolder"}, cfg, audit, "sess-1")

        assert "Error" in result

    def test_imap_error_is_caught(self, cfg, audit):
        conn = make_imap_conn()
        conn.search.side_effect = imaplib.IMAP4.error("search failed")

        with patch(self.PATCH, return_value=conn):
            result = run_email_inbox({}, cfg, audit, "sess-1")

        assert "IMAP error" in result

    def test_connection_refused_is_caught(self, cfg, audit):
        with patch(self.PATCH, side_effect=ConnectionRefusedError):
            result = run_email_inbox({}, cfg, audit, "sess-1")

        assert "connect" in result.lower()

    def test_folder_param_is_forwarded(self, cfg, audit):
        conn = make_imap_conn(uid_list=[])

        with patch(self.PATCH, return_value=conn):
            run_email_inbox({"folder": "Sent"}, cfg, audit, "sess-1")

        conn.select.assert_called_once_with("Sent", readonly=True)

    def test_results_are_most_recent_first(self, cfg, audit):
        """UIDs come back in ascending order from IMAP; adapter should reverse them."""
        # Use two distinct emails so we can check order
        raw_old = make_plain_email(subject="Old message")
        raw_new = make_plain_email(subject="New message")

        conn = make_imap_conn(uid_list=[b"1", b"2"])
        conn.fetch.side_effect = [
            # uid 2 fetched first (most-recent)
            ("OK", [(b"2 (RFC822 {1})", raw_new)]),
            # uid 1 fetched second
            ("OK", [(b"1 (RFC822 {1})", raw_old)]),
        ]

        with patch(self.PATCH, return_value=conn):
            result = run_email_inbox({"limit": "2"}, cfg, audit, "sess-1")

        new_pos = result.find("New message")
        old_pos = result.find("Old message")
        assert new_pos < old_pos, "Most recent message should appear first"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. IMAP mock tests — run_email_read
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunEmailRead:
    PATCH = "prompt_panda.email_adapter.imaplib.IMAP4"

    def test_happy_path_includes_body(self, cfg, audit):
        raw = make_plain_email(subject="Read Me", body="Full email body here.")
        conn = make_imap_conn(raw_email=raw)

        with patch(self.PATCH, return_value=conn):
            result = run_email_read({"uid": "1"}, cfg, audit, "sess-1")

        assert "Read Me" in result
        assert "Full email body here." in result

    def test_uid_not_found_returns_error(self, cfg, audit):
        conn = make_imap_conn(fetch_status="NO")

        with patch(self.PATCH, return_value=conn):
            result = run_email_read({"uid": "999"}, cfg, audit, "sess-1")

        assert "not found" in result.lower() or "Error" in result

    def test_audit_logged_with_uid(self, cfg, audit):
        conn = make_imap_conn()

        with patch(self.PATCH, return_value=conn):
            run_email_read({"uid": "42", "folder": "INBOX"}, cfg, audit, "sess-1")

        audit.write.assert_called_once()
        call_args = audit.write.call_args[0]
        assert "uid=42" in call_args[2]

    def test_custom_folder_used(self, cfg, audit):
        conn = make_imap_conn()

        with patch(self.PATCH, return_value=conn):
            run_email_read({"uid": "1", "folder": "Sent"}, cfg, audit, "sess-1")

        conn.select.assert_called_once_with("Sent", readonly=True)

    def test_connection_refused(self, cfg, audit):
        with patch(self.PATCH, side_effect=ConnectionRefusedError):
            result = run_email_read({"uid": "1"}, cfg, audit, "sess-1")

        assert "connect" in result.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. IMAP mock tests — run_email_search
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunEmailSearch:
    PATCH = "prompt_panda.email_adapter.imaplib.IMAP4"

    def test_text_query_builds_text_criteria(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"1"])

        with patch(self.PATCH, return_value=conn):
            run_email_search({"query": "invoice"}, cfg, audit, "sess-1")

        search_call = conn.search.call_args[0]
        assert 'TEXT "invoice"' in search_call[1]

    def test_from_filter_builds_from_criteria(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"1"])

        with patch(self.PATCH, return_value=conn):
            run_email_search({"from_": "boss@work.com"}, cfg, audit, "sess-1")

        search_call = conn.search.call_args[0]
        assert 'FROM "boss@work.com"' in search_call[1]

    def test_since_builds_since_criteria(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"1"])

        with patch(self.PATCH, return_value=conn):
            run_email_search({"since": "01-Jan-2025"}, cfg, audit, "sess-1")

        search_call = conn.search.call_args[0]
        assert "SINCE 01-Jan-2025" in search_call[1]

    def test_combined_criteria(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"1"])

        with patch(self.PATCH, return_value=conn):
            run_email_search(
                {"query": "report", "from_": "alice@example.com", "since": "01-Mar-2025"},
                cfg, audit, "sess-1",
            )

        criteria = conn.search.call_args[0][1]
        assert 'TEXT "report"' in criteria
        assert 'FROM "alice@example.com"' in criteria
        assert "SINCE 01-Mar-2025" in criteria

    def test_no_results(self, cfg, audit):
        conn = make_imap_conn(uid_list=[])

        with patch(self.PATCH, return_value=conn):
            result = run_email_search({"query": "unicorn"}, cfg, audit, "sess-1")

        assert "No messages" in result

    def test_strips_quotes_from_query_to_prevent_injection(self, cfg, audit):
        """Quotes in user input would break IMAP syntax — they must be stripped."""
        conn = make_imap_conn(uid_list=[])

        with patch(self.PATCH, return_value=conn):
            run_email_search({"query": 'bad"quote'}, cfg, audit, "sess-1")

        criteria = conn.search.call_args[0][1]
        # The outer quotes are from the adapter's formatting; inner ones should be gone
        assert 'TEXT "badquote"' in criteria

    def test_result_header_shows_total_count(self, cfg, audit):
        conn = make_imap_conn(uid_list=[b"1", b"2", b"3"])

        with patch(self.PATCH, return_value=conn):
            result = run_email_search({"query": "hello"}, cfg, audit, "sess-1")

        assert "3" in result  # total count shown in header


# ═══════════════════════════════════════════════════════════════════════════════
# 6. IMAP mock tests — run_email_folders
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunEmailFolders:
    PATCH = "prompt_panda.email_adapter.imaplib.IMAP4"

    def test_happy_path_returns_sorted_folder_names(self, cfg, audit):
        folders = [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "Sent"',
            b'(\\HasNoChildren) "/" "Trash"',
        ]
        conn = make_imap_conn(folder_list=folders)

        with patch(self.PATCH, return_value=conn):
            result = run_email_folders({}, cfg, audit, "sess-1")

        assert "INBOX" in result
        assert "Sent" in result
        assert "Trash" in result

    def test_connection_refused(self, cfg, audit):
        with patch(self.PATCH, side_effect=ConnectionRefusedError):
            result = run_email_folders({}, cfg, audit, "sess-1")

        assert "connect" in result.lower()

    def test_list_failure_returns_error(self, cfg, audit):
        conn = make_imap_conn()
        conn.list.return_value = ("NO", [])

        with patch(self.PATCH, return_value=conn):
            result = run_email_folders({}, cfg, audit, "sess-1")

        assert "Error" in result

    def test_audit_logged(self, cfg, audit):
        conn = make_imap_conn()

        with patch(self.PATCH, return_value=conn):
            run_email_folders({}, cfg, audit, "sess-1")

        audit.write.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# 7. IMAP mock tests — run_email_delete
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunEmailDelete:
    PATCH = "prompt_panda.email_adapter.imaplib.IMAP4"

    def test_soft_delete_marks_but_does_not_expunge(self, cfg, audit):
        conn = make_imap_conn()

        with patch(self.PATCH, return_value=conn):
            result = run_email_delete({"uid": "5"}, cfg, audit, "sess-1")

        conn.store.assert_called_once_with(b"5", "+FLAGS", "\\Deleted")
        conn.expunge.assert_not_called()
        assert "trash" in result.lower() or "marked" in result.lower()

    def test_permanent_delete_expunges(self, cfg, audit):
        conn = make_imap_conn()

        with patch(self.PATCH, return_value=conn):
            result = run_email_delete(
                {"uid": "5", "permanent": "true"}, cfg, audit, "sess-1"
            )

        conn.store.assert_called_once()
        conn.expunge.assert_called_once()
        assert "permanently" in result.lower() or "deleted" in result.lower()

    def test_store_failure_returns_error(self, cfg, audit):
        conn = make_imap_conn(store_status="NO")

        with patch(self.PATCH, return_value=conn):
            result = run_email_delete({"uid": "5"}, cfg, audit, "sess-1")

        assert "Error" in result

    def test_audit_logged_with_uid(self, cfg, audit):
        conn = make_imap_conn()

        with patch(self.PATCH, return_value=conn):
            run_email_delete({"uid": "7"}, cfg, audit, "sess-1")

        audit.write.assert_called_once()
        assert "uid=7" in audit.write.call_args[0][2]

    def test_connection_refused(self, cfg, audit):
        with patch(self.PATCH, side_effect=ConnectionRefusedError):
            result = run_email_delete({"uid": "1"}, cfg, audit, "sess-1")

        assert "connect" in result.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 8. SMTP mock tests — run_email_send
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunEmailSend:
    SMTP_PATCH = "prompt_panda.email_adapter.smtplib.SMTP"

    def _valid_params(self):
        return {
            "to": "bob@example.com",
            "subject": "Hello",
            "body": "This is the body.",
        }

    def test_happy_path_sends_and_returns_success(self, cfg, audit):
        mock_smtp = MagicMock()

        with patch(self.SMTP_PATCH, return_value=mock_smtp):
            result = run_email_send(self._valid_params(), cfg, audit, "sess-1")

        mock_smtp.login.assert_called_once_with(cfg.email_username, cfg.email_password)
        mock_smtp.sendmail.assert_called_once()
        mock_smtp.quit.assert_called_once()
        assert "bob@example.com" in result

    def test_cc_and_bcc_included_in_recipients(self, cfg, audit):
        mock_smtp = MagicMock()
        params = {
            **self._valid_params(),
            "cc": "carol@example.com",
            "bcc": "dave@example.com",
        }

        with patch(self.SMTP_PATCH, return_value=mock_smtp):
            run_email_send(params, cfg, audit, "sess-1")

        _, recipients, _ = mock_smtp.sendmail.call_args[0]
        assert "carol@example.com" in recipients
        assert "dave@example.com" in recipients

    def test_starttls_called_for_non_ssl(self, cfg, audit):
        mock_smtp = MagicMock()

        with patch(self.SMTP_PATCH, return_value=mock_smtp):
            run_email_send(self._valid_params(), cfg, audit, "sess-1")

        mock_smtp.starttls.assert_called_once()

    def test_smtp_ssl_uses_smtp_ssl_class(self, cfg, audit):
        cfg.email_smtp_ssl = True
        mock_smtp = MagicMock()

        with patch("prompt_panda.email_adapter.smtplib.SMTP_SSL", return_value=mock_smtp):
            run_email_send(self._valid_params(), cfg, audit, "sess-1")

        mock_smtp.sendmail.assert_called_once()
        # starttls should NOT be called when using SMTP_SSL
        mock_smtp.starttls.assert_not_called()

    def test_auth_error_returns_friendly_message(self, cfg, audit):
        mock_smtp = MagicMock()
        mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Bad credentials")

        with patch(self.SMTP_PATCH, return_value=mock_smtp):
            result = run_email_send(self._valid_params(), cfg, audit, "sess-1")

        assert "authentication" in result.lower() or "SMTP" in result

    def test_connection_refused_returns_friendly_message(self, cfg, audit):
        with patch(self.SMTP_PATCH, side_effect=ConnectionRefusedError):
            result = run_email_send(self._valid_params(), cfg, audit, "sess-1")

        assert "connect" in result.lower()

    def test_smtp_exception_caught(self, cfg, audit):
        mock_smtp = MagicMock()
        mock_smtp.sendmail.side_effect = smtplib.SMTPException("relay denied")

        with patch(self.SMTP_PATCH, return_value=mock_smtp):
            result = run_email_send(self._valid_params(), cfg, audit, "sess-1")

        assert "SMTP error" in result or "relay" in result

    def test_audit_logged_with_recipient(self, cfg, audit):
        mock_smtp = MagicMock()

        with patch(self.SMTP_PATCH, return_value=mock_smtp):
            run_email_send(self._valid_params(), cfg, audit, "sess-1")

        audit.write.assert_called_once()
        assert "bob@example.com" in audit.write.call_args[0][2]


# ═══════════════════════════════════════════════════════════════════════════════
# 9. IMAPConnection — context manager behaviour
# ═══════════════════════════════════════════════════════════════════════════════

class TestIMAPConnection:
    """Test the context manager itself, not the tool runners."""

    from prompt_panda.email_adapter import IMAPConnection  # noqa: E402  (class-level import)

    def test_enter_calls_login(self):
        from prompt_panda.email_adapter import IMAPConnection

        mock_imap = MagicMock()
        with patch("prompt_panda.email_adapter.imaplib.IMAP4", return_value=mock_imap):
            with IMAPConnection("127.0.0.1", 1143, "user", "pass", use_ssl=False) as c:
                assert c.conn is mock_imap

        mock_imap.login.assert_called_once_with("user", "pass")
        mock_imap.logout.assert_called_once()

    def test_exit_calls_logout_even_on_exception(self):
        from prompt_panda.email_adapter import IMAPConnection

        mock_imap = MagicMock()
        with patch("prompt_panda.email_adapter.imaplib.IMAP4", return_value=mock_imap):
            try:
                with IMAPConnection("127.0.0.1", 1143, "u", "p", use_ssl=False):
                    raise ValueError("boom")
            except ValueError:
                pass

        mock_imap.logout.assert_called_once()

    def test_conn_raises_if_not_entered(self):
        from prompt_panda.email_adapter import IMAPConnection

        conn = IMAPConnection("127.0.0.1", 1143, "u", "p", use_ssl=False)
        with pytest.raises(RuntimeError, match="context manager"):
            _ = conn.conn

    def test_ssl_uses_imap4_ssl_class(self):
        from prompt_panda.email_adapter import IMAPConnection

        mock_imap = MagicMock()
        with patch(
            "prompt_panda.email_adapter.imaplib.IMAP4_SSL", return_value=mock_imap
        ) as mock_cls:
            with IMAPConnection("127.0.0.1", 993, "u", "p", use_ssl=True):
                pass

        mock_cls.assert_called_once_with("127.0.0.1", 993)
