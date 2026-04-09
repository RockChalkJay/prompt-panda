from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import TYPE_CHECKING

from telegram import Update
from telegram.constants import ChatAction
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

if TYPE_CHECKING:
    from .agent_core import AgentCore, Config

logger = logging.getLogger(__name__)
HITL_TIMEOUT_SECONDS = 120.0
MAX_TELEGRAM_MESSAGE_LENGTH = 4000

# Per-chat AgentCore instances — each chat gets its own conversation history
# and session ID, so conversations stay isolated.
_agents: dict[int, "AgentCore"] = {}


def _get_or_create_agent(chat_id: int, config: "Config") -> "AgentCore":
    """Return existing agent for this chat, or create a fresh one."""
    if chat_id not in _agents:
        from .agent_core import AgentCore

        _agents[chat_id] = AgentCore(
            config=config,
            hitl_fn=lambda prompt: False,   # overridden per-agent in adapter
            stream_fn=lambda text: None,    # overridden per-agent in adapter
        )
    return _agents[chat_id]


class TelegramAdapter:
    """
    Wraps AgentCore for Telegram. One instance drives the whole bot process.
    Each chat gets its own AgentCore so conversation histories stay separate.
    """

    def __init__(self, config: "Config") -> None:
        if not config.telegram_token:
            raise ValueError(
                "Telegram token is not set. "
                "Add your bot token to messaging.telegram.token in config.yaml."
            )
        self.config = config
        self._hitl_events: dict[int, asyncio.Event] = {}
        self._hitl_results: dict[int, bool] = {}
        self._hitl_active: dict[int, bool] = {}
        self._chat_locks: dict[int, asyncio.Lock] = {}
        self._seen_update_ids: set[int] = set()
        self._seen_update_ids_order: deque[int] = deque(maxlen=500)

    # ── Auth check ────────────────────────────

    def _is_allowed(self, user_id: int) -> bool:
        if not self.config.telegram_allowed_users:
            return True
        return user_id in self.config.telegram_allowed_users

    async def _ensure_authorized(self, update: Update) -> bool:
        user = update.effective_user
        if self._is_allowed(user.id):
            return True
        await update.message.reply_text("Sorry, you are not authorized to use this bot.")
        logger.warning(f"Unauthorised access attempt from user_id={user.id}")
        return False

    # ── Update deduplication ───────────────────

    def _is_duplicate_update(self, update: Update) -> bool:
        update_id = getattr(update, "update_id", None)
        if update_id is None:
            return False
        if update_id in self._seen_update_ids:
            logger.info(f"Duplicate Telegram update skipped: update_id={update_id}")
            return True
        logger.debug(f"New Telegram update: update_id={update_id}")
        if len(self._seen_update_ids_order) >= self._seen_update_ids_order.maxlen:
            oldest = self._seen_update_ids_order.popleft()
            self._seen_update_ids.discard(oldest)
        self._seen_update_ids.add(update_id)
        self._seen_update_ids_order.append(update_id)
        return False

    # ── HITL over Telegram ────────────────────

    async def _request_hitl(
        self,
        chat_id: int,
        prompt: str,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> bool:
        """
        Send the HITL confirmation request to the user and wait up to 120s
        for a /yes or /no reply. Returns True if approved, False otherwise.
        """
        if self._hitl_active.get(chat_id, False):
            logger.warning(
                f"HITL already active for chat_id={chat_id}; waiting on existing confirmation"
            )
            event = self._hitl_events[chat_id]
            try:
                await asyncio.wait_for(event.wait(), timeout=HITL_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                logger.warning(
                    f"HITL: Existing confirmation also timed out for chat_id={chat_id}"
                )
                return self._hitl_results.get(chat_id, False)
            return self._hitl_results.get(chat_id, False)

        event = asyncio.Event()
        self._hitl_events[chat_id] = event
        self._hitl_results[chat_id] = False
        self._hitl_active[chat_id] = True

        logger.info(f"HITL: Waiting for confirmation from chat_id={chat_id}")

        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⚠️ *Confirmation required*\n\n"
                f"```\n{prompt}\n```\n"
                f"Reply /yes to allow or /no to cancel.\n"
                f"_This request expires in {int(HITL_TIMEOUT_SECONDS)} seconds._"
            ),
            parse_mode="Markdown",
        )

        approved = False
        try:
            await asyncio.wait_for(event.wait(), timeout=HITL_TIMEOUT_SECONDS)
            logger.info(f"HITL: Confirmation received from chat_id={chat_id}, result={self._hitl_results.get(chat_id, False)}")
            approved = self._hitl_results.get(chat_id, False)
        except asyncio.TimeoutError:
            logger.warning(f"HITL: Confirmation timed out from chat_id={chat_id}")
            await context.bot.send_message(
                chat_id=chat_id,
                text="⏰ Confirmation timed out. Operation cancelled.",
            )
        finally:
            self._hitl_events.pop(chat_id, None)
            self._hitl_results.pop(chat_id, None)
            self._hitl_active.pop(chat_id, None)

        return approved

    # ── Command handlers ──────────────────────

    def _resolve_hitl(self, chat_id: int, approved: bool) -> bool:
        if not self._hitl_active.get(chat_id, False):
            return False
        self._hitl_results[chat_id] = approved
        self._hitl_events[chat_id].set()
        return True

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if self._is_duplicate_update(update):
            return
        if not await self._ensure_authorized(update):
            return
        user = update.effective_user
        await update.message.reply_text(
            f"👋 Hi {user.first_name}! I'm Prompt Panda, your local AI assistant.\n"
            f"Just send me a message to get started.\n\n"
            f"Commands:\n"
            f"/start — show this message\n"
            f"/reset — start a new conversation\n"
            f"/yes — confirm a pending operation\n"
            f"/no — cancel a pending operation"
        )

    async def cmd_reset(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if self._is_duplicate_update(update):
            return
        if not await self._ensure_authorized(update):
            return
        chat_id = update.effective_chat.id
        _agents.pop(chat_id, None)
        await update.message.reply_text("🐼 Conversation reset. Starting fresh!")

    async def cmd_yes(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if self._is_duplicate_update(update):
            return
        chat_id = update.effective_chat.id
        logger.info(f"cmd_yes called for chat_id={chat_id}, update_id={update.update_id}")
        if not self._resolve_hitl(chat_id, approved=True):
            logger.warning(f"cmd_yes: No active confirmation for chat_id={chat_id}")
            await update.message.reply_text("No pending confirmation to approve.")

    async def cmd_no(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if self._is_duplicate_update(update):
            return
        chat_id = update.effective_chat.id
        logger.info(f"cmd_no called for chat_id={chat_id}, update_id={update.update_id}")
        if not self._resolve_hitl(chat_id, approved=False):
            logger.warning(f"cmd_no: No active confirmation for chat_id={chat_id}")
            await update.message.reply_text("No pending confirmation to cancel.")

    # ── Message handler ───────────────────────

    async def handle_message(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if self._is_duplicate_update(update):
            return
        user = update.effective_user
        chat_id = update.effective_chat.id
        user_text = update.message.text or ""

        logger.info(f"handle_message from chat_id={chat_id}, user_id={user.id}, text: {user_text[:50]}")

        if not await self._ensure_authorized(update):
            return

        if self._hitl_active.get(chat_id, False):
            normalized = user_text.strip().lower()
            logger.info(
                f"HITL active on plain text message for chat_id={chat_id}, update_id={update.update_id}, text={normalized!r}"
            )
            if normalized in {"yes", "y"}:
                logger.info(f"Plain text approval received for chat_id={chat_id}")
                self._resolve_hitl(chat_id, approved=True)
                return
            if normalized in {"no", "n"}:
                logger.info(f"Plain text rejection received for chat_id={chat_id}")
                self._resolve_hitl(chat_id, approved=False)
                return

        if not user_text.strip():
            return

        lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
        async with lock:
            await self._process_message(chat_id, user_text, update, context)

    async def _process_message(
        self,
        chat_id: int,
        user_text: str,
        update: Update,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)

        agent = _get_or_create_agent(chat_id, self.config)
        loop = asyncio.get_running_loop()

        async def telegram_hitl(prompt: str) -> bool:
            return await self._request_hitl(chat_id, prompt, context)

        def sync_hitl(prompt: str) -> bool:
            logger.debug(f"sync_hitl called with prompt: {prompt[:50]}...")
            try:
                future = asyncio.run_coroutine_threadsafe(telegram_hitl(prompt), loop)
                result = future.result(timeout=HITL_TIMEOUT_SECONDS + 5)
                logger.debug(f"sync_hitl returning: {result}")
                return result
            except Exception as e:
                logger.exception(f"sync_hitl error: {type(e).__name__}: {e}")
                return False

        chunks: list[str] = []

        def stream_fn(text: str) -> None:
            chunks.append(text)

        agent.hitl = sync_hitl
        agent.stream = stream_fn

        reply = await loop.run_in_executor(None, agent.chat, user_text)

        if reply:
            for i in range(0, len(reply), MAX_TELEGRAM_MESSAGE_LENGTH):
                await update.message.reply_text(
                    reply[i:i + MAX_TELEGRAM_MESSAGE_LENGTH],
                    parse_mode="Markdown",
                )

    # ── Run the bot ───────────────────────────

    def run(self) -> None:
        """Start the bot using long-polling. Blocks until interrupted."""
        logger.info("Starting Prompt Panda Telegram bot (polling)...")

        app = (
            Application.builder()
            .token(self.config.telegram_token)
            .connect_timeout(20)
            .read_timeout(120)
            .get_updates_read_timeout(120)
            .concurrent_updates(True)
            .build()
        )

        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("reset", self.cmd_reset))
        app.add_handler(CommandHandler("yes", self.cmd_yes))
        app.add_handler(CommandHandler("no", self.cmd_no))
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message)
        )

        logger.info("Handlers registered: /start, /reset, /yes, /no, text messages")
        logger.info("Prompt Panda Telegram bot is running. Press Ctrl+C to stop.")
        app.run_polling(drop_pending_updates=True)
