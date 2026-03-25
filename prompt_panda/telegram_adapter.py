# telegram_adapter.py — Telegram bot adapter for Prompt Panda
#
# Uses long-polling (not webhooks) — no open ports, no inbound connections.
# The bot connects outbound to Telegram's servers and waits for messages.
#
# Setup:
#   1. Message @BotFather on Telegram to create a bot and get a token
#   2. Set messaging.telegram.enabled: true in config.yaml
#   3. Paste your token into messaging.telegram.token
#   4. Get your Telegram user ID from @userinfobot and add it to
#      messaging.telegram.allowed_users for security
#   5. pip install -e ".[telegram]"
#   6. Run: prompt-panda --telegram

from __future__ import annotations

import asyncio
import logging
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

# Per-chat AgentCore instances — each chat gets its own conversation history
# and session ID, so conversations stay isolated.
_agents: dict[int, "AgentCore"] = {}


def _get_or_create_agent(chat_id: int, config: "Config") -> "AgentCore":
    """Return existing agent for this chat, or create a fresh one."""
    if chat_id not in _agents:
        from .agent_core import AgentCore

        # HITL over Telegram: send a confirmation message and wait for reply.
        # This is wired up per-agent below in TelegramAdapter.
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

    # ── Auth check ────────────────────────────

    def _is_allowed(self, user_id: int) -> bool:
        """
        If allowed_users is set, only those IDs may use the bot.
        If empty, anyone who finds the bot can use it — fine for private bots,
        risky if the bot token leaks. Set allowed_users in config.yaml.
        """
        if not self.config.telegram_allowed_users:
            return True
        return user_id in self.config.telegram_allowed_users

    # ── HITL over Telegram ────────────────────

    async def _request_hitl(
        self,
        chat_id: int,
        prompt: str,
        context: ContextTypes.DEFAULT_TYPE,
    ) -> bool:
        """
        Send the HITL confirmation request to the user and wait up to 60s
        for a /yes or /no reply. Returns True if approved, False otherwise.
        """
        event = asyncio.Event()
        self._hitl_events[chat_id] = event
        self._hitl_results[chat_id] = False

        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⚠️ *Confirmation required*\n\n"
                f"```\n{prompt}\n```\n"
                f"Reply /yes to allow or /no to cancel.\n"
                f"_This request expires in 60 seconds._"
            ),
            parse_mode="Markdown",
        )

        try:
            await asyncio.wait_for(event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            await context.bot.send_message(
                chat_id=chat_id,
                text="⏰ Confirmation timed out. Operation cancelled.",
            )
            return False
        finally:
            self._hitl_events.pop(chat_id, None)

        return self._hitl_results.pop(chat_id, False)

    # ── Command handlers ──────────────────────

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        user = update.effective_user
        if not self._is_allowed(user.id):
            await update.message.reply_text("Sorry, you are not authorised to use this bot.")
            logger.warning(f"Unauthorised access attempt from user_id={user.id}")
            return
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
        user = update.effective_user
        if not self._is_allowed(user.id):
            return
        chat_id = update.effective_chat.id
        # Drop the existing agent — next message creates a fresh one
        _agents.pop(chat_id, None)
        await update.message.reply_text("🐼 Conversation reset. Starting fresh!")

    async def cmd_yes(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        chat_id = update.effective_chat.id
        if chat_id in self._hitl_events:
            self._hitl_results[chat_id] = True
            self._hitl_events[chat_id].set()
        else:
            await update.message.reply_text("No pending confirmation to approve.")

    async def cmd_no(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        chat_id = update.effective_chat.id
        if chat_id in self._hitl_events:
            self._hitl_results[chat_id] = False
            self._hitl_events[chat_id].set()
        else:
            await update.message.reply_text("No pending confirmation to cancel.")

    # ── Message handler ───────────────────────

    async def handle_message(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        user    = update.effective_user
        chat_id = update.effective_chat.id

        if not self._is_allowed(user.id):
            await update.message.reply_text("Sorry, you are not authorised to use this bot.")
            return

        user_text = update.message.text or ""
        if not user_text.strip():
            return

        # Show typing indicator while the agent is thinking
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)

        # Get or create an agent scoped to this chat
        agent = _get_or_create_agent(chat_id, self.config)

        # Wire up HITL and streaming to Telegram for this specific chat + context
        async def telegram_hitl(prompt: str) -> bool:
            return await self._request_hitl(chat_id, prompt, context)

        # AgentCore.hitl_fn is synchronous — wrap async HITL in a sync call
        # by running it in the event loop that's already running
        def sync_hitl(prompt: str) -> bool:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(telegram_hitl(prompt))

        # Collect streamed text chunks and send as one message
        chunks: list[str] = []

        def stream_fn(text: str) -> None:
            chunks.append(text)

        agent.hitl    = sync_hitl
        agent.stream  = stream_fn

        # Run the blocking agent.chat() in a thread so we don't block the event loop
        reply = await asyncio.get_event_loop().run_in_executor(
            None, agent.chat, user_text
        )

        # Send reply — split into chunks if over Telegram's 4096 char limit
        if reply:
            for i in range(0, len(reply), 4000):
                await update.message.reply_text(
                    reply[i:i + 4000],
                    parse_mode="Markdown",
                )

    # ── Run the bot ───────────────────────────

    def run(self) -> None:
        """Start the bot using long-polling. Blocks until interrupted."""
        logger.info("Starting Prompt Panda Telegram bot (polling)...")

        app = (
            Application.builder()
            .token(self.config.telegram_token)
            .build()
        )

        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("reset", self.cmd_reset))
        app.add_handler(CommandHandler("yes",   self.cmd_yes))
        app.add_handler(CommandHandler("no",    self.cmd_no))
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message)
        )

        logger.info("Prompt Panda Telegram bot is running. Press Ctrl+C to stop.")
        app.run_polling(drop_pending_updates=True)
