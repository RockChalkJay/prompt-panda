#!/usr/bin/env python3
# main.py — entry point for Prompt Panda (CLI and Telegram)
import sys
import logging
import argparse
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.markdown import Markdown
from rich.panel import Panel

from prompt_panda import AgentCore, Config

logging.basicConfig(level=logging.INFO)
console = Console()


# ── CLI wiring ────────────────────────────────

def hitl(prompt: str) -> bool:
    console.print(Panel(
        prompt,
        title="[bold yellow]Confirmation required[/bold yellow]",
        border_style="yellow",
    ))
    return Confirm.ask("Allow this operation?", default=False)


def stream(text: str) -> None:
    console.print(Markdown(text))


def run_cli(config: Config) -> None:
    agent = AgentCore(config, hitl_fn=hitl, stream_fn=stream)

    console.print(Panel(
        f"[bold]Prompt Panda[/bold] — local AI assistant\n"
        f"Model: [cyan]{config.model}[/cyan]  |  "
        f"Sandbox: [cyan]{config.sandbox_root}[/cyan]  |  "
        f"Type [bold]exit[/bold] to quit",
        border_style="blue",
    ))

    while True:
        try:
            user_input = Prompt.ask("\n[bold blue]You[/bold blue]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        user_input = user_input.strip()
        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/dim]")
            break

        console.print("\n[bold green]Panda:[/bold green]")
        agent.chat(user_input)


# ── Telegram wiring ───────────────────────────

def run_telegram(config: Config) -> None:
    if not config.telegram_enabled:
        console.print(
            "[bold red]Error:[/bold red] Telegram is not enabled. "
            "Set [cyan]messaging.telegram.enabled: true[/cyan] in config.yaml."
        )
        sys.exit(1)

    if not config.telegram_token:
        console.print(
            "[bold red]Error:[/bold red] Telegram token is missing. "
            "Add your bot token to [cyan]messaging.telegram.token[/cyan] in config.yaml.\n"
            "Get a token from @BotFather on Telegram."
        )
        sys.exit(1)

    try:
        from prompt_panda.telegram_adapter import TelegramAdapter
    except ImportError:
        console.print(
            "[bold red]Error:[/bold red] Telegram dependencies not installed.\n"
            "Run: [cyan]pip install -e '.[telegram]'[/cyan]"
        )
        sys.exit(1)

    if not config.telegram_allowed_users:
        console.print(
            "[bold yellow]Warning:[/bold yellow] No allowed_users set in config.yaml.\n"
            "Anyone who finds your bot can use it. "
            "Consider adding your Telegram user ID to "
            "[cyan]messaging.telegram.allowed_users[/cyan].\n"
            "Get your user ID by messaging @userinfobot on Telegram.\n"
        )

    console.print(Panel(
        f"[bold]Prompt Panda[/bold] — Telegram bot\n"
        f"Model: [cyan]{config.model}[/cyan]  |  "
        f"Sandbox: [cyan]{config.sandbox_root}[/cyan]\n"
        f"Polling for messages... Press [bold]Ctrl+C[/bold] to stop.",
        border_style="blue",
    ))

    adapter = TelegramAdapter(config)
    adapter.run()


# ── Entry point ───────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="prompt-panda",
        description="Prompt Panda — secure local AI assistant",
    )
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="Run as a Telegram bot instead of CLI",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        metavar="PATH",
        help="Path to config.yaml (default: ./config.yaml)",
    )
    args = parser.parse_args()

    config = Config.load(args.config)

    if args.telegram:
        run_telegram(config)
    else:
        run_cli(config)


if __name__ == "__main__":
    main()
