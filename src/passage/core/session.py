"""Session helpers – prompt for master password and open vault."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

import typer
from rich.console import Console
from rich.prompt import Prompt

from passage.core.config import get_db_path, load_config
from passage.core.crypto import verify_master_password, setup_master_password
from passage.core.database import VaultSession

console = Console()

_MAX_ATTEMPTS = 3
_COOLDOWN_SECONDS = 5


def open_vault(
    db_path: Path | None = None,
    config_path: Path | None = None,
) -> VaultSession:
    """Prompt for master password (with retry) and return an open VaultSession."""
    cfg = load_config(config_path)
    iterations: int = cfg["security"]["pbkdf2_iterations"]
    resolved_db = db_path or get_db_path()

    is_new = not resolved_db.exists()

    if is_new:
        console.print("[bold cyan]🔐 Welcome to Passage! Set your master password.[/]")
        password = Prompt.ask("[bold]Master password[/]", password=True)
        confirm = Prompt.ask("[bold]Confirm master password[/]", password=True)
        if password != confirm:
            console.print("[red]Passwords do not match. Aborting.[/]")
            raise typer.Exit(1)
        session = VaultSession(password, resolved_db, iterations)
        session.open()
        console.print("[green]✓ Vault created.[/]")
        return session

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        password = Prompt.ask(
            f"[bold]Master password[/] (attempt {attempt}/{_MAX_ATTEMPTS})",
            password=True,
        )
        if verify_master_password(password, resolved_db, iterations):
            session = VaultSession(password, resolved_db, iterations)
            session.open()
            return session

        console.print(f"[red]Wrong password.[/]")
        if attempt < _MAX_ATTEMPTS:
            import time
            console.print(f"[yellow]Waiting {_COOLDOWN_SECONDS}s before next attempt…[/]")
            time.sleep(_COOLDOWN_SECONDS)

    console.print("[bold red]Too many failed attempts. Exiting.[/]")
    raise typer.Exit(1)
