"""Account management commands."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

from passage.core.crypto import (
    hash_password_bcrypt,
    sha1_hex,
    fuzzy_hash,
)
from passage.core.database import (
    add_account,
    edit_account,
    get_account,
    list_accounts,
    remove_account,
    upsert_password_record,
    update_reuse_groups,
)
from passage.core.strength import score_password
from passage.core.session import open_vault
from passage.core.config import load_config

console = Console()

app = typer.Typer(help="Manage accounts.")


@app.command("add")
def cmd_add(
    name: str = typer.Option(..., "--name", "-n", help="Account name"),
    url: Optional[str] = typer.Option(None, "--url", help="Website URL"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Username/email"),
    category: str = typer.Option("other", "--category", "-c",
                                  help="Category: social/work/finance/email/dev/other"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Add a new account and record its current password."""
    with open_vault(db_path, config_path) as session:
        cfg = load_config(config_path)
        threshold: float = cfg["security"]["reuse_threshold"]

        password = Prompt.ask("[bold]Enter current password for this account[/]", password=True)
        strength = score_password(password)

        account_id = add_account(session.conn, name, url, username, category)

        sha1 = sha1_hex(password)
        upsert_password_record(
            session.conn,
            account_id=account_id,
            bcrypt_hash=hash_password_bcrypt(password),
            fuzzy_hash_val=fuzzy_hash(password),
            sha1_prefix=sha1[:5],
            strength_score=strength.score,
        )
        update_reuse_groups(session.conn, threshold)

        console.print(
            f"[green]✓ Added[/] [bold]{name}[/] (id={account_id}) "
            f"– Password strength: [{strength.color}]{strength.label} ({strength.score}/100)[/]"
        )
        if strength.warnings:
            for w in strength.warnings:
                console.print(f"  [yellow]⚠  {w}[/]")


@app.command("list")
def cmd_list(
    category: Optional[str] = typer.Option(None, "--category", "-c"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """List all accounts."""
    with open_vault(db_path, config_path) as session:
        accounts = list_accounts(session.conn, category)
        if not accounts:
            console.print("[yellow]No accounts found.[/]")
            return

        t = Table(title="📋 Accounts", box=box.ROUNDED, border_style="cyan")
        t.add_column("ID", style="dim", width=4)
        t.add_column("Name", style="bold")
        t.add_column("URL")
        t.add_column("Username")
        t.add_column("Category", style="magenta")
        t.add_column("Added")

        for a in accounts:
            t.add_row(
                str(a["id"]),
                a["name"],
                a["url"] or "–",
                a["username"] or "–",
                a["category"],
                a["created_at"][:10],
            )
        console.print(t)


@app.command("edit")
def cmd_edit(
    account_id: int = typer.Option(..., "--id"),
    name: Optional[str] = typer.Option(None, "--name"),
    url: Optional[str] = typer.Option(None, "--url"),
    username: Optional[str] = typer.Option(None, "--username"),
    category: Optional[str] = typer.Option(None, "--category"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Edit an existing account."""
    with open_vault(db_path, config_path) as session:
        ok = edit_account(session.conn, account_id,
                          name=name, url=url, username=username, category=category)
        if ok:
            console.print(f"[green]✓ Account {account_id} updated.[/]")
        else:
            console.print(f"[red]No changes made (invalid id or no fields provided).[/]")


@app.command("remove")
def cmd_remove(
    account_id: int = typer.Option(..., "--id"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Remove an account."""
    with open_vault(db_path, config_path) as session:
        acct = get_account(session.conn, account_id)
        if not acct:
            console.print(f"[red]Account {account_id} not found.[/]")
            raise typer.Exit(1)
        if not yes:
            ok = Confirm.ask(f"Remove [bold]{acct['name']}[/] (id={account_id})?")
            if not ok:
                console.print("Aborted.")
                return
        remove_account(session.conn, account_id)
        console.print(f"[green]✓ Removed {acct['name']}.[/]")
