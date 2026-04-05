"""Password generation and security audit commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from passage.core.config import load_config
from passage.core.database import (
    get_account,
    get_latest_password,
    list_accounts,
    upsert_password_record,
    update_reuse_groups,
)
from passage.core.crypto import hash_password_bcrypt, sha1_hex, fuzzy_hash
from passage.core.session import open_vault
from passage.core.strength import generate_password, score_password
from passage.utils.render import password_age_days

console = Console()

generate_app = typer.Typer(help="Generate strong passwords.")
audit_app = typer.Typer(help="Security audit.")


@generate_app.command("generate")
def cmd_generate(
    length: int = typer.Option(20, "--length", "-l", help="Password length"),
    no_symbols: bool = typer.Option(False, "--no-symbols", help="Exclude symbols"),
    count: int = typer.Option(1, "--count", "-n", help="How many to generate"),
    replace_id: Optional[str] = typer.Option(
        None, "--replace", help="Update password for account id(s), comma-separated"
    ),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Generate secure random passwords."""
    passwords = [generate_password(length=length, use_symbols=not no_symbols) for _ in range(count)]

    console.print()
    for i, pw in enumerate(passwords, 1):
        strength = score_password(pw)
        console.print(
            f"  [bold cyan]{pw}[/]  "
            f"[{strength.color}]({strength.label} {strength.score}/100)[/]"
        )

    if replace_id:
        ids = [int(x.strip()) for x in replace_id.split(",")]
        if len(ids) != len(passwords) and len(passwords) != 1:
            console.print("[red]Provide exactly 1 password or match count to number of ids.[/]")
            return

        with open_vault(db_path, config_path) as session:
            cfg = load_config(config_path)
            threshold: float = cfg["security"]["reuse_threshold"]
            for i, aid in enumerate(ids):
                pw = passwords[0] if len(passwords) == 1 else passwords[i]
                acct = get_account(session.conn, aid)
                if not acct:
                    console.print(f"[red]Account {aid} not found.[/]")
                    continue
                strength = score_password(pw)
                sha1 = sha1_hex(pw)
                upsert_password_record(
                    session.conn,
                    account_id=aid,
                    bcrypt_hash=hash_password_bcrypt(pw),
                    fuzzy_hash_val=fuzzy_hash(pw),
                    sha1_prefix=sha1[:5],
                    strength_score=strength.score,
                )
                console.print(f"[green]✓ Updated password for {acct['name']} (id={aid})[/]")
            update_reuse_groups(session.conn, threshold)
    console.print()


@audit_app.command("audit")
def cmd_audit(
    weak_only: bool = typer.Option(False, "--weak", help="Show only weak passwords"),
    min_strength: int = typer.Option(60, "--min-strength", help="Strength threshold (0-100)"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Audit account passwords for weaknesses."""
    with open_vault(db_path, config_path) as session:
        accounts = list_accounts(session.conn)
        if not accounts:
            console.print("[yellow]No accounts found.[/]")
            return

        issues: list[dict] = []
        for a in accounts:
            pw = get_latest_password(session.conn, a["id"])
            if not pw:
                issues.append({"id": a["id"], "name": a["name"], "issue": "No password recorded", "score": 0})
                continue
            score = pw["strength_score"]
            days = password_age_days(pw["last_changed"])
            acct_issues = []
            if score < min_strength:
                acct_issues.append(f"Weak password (score {score})")
            if days > 365:
                acct_issues.append(f"Very old ({days} days)")
            elif days > 180:
                acct_issues.append(f"Getting old ({days} days)")

            if acct_issues:
                issues.append({
                    "id": a["id"],
                    "name": a["name"],
                    "issue": "; ".join(acct_issues),
                    "score": score,
                    "age_days": days,
                })

        if not issues:
            console.print("[green]✅ All passwords look healthy![/]")
            return

        t = Table(title=f"⚠️  Audit Findings ({len(issues)})", box=box.ROUNDED, border_style="yellow")
        t.add_column("ID", style="dim", width=4)
        t.add_column("Account", style="bold")
        t.add_column("Issue", style="yellow")
        t.add_column("Strength")
        t.add_column("Age (days)")

        for item in issues:
            t.add_row(
                str(item["id"]),
                item["name"],
                item["issue"],
                str(item.get("score", "–")),
                str(item.get("age_days", "–")),
            )
        console.print(t)
        console.print(f"\n[cyan]Tip:[/] Run [bold]passage generate --replace {','.join(str(i['id']) for i in issues[:3])}[/] to fix.")
