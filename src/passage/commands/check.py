"""Password health check commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from passage.core.config import load_config
from passage.core.database import (
    find_reuse_groups,
    get_all_passwords,
    get_breach_check,
    get_latest_password,
    list_accounts,
    upsert_breach_check,
)
from passage.core.hibp import run_batch_check, should_refresh_breach_check
from passage.core.session import open_vault
from passage.utils.render import (
    age_color,
    console,
    health_score,
    password_age_days,
    render_check_results,
)

app = typer.Typer(help="Check password health.")


def _build_account_summary(conn, account, breach_row, reuse_map) -> dict:
    """Build a flat summary dict for a single account."""
    pw = get_latest_password(conn, account["id"])
    days = password_age_days(pw["last_changed"]) if pw else 0
    breach_count = breach_row["breach_count"] if breach_row else 0
    breach_names: list[str] = []
    if breach_row and breach_row["breach_names"]:
        try:
            breach_names = json.loads(breach_row["breach_names"])
        except (json.JSONDecodeError, TypeError):
            breach_names = []

    return {
        "id": account["id"],
        "name": account["name"],
        "category": account["category"],
        "age_days": days,
        "breach_count": breach_count,
        "breach_names": breach_names,
        "strength_score": pw["strength_score"] if pw else 0,
        "reused": bool(reuse_map.get(account["id"])),
    }


def _run_hibp_checks(conn, accounts, cfg) -> None:
    """Query HIBP for all accounts that need a refresh."""
    cache_days: int = cfg["hibp"]["cache_days"]
    timeout: int = cfg["hibp"]["timeout_seconds"]

    items_to_check = []
    for a in accounts:
        pw = get_latest_password(conn, a["id"])
        if not pw:
            continue
        breach_row = get_breach_check(conn, a["id"])
        last_check = breach_row["last_check_date"] if breach_row else None
        if should_refresh_breach_check(last_check, cache_days):
            items_to_check.append({
                "account_id": a["id"],
                "sha1_prefix": pw["sha1_prefix"],
                "sha1_full": pw["sha1_prefix"] + "X" * 35,  # placeholder suffix
            })

    if not items_to_check:
        return

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
    ) as progress:
        progress.add_task(
            f"Checking {len(items_to_check)} accounts against HIBP…", total=None
        )
        results = run_batch_check(items_to_check, timeout=timeout)

    for item in items_to_check:
        aid = item["account_id"]
        count = results.get(aid, -1)
        if count >= 0:
            upsert_breach_check(conn, aid, count, json.dumps([]))


@app.command("check")
def cmd_check(
    all_accounts: bool = typer.Option(False, "--all", "-a", help="Check all accounts"),
    account_id: Optional[int] = typer.Option(None, "--id", help="Check single account"),
    reused_only: bool = typer.Option(False, "--reused", help="Show only reused passwords"),
    no_hibp: bool = typer.Option(False, "--no-hibp", help="Skip HIBP checks"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Check password health (age, breaches, reuse)."""
    with open_vault(db_path, config_path) as session:
        conn = session.conn
        cfg = load_config(config_path)

        if account_id:
            accounts = []
            from passage.core.database import get_account
            a = get_account(conn, account_id)
            if not a:
                console.print(f"[red]Account {account_id} not found.[/]")
                raise typer.Exit(1)
            accounts = [a]
        else:
            accounts = list_accounts(conn)

        if not accounts:
            console.print("[yellow]No accounts found. Add some with [cyan]passage add[/].[/]")
            return

        # HIBP check
        if not no_hibp and cfg["hibp"]["enabled"]:
            _run_hibp_checks(conn, accounts, cfg)

        # Build reuse map {account_id: [other_account_names]}
        groups = find_reuse_groups(conn)
        reuse_map: dict[int, list[str]] = {}
        for g in groups:
            names = [m["name"] for m in g["accounts"]]
            for m in g["accounts"]:
                others = [n for n in names if n != m["name"]]
                if others:
                    reuse_map[m["id"]] = others

        # Build summaries
        summaries = []
        for a in accounts:
            breach_row = get_breach_check(conn, a["id"])
            s = _build_account_summary(conn, a, breach_row, reuse_map)
            summaries.append(s)

        if reused_only:
            summaries = [s for s in summaries if s["reused"]]
            if not summaries:
                console.print("[green]No reused passwords detected.[/]")
                return

        # Bucket by age
        critical, danger, warning, healthy = [], [], [], []
        for s in summaries:
            d = s["age_days"]
            if s["breach_count"] > 0 or d >= 365:
                critical.append(s)
            elif d >= 180:
                danger.append(s)
            elif d >= 90:
                warning.append(s)
            else:
                healthy.append(s)

        score, grade = health_score(summaries)
        render_check_results(critical, warning, danger, healthy, reuse_map, score, grade)