"""Rich terminal rendering helpers for Passage.

Falls back to plain print() if Rich is not installed.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    # Minimal shim so imports don't break
    class _FakeConsole:
        def print(self, *args, **kw): print(*args)
        def rule(self, *args, **kw): print("─" * 60)
    console = _FakeConsole()  # type: ignore


def age_color(days: int) -> str:
    if days < 90:  return "green"
    if days < 180: return "yellow"
    if days < 365: return "orange3"
    return "red"


def age_label(days: int) -> str:
    if days < 90:  return "✅ HEALTHY"
    if days < 180: return "⚠️  WARNING"
    if days < 365: return "🔶 DANGER"
    return "🚨 CRITICAL"


def risk_level(days: int) -> str:
    if days < 90:  return "GREEN"
    if days < 180: return "YELLOW"
    if days < 365: return "ORANGE"
    return "RED"


def password_age_days(last_changed: str) -> int:
    try:
        d = date.fromisoformat(last_changed)
        return (date.today() - d).days
    except (ValueError, TypeError):
        return 0


def health_score(accounts: list[dict]) -> tuple[int, str]:
    """Compute overall health score 0-100 and letter grade."""
    if not accounts:
        return 100, "A"
    total = len(accounts)
    penalty = 0
    for a in accounts:
        days = a.get("age_days", 0)
        if a.get("breached"):
            penalty += 40
        elif a.get("reused"):
            penalty += 20
        elif days > 365:
            penalty += 30
        elif days > 180:
            penalty += 15
        elif days > 90:
            penalty += 5
    raw = max(0, 100 - int(penalty / total))
    if raw >= 90: grade = "A"
    elif raw >= 80: grade = "B"
    elif raw >= 65: grade = "C"
    elif raw >= 50: grade = "D"
    else:           grade = "F"
    return raw, grade


def render_check_results(
    critical: list[dict],
    warning: list[dict],
    danger: list[dict],
    healthy: list[dict],
    reuse_map: dict[int, list[str]],
    score: int,
    grade: str,
    table_style: str = "rounded",
) -> None:
    if not _RICH:
        _plain_render(critical, warning, danger, healthy, reuse_map, score, grade)
        return

    console.print()
    console.rule("[bold cyan]🔐 PASSAGE – Password Decay Tracker[/]")
    console.print()

    def _render_group(title: str, accounts: list[dict], border_color: str) -> None:
        if not accounts:
            return
        t = Table(
            title=title,
            box=getattr(box, table_style.upper(), box.ROUNDED),
            border_style=border_color,
            show_header=False,
            expand=True,
        )
        t.add_column("info", no_wrap=False)
        for a in accounts:
            days = a.get("age_days", 0)
            breach_info = ""
            if a.get("breach_count", 0) > 0:
                breach_info = f" [red]– BREACHED ({a.get('breach_count')} pwns)[/]"
            reused_with = reuse_map.get(a["id"], [])
            reuse_info = f"\n   [dim]↳ Reused on: {', '.join(reused_with)}[/]" if reused_with else ""
            strength = a.get("strength_score", 0)
            strength_badge = " [green]✓ strong[/]" if strength >= 80 else ""
            line = (
                f"[bold]{a['name']}[/] [{a.get('category','other')}] "
                f"– [bold]{days}[/] days old{breach_info}{strength_badge}{reuse_info}"
            )
            t.add_row(line)
        console.print(t)
        console.print()

    _render_group(f"🚨 CRITICAL ({len(critical)})", critical, "red")
    _render_group(f"🔶 DANGER ({len(danger)})", danger, "orange3")
    _render_group(f"⚠️  WARNING ({len(warning)})", warning, "yellow")

    if healthy:
        console.print(Panel(
            f"[green]{len(healthy)} accounts are healthy ✅[/]",
            title="✅ HEALTHY", border_style="green",
        ))
        console.print()

    breached  = sum(1 for a in critical + warning + danger if a.get("breach_count", 0) > 0)
    reused_c  = sum(1 for a in critical + warning + danger + healthy if reuse_map.get(a["id"]))
    old_count = sum(1 for a in critical + warning + danger if a.get("age_days", 0) > 180)
    total     = len(critical) + len(warning) + len(danger) + len(healthy)
    gc = "green" if grade in ("A","B") else "yellow" if grade == "C" else "red"

    summary = (
        f"[bold]Total:[/] {total} accounts\n"
        f"[red]Breached:[/] {breached}\n"
        f"[yellow]Reused:[/] {reused_c}\n"
        f"[orange3]>180 days old:[/] {old_count}\n"
        f"[bold]Health:[/] [{gc}]{score}/100 (Grade {grade})[/]"
    )
    console.print(Panel(summary, title="📊 SUMMARY", border_style="cyan"))

    recs: list[str] = []
    if breached:   recs.append(f"[red]Change {breached} breached password(s) immediately![/]")
    if reused_c:   recs.append("Use unique passwords (try [cyan]passage generate[/]).")
    if old_count:  recs.append(f"Rotate {old_count} password(s) older than 180 days.")
    if not recs:   recs.append("[green]Great job! Keep your passwords fresh.[/]")
    rec_text = "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs))
    console.print(Panel(rec_text, title="🔧 RECOMMENDATIONS", border_style="blue"))
    console.print()


def _plain_render(critical, warning, danger, healthy, reuse_map, score, grade):
    print("\n🔐 PASSAGE – Password Decay Tracker\n")
    for bucket, label in [(critical,"🚨 CRITICAL"),(danger,"🔶 DANGER"),(warning,"⚠ WARNING")]:
        if bucket:
            print(f"{label} ({len(bucket)}):")
            for a in bucket:
                print(f"  ● {a['name']} – {a['age_days']}d old"
                      + (f" BREACHED({a['breach_count']})" if a.get("breach_count") else ""))
    print(f"\n✅ HEALTHY: {len(healthy)}")
    print(f"📊 Health: {score}/100 (Grade {grade})\n")
