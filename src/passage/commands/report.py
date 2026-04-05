"""Report generation command."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from passage.core.config import load_config
from passage.core.database import (
    find_reuse_groups,
    get_all_passwords,
    get_breach_check,
    get_latest_password,
    list_accounts,
)
from passage.core.session import open_vault
from passage.utils.render import health_score, password_age_days, risk_level

console = Console()
app = typer.Typer(help="Generate reports.")


def _collect_report_data(conn) -> list[dict]:
    accounts = list_accounts(conn)
    groups = find_reuse_groups(conn)
    reuse_map: dict[int, list[str]] = {}
    for g in groups:
        names = [m["name"] for m in g["accounts"]]
        for m in g["accounts"]:
            reuse_map[m["id"]] = [n for n in names if n != m["name"]]

    rows = []
    for a in accounts:
        pw = get_latest_password(conn, a["id"])
        breach = get_breach_check(conn, a["id"])
        days = password_age_days(pw["last_changed"]) if pw else 0
        rows.append({
            "id": a["id"],
            "name": a["name"],
            "url": a["url"] or "",
            "username": a["username"] or "",
            "category": a["category"],
            "age_days": days,
            "risk": risk_level(days),
            "strength_score": pw["strength_score"] if pw else 0,
            "breach_count": breach["breach_count"] if breach else 0,
            "last_hibp_check": breach["last_check_date"][:10] if breach else "never",
            "reused_with": ", ".join(reuse_map.get(a["id"], [])),
        })
    return rows


@app.command("report")
def cmd_report(
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|json|csv"),
    export: Optional[Path] = typer.Option(None, "--export", "-e", help="Export to file"),
    summary: bool = typer.Option(False, "--summary", help="Print one-line summary"),
    db_path: Optional[Path] = typer.Option(None, "--db-path"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Generate password health report."""
    with open_vault(db_path, config_path) as session:
        rows = _collect_report_data(session.conn)

        if not rows:
            console.print("[yellow]No data yet.[/]")
            return

        if summary:
            total = len(rows)
            breached = sum(1 for r in rows if r["breach_count"] > 0)
            old = sum(1 for r in rows if r["age_days"] > 180)
            reused = sum(1 for r in rows if r["reused_with"])
            score, grade = health_score(rows)
            console.print(
                f"[bold]You have {total} accounts.[/] "
                f"[red]{breached} breached.[/] "
                f"[orange3]{old} passwords >180d old.[/] "
                f"[yellow]{reused} reused.[/] "
                f"Health: [bold]{score}/100 ({grade})[/]"
            )
            return

        if fmt == "json":
            output = json.dumps(rows, indent=2)
            if export:
                export.write_text(output)
                console.print(f"[green]✓ Exported JSON to {export}[/]")
            else:
                print(output)

        elif fmt == "csv":
            if export:
                with open(export, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                console.print(f"[green]✓ Exported CSV to {export}[/]")
            else:
                writer = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

        elif fmt == "html" or (export and str(export).endswith(".html")):
            _export_html(rows, export or Path("passage_report.html"))

        else:  # table (default)
            _render_table(rows)
            if export:
                # Export as CSV when exporting table format
                with open(export, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                console.print(f"[green]✓ Also exported to {export}[/]")


def _render_table(rows: list[dict]) -> None:
    t = Table(title="📊 Password Health Report", box=box.ROUNDED, border_style="cyan")
    t.add_column("ID", style="dim", width=4)
    t.add_column("Name", style="bold")
    t.add_column("Category", style="magenta")
    t.add_column("Age (days)")
    t.add_column("Risk")
    t.add_column("Strength")
    t.add_column("Breached")
    t.add_column("Reused With")

    risk_colors = {"GREEN": "green", "YELLOW": "yellow", "ORANGE": "orange3", "RED": "red"}
    for r in rows:
        rc = risk_colors.get(r["risk"], "white")
        t.add_row(
            str(r["id"]),
            r["name"],
            r["category"],
            f"[{rc}]{r['age_days']}[/]",
            f"[{rc}]{r['risk']}[/]",
            str(r["strength_score"]),
            f"[red]{r['breach_count']}[/]" if r["breach_count"] else "[green]0[/]",
            r["reused_with"] or "–",
        )
    console.print(t)


def _export_html(rows: list[dict], path: Path) -> None:
    score, grade = health_score(rows)
    total = len(rows)
    breached = sum(1 for r in rows if r["breach_count"] > 0)
    old = sum(1 for r in rows if r["age_days"] > 180)
    reused = sum(1 for r in rows if r["reused_with"])

    def risk_class(risk: str) -> str:
        return {"GREEN": "healthy", "YELLOW": "warning", "ORANGE": "danger", "RED": "critical"}.get(risk, "")

    rows_html = "\n".join(
        f"""<tr class="{risk_class(r['risk'])}">
  <td>{r['id']}</td><td>{r['name']}</td><td>{r['category']}</td>
  <td>{r['age_days']}</td><td>{r['risk']}</td><td>{r['strength_score']}</td>
  <td>{'⚠ ' + str(r['breach_count']) if r['breach_count'] else '✓'}</td>
  <td>{r['reused_with'] or '–'}</td>
</tr>"""
        for r in rows
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Passage Health Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; background:#0d1117; color:#c9d1d9; padding:2rem; }}
  h1 {{ color:#58a6ff; }} h2 {{ color:#8b949e; }}
  .summary {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1rem 1.5rem; min-width:120px; }}
  .card .num {{ font-size:2rem; font-weight:bold; }} .card .label {{ color:#8b949e; font-size:.85rem; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ background:#161b22; padding:.6rem 1rem; text-align:left; color:#8b949e; }}
  td {{ padding:.5rem 1rem; border-bottom:1px solid #21262d; }}
  tr.healthy td:nth-child(5) {{ color:#3fb950; }}
  tr.warning td:nth-child(5) {{ color:#d29922; }}
  tr.danger td:nth-child(5) {{ color:#e3b341; }}
  tr.critical {{ background:#2d1a1a; }} tr.critical td:nth-child(5) {{ color:#f85149; }}
</style>
</head>
<body>
<h1>🔐 Passage – Password Health Report</h1>
<div class="summary">
  <div class="card"><div class="num">{total}</div><div class="label">Accounts</div></div>
  <div class="card"><div class="num" style="color:#f85149">{breached}</div><div class="label">Breached</div></div>
  <div class="card"><div class="num" style="color:#d29922">{reused}</div><div class="label">Reused</div></div>
  <div class="card"><div class="num" style="color:#e3b341">{old}</div><div class="label">&gt;180 days</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{score}/100</div><div class="label">Health (Grade {grade})</div></div>
</div>
<table>
<thead><tr>
  <th>ID</th><th>Name</th><th>Category</th><th>Age (days)</th>
  <th>Risk</th><th>Strength</th><th>Breached</th><th>Reused With</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
</body>
</html>"""

    path.write_text(html)
    console.print(f"[green]✓ HTML report saved to {path}[/]")
