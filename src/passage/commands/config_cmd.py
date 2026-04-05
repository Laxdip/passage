"""Config management and reminder/cron helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.syntax import Syntax

from passage.core.config import get_passage_dir, load_config, save_config

console = Console()
config_app = typer.Typer(help="Manage configuration.")


@config_app.command("config")
def cmd_config(
    show: bool = typer.Option(False, "--show", help="Show current config"),
    reset: bool = typer.Option(False, "--reset", help="Reset config to defaults"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Show or reset Passage configuration."""
    cfg_path = config_path or (get_passage_dir() / "config.yaml")

    if reset:
        from passage.core.config import DEFAULT_CONFIG
        save_config(DEFAULT_CONFIG, cfg_path)
        console.print("[green]✓ Config reset to defaults.[/]")
        return

    cfg = load_config(config_path)
    raw = yaml.dump(cfg, default_flow_style=False)
    console.print(Syntax(raw, "yaml", theme="monokai", line_numbers=False))
    console.print(f"[dim]Config file: {cfg_path}[/]")


@config_app.command("remind")
def cmd_remind(
    schedule: str = typer.Option("0 9 * * *", "--schedule", help="Cron schedule expression"),
) -> None:
    """Print a cron line for daily decay checks."""
    import shutil
    passage_bin = shutil.which("passage") or "passage"
    cron_line = f'{schedule} {passage_bin} check --all --no-hibp >> ~/passage_check.log 2>&1'
    console.print("[bold]Add this line to your crontab ([cyan]crontab -e[/]):[/]")
    console.print(f"\n  [green]{cron_line}[/]\n")
    console.print("[dim]Run [cyan]crontab -e[/] and paste the line above.[/]")
