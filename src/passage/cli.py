"""Passage CLI – main entry point."""

from __future__ import annotations

import logging

import typer

try:
    from rich.console import Console
    console = Console()
except ImportError:
    class _C:
        def print(self, *a, **k): print(*a)
    console = _C()

from passage import __version__
from passage.commands.account import app as account_app
from passage.commands.check import app as check_app
from passage.commands.report import app as report_app
from passage.commands.tools import generate_app, audit_app
from passage.commands.config_cmd import config_app

app = typer.Typer(
    name="passage",
    help="Passage - Password Decay Tracker",
    add_completion=False,
    no_args_is_help=True,
)

app.add_typer(account_app,  name="account")
app.add_typer(check_app,    name="check")
app.add_typer(report_app,   name="report")
app.add_typer(generate_app, name="generate")
app.add_typer(audit_app,    name="audit")
app.add_typer(config_app,   name="config")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging."),
) -> None:
    """Passage - track password age, detect reuse, check breaches."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    if version:
        console.print(f"Passage {__version__}")
        raise typer.Exit()


if __name__ == "__main__":
    app()