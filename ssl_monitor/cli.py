"""Command-line interface for SSL Certificate Monitor."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from . import __version__
from .checker import check_domains
from .config import load_config
from .models import CertificateResult
from .notifier import send_email, send_slack
from .reporter import print_results, to_html, to_json

console = Console(stderr=True)
err = Console(stderr=True)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _targets_from_config(cfg_path: str) -> tuple[list[tuple], "object"]:
    """Return (targets_list, config) from a config file."""
    from .config import Config
    cfg = load_config(cfg_path)
    targets = [(d.host, d.port, d.warn_days, d.critical_days) for d in cfg.domains]
    return targets, cfg


def _targets_from_args(domains: tuple[str, ...], warn: int, crit: int) -> list[tuple]:
    """Parse raw domain strings (optionally with :port) into targets."""
    targets = []
    for raw in domains:
        if ":" in raw:
            host, port_str = raw.rsplit(":", 1)
            targets.append((host, int(port_str), warn, crit))
        else:
            targets.append((raw, 443, warn, crit))
    return targets


def _write_output(results: list[CertificateResult], fmt: str, output_file: Optional[str]) -> None:
    if fmt == "json":
        content = to_json(results)
        if output_file:
            Path(output_file).write_text(content)
            console.print(f"[green]JSON report saved to[/green] {output_file}")
        else:
            click.echo(content)
    elif fmt == "html":
        content = to_html(results)
        if output_file:
            Path(output_file).write_text(content)
            console.print(f"[green]HTML report saved to[/green] {output_file}")
        else:
            click.echo(content)
    else:
        print_results(results)
        if output_file:
            err.print(f"[yellow]Note: --output-file is ignored for 'table' format.[/yellow]")


def _exit_code(results: list[CertificateResult]) -> int:
    """Return 0 if all OK, 1 if any warnings, 2 if any critical/expired/error."""
    statuses = {r.status for r in results}
    if statuses & {"CRITICAL", "EXPIRED", "ERROR"}:
        return 2
    if "WARNING" in statuses:
        return 1
    return 0


# ------------------------------------------------------------------ #
# CLI
# ------------------------------------------------------------------ #


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="ssl-monitor")
def main() -> None:
    """SSL Certificate Monitor — check TLS certificate expiry across domains.

    \b
    Quick check:
        ssl-monitor check google.com github.com

    Scan from a config file with alerting:
        ssl-monitor scan --config config.yaml --notify

    Generate an HTML report:
        ssl-monitor check google.com --format html --output-file report.html
    """


@main.command()
@click.argument("domains", nargs=-1, required=True)
@click.option("--port", "-p", default=443, show_default=True, help="Default port (overridden by host:port syntax).")
@click.option("--timeout", "-t", default=10, show_default=True, help="Connection timeout in seconds.")
@click.option("--warn-days", "-w", default=30, show_default=True, help="Days before expiry to warn.")
@click.option("--critical-days", "-c", default=7, show_default=True, help="Days before expiry to mark critical.")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["table", "json", "html"], case_sensitive=False),
    default="table", show_default=True,
    help="Output format.",
)
@click.option("--output-file", "-o", default=None, metavar="FILE", help="Save report to FILE.")
@click.option("--fail-on-warning", is_flag=True, default=False, help="Exit code 1 on WARNING (in addition to CRITICAL).")
def check(
    domains: tuple[str, ...],
    port: int,
    timeout: int,
    warn_days: int,
    critical_days: int,
    fmt: str,
    output_file: Optional[str],
    fail_on_warning: bool,
) -> None:
    """Check one or more DOMAINS directly from the command line.

    \b
    Examples:
        ssl-monitor check google.com github.com
        ssl-monitor check example.com:8443 --warn-days 14
        ssl-monitor check google.com --format json --output-file certs.json
    """
    targets = _targets_from_args(domains, warn_days, critical_days)

    # Override default port if --port given and host has no explicit port
    targets = [
        (h, port if p == 443 and port != 443 else p, w, c)
        for h, p, w, c in targets
    ]

    results = asyncio.run(_run_checks(targets, timeout))
    _write_output(results, fmt, output_file)
    code = _exit_code(results)
    sys.exit(0 if (code == 1 and not fail_on_warning) else code)


@main.command()
@click.option("--config", "-C", "cfg_path", required=True, metavar="FILE", help="Path to YAML config file.")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["table", "json", "html"], case_sensitive=False),
    default="table", show_default=True,
)
@click.option("--output-file", "-o", default=None, metavar="FILE", help="Save report to FILE.")
@click.option("--notify", "-n", is_flag=True, default=False, help="Send configured Slack/email notifications.")
@click.option("--fail-on-warning", is_flag=True, default=False, help="Exit code 1 on WARNING.")
def scan(
    cfg_path: str,
    fmt: str,
    output_file: Optional[str],
    notify: bool,
    fail_on_warning: bool,
) -> None:
    """Scan all domains from a YAML configuration file.

    \b
    Example:
        ssl-monitor scan --config config.yaml
        ssl-monitor scan --config config.yaml --notify --format html -o report.html
    """
    try:
        targets, cfg = _targets_from_config(cfg_path)
    except FileNotFoundError as exc:
        err.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        err.print(f"[red]Config error:[/red] {exc}")
        sys.exit(1)

    results = asyncio.run(_run_checks(targets, cfg.timeout))
    _write_output(results, fmt, output_file)

    if notify:
        asyncio.run(_send_notifications(results, cfg))

    code = _exit_code(results)
    sys.exit(0 if (code == 1 and not fail_on_warning) else code)


# ------------------------------------------------------------------ #
# Internal async runners
# ------------------------------------------------------------------ #


async def _run_checks(targets: list[tuple], timeout: int) -> list[CertificateResult]:
    with console.status(f"[bold blue]Checking {len(targets)} domain(s)…[/bold blue]"):
        return await check_domains(targets, timeout=timeout)


async def _send_notifications(results: list[CertificateResult], cfg) -> None:
    if cfg.slack:
        try:
            await send_slack(results, cfg.slack)
            console.print("[green]Slack notification sent.[/green]")
        except Exception as exc:  # noqa: BLE001
            err.print(f"[red]Slack error:[/red] {exc}")

    if cfg.email:
        try:
            send_email(results, cfg.email)
            console.print("[green]Email notification sent.[/green]")
        except Exception as exc:  # noqa: BLE001
            err.print(f"[red]Email error:[/red] {exc}")
