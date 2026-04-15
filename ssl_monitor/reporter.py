"""Output reporters: rich console table, JSON, and self-contained HTML."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from jinja2 import Environment, BaseLoader
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from .models import CertificateResult

console = Console()


# ------------------------------------------------------------------ #
# Console (Rich)
# ------------------------------------------------------------------ #


def print_results(results: list[CertificateResult], title: str = "SSL Certificate Report") -> None:
    """Print a colour-coded Rich table to stdout."""
    checked_at = results[0].checked_at.strftime("%Y-%m-%d %H:%M UTC") if results else ""

    table = Table(
        title=f"[bold]{title}[/bold]  [dim]{checked_at}[/dim]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on dark_blue",
        border_style="bright_black",
        expand=False,
    )

    table.add_column("Domain", style="bold", min_width=22)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Expires", justify="center", min_width=12)
    table.add_column("Days Left", justify="right", min_width=9)
    table.add_column("Issuer", min_width=20)
    table.add_column("Subject Alt Names", min_width=24)

    for r in sorted(results, key=lambda x: (["OK","WARNING","CRITICAL","EXPIRED","ERROR"].index(x.status), x.domain)):
        status_text = Text(f" {r.status_icon} {r.status} ", style=f"bold {r.status_color}")

        if r.expiry_date:
            expiry_str = r.expiry_date.strftime("%Y-%m-%d")
        else:
            expiry_str = "—"

        if r.days_remaining is not None:
            days_text = Text(str(r.days_remaining), style=r.status_color)
        else:
            days_text = Text("—", style="dim")

        issuer = r.issued_by or (Text(r.error or "unknown", style="dim italic") if not r.issued_by else "")
        san = ", ".join(r.subject_alt_names[:3])
        if len(r.subject_alt_names) > 3:
            san += f" [dim]+{len(r.subject_alt_names) - 3} more[/dim]"

        table.add_row(r.host_label, status_text, expiry_str, days_text, issuer or "—", san or "—")

    console.print()
    console.print(table)
    _print_summary(results)


def _print_summary(results: list[CertificateResult]) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    parts = []
    color_map = {"OK": "green", "WARNING": "yellow", "CRITICAL": "red", "EXPIRED": "bright_red", "ERROR": "magenta"}
    for status in ["OK", "WARNING", "CRITICAL", "EXPIRED", "ERROR"]:
        if n := counts.get(status):
            parts.append(f"[{color_map[status]}]{n} {status}[/{color_map[status]}]")

    console.print(f"\n  Summary: {' · '.join(parts)}\n")


# ------------------------------------------------------------------ #
# JSON
# ------------------------------------------------------------------ #


def to_json(results: list[CertificateResult], indent: int = 2) -> str:
    """Serialise results to a JSON string."""
    def _serialise(r: CertificateResult) -> dict:
        return {
            "domain": r.domain,
            "port": r.port,
            "status": r.status,
            "is_valid": r.is_valid,
            "days_remaining": r.days_remaining,
            "expiry_date": r.expiry_date.isoformat() if r.expiry_date else None,
            "issued_to": r.issued_to,
            "issued_by": r.issued_by,
            "serial_number": r.serial_number,
            "subject_alt_names": r.subject_alt_names,
            "error": r.error,
            "checked_at": r.checked_at.isoformat(),
        }

    payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(results),
        "summary": {
            status: sum(1 for r in results if r.status == status)
            for status in ["OK", "WARNING", "CRITICAL", "EXPIRED", "ERROR"]
        },
        "results": [_serialise(r) for r in results],
    }
    return json.dumps(payload, indent=indent)


# ------------------------------------------------------------------ #
# HTML
# ------------------------------------------------------------------ #

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SSL Certificate Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --ok:       #22c55e;
      --warning:  #eab308;
      --critical: #ef4444;
      --expired:  #dc2626;
      --error:    #a855f7;
      --bg:       #0f172a;
      --surface:  #1e293b;
      --border:   #334155;
      --text:     #e2e8f0;
      --muted:    #94a3b8;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 32px 16px 64px;
    }

    header {
      max-width: 1100px;
      margin: 0 auto 32px;
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .logo {
      width: 48px; height: 48px;
      background: linear-gradient(135deg, #3b82f6, #8b5cf6);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 24px;
      flex-shrink: 0;
    }

    h1 { font-size: 1.6rem; font-weight: 700; }
    h1 span { color: var(--muted); font-weight: 400; font-size: 1rem; margin-left: 8px; }

    .summary-bar {
      max-width: 1100px;
      margin: 0 auto 28px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .badge {
      padding: 6px 14px;
      border-radius: 999px;
      font-weight: 600;
      font-size: 0.8rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      opacity: 0.9;
    }
    .badge-ok       { background: rgba(34,197,94,.15);  color: var(--ok); }
    .badge-warning  { background: rgba(234,179,8,.15);  color: var(--warning); }
    .badge-critical { background: rgba(239,68,68,.15);  color: var(--critical); }
    .badge-expired  { background: rgba(220,38,38,.15);  color: var(--expired); }
    .badge-error    { background: rgba(168,85,247,.15); color: var(--error); }

    table {
      width: 100%;
      max-width: 1100px;
      margin: 0 auto;
      border-collapse: collapse;
      background: var(--surface);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 24px rgba(0,0,0,.4);
    }

    thead tr { background: rgba(255,255,255,.04); }
    th {
      padding: 14px 16px;
      text-align: left;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 13px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.025); }

    .domain { font-weight: 600; font-size: 0.95rem; }

    .status-pill {
      display: inline-flex; align-items: center; gap: 5px;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .s-ok       { background: rgba(34,197,94,.15);  color: var(--ok); }
    .s-warning  { background: rgba(234,179,8,.15);  color: var(--warning); }
    .s-critical { background: rgba(239,68,68,.15);  color: var(--critical); }
    .s-expired  { background: rgba(220,38,38,.15);  color: var(--expired); }
    .s-error    { background: rgba(168,85,247,.15); color: var(--error); }

    .days-bar {
      display: flex; align-items: center; gap: 8px;
    }
    .bar-track {
      height: 4px; width: 80px;
      background: var(--border);
      border-radius: 2px;
      overflow: hidden;
    }
    .bar-fill {
      height: 100%;
      border-radius: 2px;
      transition: width .3s;
    }

    .san { color: var(--muted); font-size: 0.8rem; }
    .error-text { color: var(--error); font-size: 0.8rem; }

    footer {
      max-width: 1100px;
      margin: 32px auto 0;
      text-align: center;
      color: var(--muted);
      font-size: 0.8rem;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">🔒</div>
    <div>
      <h1>SSL Certificate Monitor <span>{{ generated_at }}</span></h1>
    </div>
  </header>

  <div class="summary-bar">
    {% if summary.OK %}
    <span class="badge badge-ok">✓ {{ summary.OK }} OK</span>
    {% endif %}
    {% if summary.WARNING %}
    <span class="badge badge-warning">⚠ {{ summary.WARNING }} Warning</span>
    {% endif %}
    {% if summary.CRITICAL %}
    <span class="badge badge-critical">✗ {{ summary.CRITICAL }} Critical</span>
    {% endif %}
    {% if summary.EXPIRED %}
    <span class="badge badge-expired">✗ {{ summary.EXPIRED }} Expired</span>
    {% endif %}
    {% if summary.ERROR %}
    <span class="badge badge-error">? {{ summary.ERROR }} Error</span>
    {% endif %}
  </div>

  <table>
    <thead>
      <tr>
        <th>Domain</th>
        <th>Status</th>
        <th>Expires</th>
        <th>Days Left</th>
        <th>Issuer</th>
        <th>Subject Alt Names</th>
      </tr>
    </thead>
    <tbody>
      {% for r in results %}
      <tr>
        <td class="domain">{{ r.host_label }}</td>
        <td>
          <span class="status-pill s-{{ r.status | lower }}">
            {{ r.status_icon }} {{ r.status }}
          </span>
        </td>
        <td>{{ r.expiry_date.strftime('%Y-%m-%d') if r.expiry_date else '—' }}</td>
        <td>
          {% if r.days_remaining is not none %}
          <div class="days-bar">
            <span>{{ r.days_remaining }}</span>
            <div class="bar-track">
              <div class="bar-fill"
                   style="width:{{ [r.days_remaining / 365 * 100, 100] | min | int }}%;
                          background:{{ r.status_css_color }}"></div>
            </div>
          </div>
          {% else %}—{% endif %}
        </td>
        <td>{{ r.issued_by or '—' }}</td>
        <td>
          {% if r.error %}
          <span class="error-text">{{ r.error }}</span>
          {% elif r.subject_alt_names %}
          <span class="san">{{ r.subject_alt_names[:4] | join(', ') }}{% if r.subject_alt_names | length > 4 %} +{{ r.subject_alt_names | length - 4 }} more{% endif %}</span>
          {% else %}—{% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <footer>
    Generated by <strong>ssl-certificate-monitor</strong> &middot; {{ total }} domain(s) checked
  </footer>
</body>
</html>
"""


def to_html(results: list[CertificateResult]) -> str:
    """Render a self-contained HTML report."""
    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_HTML_TEMPLATE)

    summary = {
        status: sum(1 for r in results if r.status == status)
        for status in ["OK", "WARNING", "CRITICAL", "EXPIRED", "ERROR"]
    }

    sorted_results = sorted(
        results,
        key=lambda r: (["OK", "WARNING", "CRITICAL", "EXPIRED", "ERROR"].index(r.status), r.domain),
    )

    return tmpl.render(
        results=sorted_results,
        summary=summary,
        total=len(results),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
