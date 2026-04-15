"""Alert notifications — Slack webhooks and SMTP email."""

from __future__ import annotations

import smtplib
import ssl as ssl_lib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

import aiohttp

from .models import CertificateResult

if TYPE_CHECKING:
    from .config import EmailConfig, SlackConfig


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _should_notify(result: CertificateResult, notify_on: list[str]) -> bool:
    return result.status.lower() in [n.lower() for n in notify_on]


def _summary_line(result: CertificateResult) -> str:
    if result.error:
        return f"{result.host_label} — ERROR: {result.error}"
    if result.days_remaining is not None and result.days_remaining <= 0:
        return f"{result.host_label} — EXPIRED"
    return f"{result.host_label} — {result.status} ({result.days_remaining} days remaining)"


# ------------------------------------------------------------------ #
# Slack
# ------------------------------------------------------------------ #


async def send_slack(results: list[CertificateResult], cfg: "SlackConfig") -> None:
    """Post a summary of flagged certificates to a Slack webhook."""
    flagged = [r for r in results if _should_notify(r, cfg.notify_on)]
    if not flagged:
        return

    color_map = {"WARNING": "#eab308", "CRITICAL": "#ef4444", "EXPIRED": "#dc2626", "ERROR": "#a855f7"}

    attachments = []
    for result in flagged:
        color = color_map.get(result.status, "#6b7280")
        fields = []

        if result.days_remaining is not None:
            fields.append({"title": "Days Remaining", "value": str(result.days_remaining), "short": True})
        if result.expiry_date:
            fields.append({"title": "Expires", "value": result.expiry_date.strftime("%Y-%m-%d"), "short": True})
        if result.issued_by:
            fields.append({"title": "Issuer", "value": result.issued_by, "short": True})
        if result.error:
            fields.append({"title": "Error", "value": result.error, "short": False})

        attachments.append(
            {
                "color": color,
                "title": f"{result.status_icon} {result.host_label}",
                "fields": fields,
                "footer": "SSL Certificate Monitor",
                "ts": int(result.checked_at.timestamp()),
            }
        )

    payload: dict = {
        "text": f":shield: *SSL Certificate Monitor* — {len(flagged)} domain(s) need attention",
        "attachments": attachments,
    }
    if cfg.channel:
        payload["channel"] = cfg.channel

    async with aiohttp.ClientSession() as session:
        async with session.post(cfg.webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                body = await resp.text()
                raise RuntimeError(f"Slack webhook returned {resp.status}: {body}")


# ------------------------------------------------------------------ #
# Email
# ------------------------------------------------------------------ #


def send_email(results: list[CertificateResult], cfg: "EmailConfig") -> None:
    """Send an HTML email summarising flagged certificates via SMTP."""
    flagged = [r for r in results if _should_notify(r, cfg.notify_on)]
    if not flagged:
        return

    subject = f"SSL Alert — {len(flagged)} domain(s) need attention"

    rows = ""
    for r in flagged:
        expiry = r.expiry_date.strftime("%Y-%m-%d") if r.expiry_date else "N/A"
        days = str(r.days_remaining) if r.days_remaining is not None else "N/A"
        detail = r.error or f"{days} days"
        rows += (
            f"<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb'><strong>{r.host_label}</strong></td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;"
            f"color:{r.status_css_color};font-weight:600'>{r.status}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb'>{expiry}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb'>{detail}</td>"
            f"</tr>"
        )

    html_body = f"""
    <html><body style='font-family:-apple-system,sans-serif;color:#1f2937;'>
    <h2 style='color:#111827'>SSL Certificate Monitor</h2>
    <p>{len(flagged)} domain(s) require your attention:</p>
    <table style='border-collapse:collapse;width:100%;max-width:700px'>
      <thead>
        <tr style='background:#f3f4f6'>
          <th style='padding:10px;text-align:left'>Domain</th>
          <th style='padding:10px;text-align:left'>Status</th>
          <th style='padding:10px;text-align:left'>Expires</th>
          <th style='padding:10px;text-align:left'>Detail</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <p style='color:#6b7280;font-size:0.85em;margin-top:24px'>
      Sent by SSL Certificate Monitor &mdash; {results[0].checked_at.strftime("%Y-%m-%d %H:%M UTC")}
    </p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(cfg.to_addrs)
    msg.attach(MIMEText("\n".join(_summary_line(r) for r in flagged), "plain"))
    msg.attach(MIMEText(html_body, "html"))

    ctx = ssl_lib.create_default_context()
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port) as smtp:
        if cfg.use_tls:
            smtp.starttls(context=ctx)
        smtp.login(cfg.username, cfg.password)
        smtp.sendmail(cfg.from_addr, cfg.to_addrs, msg.as_string())
