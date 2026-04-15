"""Configuration loading from YAML files."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class DomainConfig:
    host: str
    port: int = 443
    warn_days: int = 30
    critical_days: int = 7


@dataclass
class SlackConfig:
    webhook_url: str
    channel: Optional[str] = None
    notify_on: list[str] = field(default_factory=lambda: ["warning", "critical", "expired", "error"])


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    from_addr: str
    to_addrs: list[str]
    use_tls: bool = True
    notify_on: list[str] = field(default_factory=lambda: ["warning", "critical", "expired", "error"])


@dataclass
class Config:
    domains: list[DomainConfig]
    timeout: int = 10
    warn_days: int = 30
    critical_days: int = 7
    slack: Optional[SlackConfig] = None
    email: Optional[EmailConfig] = None


# ------------------------------------------------------------------ #
# Loader
# ------------------------------------------------------------------ #


def load_config(path: str | Path) -> Config:
    """Parse a YAML config file and return a Config object.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the config file is missing required fields.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open() as fh:
        raw = yaml.safe_load(fh) or {}

    global_warn = int(raw.get("warn_days", 30))
    global_crit = int(raw.get("critical_days", 7))
    timeout = int(raw.get("timeout", 10))

    domains: list[DomainConfig] = []
    for entry in raw.get("domains", []):
        if isinstance(entry, str):
            domains.append(DomainConfig(host=entry, warn_days=global_warn, critical_days=global_crit))
        elif isinstance(entry, dict):
            host = entry.get("host")
            if not host:
                raise ValueError(f"Domain entry missing 'host' key: {entry}")
            domains.append(
                DomainConfig(
                    host=host,
                    port=int(entry.get("port", 443)),
                    warn_days=int(entry.get("warn_days", global_warn)),
                    critical_days=int(entry.get("critical_days", global_crit)),
                )
            )
        else:
            raise ValueError(f"Invalid domain entry: {entry!r}")

    if not domains:
        raise ValueError("No domains specified in config file.")

    slack: Optional[SlackConfig] = None
    if s := raw.get("slack"):
        # Allow webhook_url to come from an environment variable
        webhook = s.get("webhook_url", "") or os.environ.get("SLACK_WEBHOOK_URL", "")
        if not webhook:
            raise ValueError("slack.webhook_url is required (or set SLACK_WEBHOOK_URL env var)")
        slack = SlackConfig(
            webhook_url=webhook,
            channel=s.get("channel"),
            notify_on=s.get("notify_on", ["warning", "critical", "expired", "error"]),
        )

    email: Optional[EmailConfig] = None
    if e := raw.get("email"):
        password = e.get("password", "") or os.environ.get("SMTP_PASSWORD", "")
        email = EmailConfig(
            smtp_host=e["smtp_host"],
            smtp_port=int(e.get("smtp_port", 587)),
            username=e["username"],
            password=password,
            from_addr=e["from_addr"],
            to_addrs=e["to_addrs"],
            use_tls=bool(e.get("use_tls", True)),
            notify_on=e.get("notify_on", ["warning", "critical", "expired", "error"]),
        )

    return Config(
        domains=domains,
        timeout=timeout,
        warn_days=global_warn,
        critical_days=global_crit,
        slack=slack,
        email=email,
    )
