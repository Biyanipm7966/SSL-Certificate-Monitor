"""Data models for SSL certificate check results."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Status levels, ordered by severity
STATUS_ORDER = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "EXPIRED": 3, "ERROR": 4}

STATUS_COLORS = {
    "OK": "green",
    "WARNING": "yellow",
    "CRITICAL": "red",
    "EXPIRED": "bright_red",
    "ERROR": "magenta",
}

STATUS_ICONS = {
    "OK": "✓",
    "WARNING": "⚠",
    "CRITICAL": "✗",
    "EXPIRED": "✗",
    "ERROR": "?",
}

STATUS_CSS = {
    "OK": "#22c55e",
    "WARNING": "#eab308",
    "CRITICAL": "#ef4444",
    "EXPIRED": "#dc2626",
    "ERROR": "#a855f7",
}


@dataclass
class CertificateResult:
    """Result of an SSL certificate check for a single domain."""

    domain: str
    port: int
    checked_at: datetime

    # Certificate fields — None when check failed entirely
    is_valid: bool
    days_remaining: Optional[int]
    expiry_date: Optional[datetime]
    issued_to: Optional[str]
    issued_by: Optional[str]
    serial_number: Optional[str]
    subject_alt_names: list[str] = field(default_factory=list)

    # Set when a connection/parsing error occurred
    error: Optional[str] = None

    # Per-domain thresholds used when computing status
    warn_days: int = 30
    critical_days: int = 7

    # ------------------------------------------------------------------ #
    # Derived properties
    # ------------------------------------------------------------------ #

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if not self.is_valid or (self.days_remaining is not None and self.days_remaining <= 0):
            return "EXPIRED"
        if self.days_remaining is not None and self.days_remaining <= self.critical_days:
            return "CRITICAL"
        if self.days_remaining is not None and self.days_remaining <= self.warn_days:
            return "WARNING"
        return "OK"

    @property
    def status_color(self) -> str:
        return STATUS_COLORS[self.status]

    @property
    def status_icon(self) -> str:
        return STATUS_ICONS[self.status]

    @property
    def status_css_color(self) -> str:
        return STATUS_CSS[self.status]

    @property
    def needs_attention(self) -> bool:
        return self.status in ("WARNING", "CRITICAL", "EXPIRED", "ERROR")

    @property
    def host_label(self) -> str:
        return f"{self.domain}:{self.port}" if self.port != 443 else self.domain
