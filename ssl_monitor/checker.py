"""Core SSL certificate checking logic."""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

import certifi

from .models import CertificateResult


# ------------------------------------------------------------------ #
# Synchronous helpers (run in a thread executor)
# ------------------------------------------------------------------ #


def _fetch_cert(domain: str, port: int, timeout: int) -> dict:
    """Open a TLS connection and return the peer certificate as a dict."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((domain, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=domain) as tls:
            return tls.getpeercert()


def _parse_cert(domain: str, port: int, cert: dict, warn_days: int, critical_days: int) -> CertificateResult:
    """Turn a raw peercert dict into a CertificateResult."""
    now = datetime.now(timezone.utc)

    not_after_str: str = cert["notAfter"]
    expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_remaining = (expiry - now).days

    subject = {k: v for rdn in cert.get("subject", []) for k, v in rdn}
    issuer = {k: v for rdn in cert.get("issuer", []) for k, v in rdn}
    san = [v for kind, v in cert.get("subjectAltName", []) if kind == "DNS"]

    return CertificateResult(
        domain=domain,
        port=port,
        checked_at=now,
        is_valid=True,
        days_remaining=days_remaining,
        expiry_date=expiry,
        issued_to=subject.get("commonName"),
        issued_by=issuer.get("organizationName") or issuer.get("commonName"),
        serial_number=cert.get("serialNumber"),
        subject_alt_names=san,
        warn_days=warn_days,
        critical_days=critical_days,
    )


def _make_error_result(
    domain: str,
    port: int,
    error: str,
    warn_days: int = 30,
    critical_days: int = 7,
) -> CertificateResult:
    return CertificateResult(
        domain=domain,
        port=port,
        checked_at=datetime.now(timezone.utc),
        is_valid=False,
        days_remaining=None,
        expiry_date=None,
        issued_to=None,
        issued_by=None,
        serial_number=None,
        subject_alt_names=[],
        error=error,
        warn_days=warn_days,
        critical_days=critical_days,
    )


# ------------------------------------------------------------------ #
# Public async API
# ------------------------------------------------------------------ #


async def check_domain(
    domain: str,
    port: int = 443,
    timeout: int = 10,
    warn_days: int = 30,
    critical_days: int = 7,
) -> CertificateResult:
    """Asynchronously check the SSL certificate for a single domain."""
    loop = asyncio.get_running_loop()
    try:
        cert = await loop.run_in_executor(None, lambda: _fetch_cert(domain, port, timeout))
        return _parse_cert(domain, port, cert, warn_days, critical_days)

    except ssl.SSLCertVerificationError as exc:
        return _make_error_result(domain, port, f"Certificate verification failed: {exc}", warn_days, critical_days)

    except ssl.SSLError as exc:
        return _make_error_result(domain, port, f"SSL error: {exc}", warn_days, critical_days)

    except (socket.timeout, TimeoutError):
        return _make_error_result(domain, port, f"Connection timed out after {timeout}s", warn_days, critical_days)

    except ConnectionRefusedError:
        return _make_error_result(domain, port, "Connection refused", warn_days, critical_days)

    except socket.gaierror as exc:
        return _make_error_result(domain, port, f"DNS resolution failed: {exc}", warn_days, critical_days)

    except Exception as exc:  # noqa: BLE001
        return _make_error_result(domain, port, str(exc), warn_days, critical_days)


async def check_domains(
    targets: list[tuple[str, int, int, int]],
    timeout: int = 10,
    concurrency: int = 20,
) -> list[CertificateResult]:
    """Check multiple domains concurrently, respecting a concurrency cap.

    Args:
        targets: List of (domain, port, warn_days, critical_days) tuples.
        timeout:     Per-connection timeout in seconds.
        concurrency: Max simultaneous connections.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _guarded(domain: str, port: int, warn: int, crit: int) -> CertificateResult:
        async with semaphore:
            return await check_domain(domain, port, timeout, warn, crit)

    tasks = [_guarded(d, p, w, c) for d, p, w, c in targets]
    return await asyncio.gather(*tasks)
