"""Tests for SSL certificate checker."""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch


from ssl_monitor.checker import check_domain, check_domains, _parse_cert
from ssl_monitor.models import CertificateResult


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #

def _make_cert(days_until_expiry: int = 90) -> dict:
    """Build a minimal peercert dict."""
    expiry = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
    return {
        "subject": [[["commonName", "example.com"]]],
        "issuer": [
            [["organizationName", "Let's Encrypt"]],
            [["commonName", "R3"]],
        ],
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": [
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
        ],
        "serialNumber": "DEADBEEF",
    }


# ------------------------------------------------------------------ #
# _parse_cert
# ------------------------------------------------------------------ #

class TestParseCert:
    def test_fields_populated(self):
        cert = _make_cert(90)
        result = _parse_cert("example.com", 443, cert, warn_days=30, critical_days=7)

        assert result.domain == "example.com"
        assert result.port == 443
        assert result.is_valid is True
        assert result.issued_to == "example.com"
        assert result.issued_by == "Let's Encrypt"
        assert result.serial_number == "DEADBEEF"
        assert "example.com" in result.subject_alt_names
        assert "www.example.com" in result.subject_alt_names

    def test_days_remaining_ok(self):
        result = _parse_cert("example.com", 443, _make_cert(90), 30, 7)
        assert result.days_remaining is not None
        assert 88 <= result.days_remaining <= 91   # small tolerance for test timing

    def test_days_remaining_near_expiry(self):
        result = _parse_cert("example.com", 443, _make_cert(5), 30, 7)
        assert result.days_remaining is not None
        assert 3 <= result.days_remaining <= 6


# ------------------------------------------------------------------ #
# Status computation
# ------------------------------------------------------------------ #

class TestStatus:
    def test_ok(self):
        result = _parse_cert("x.com", 443, _make_cert(90), 30, 7)
        assert result.status == "OK"

    def test_warning(self):
        result = _parse_cert("x.com", 443, _make_cert(20), 30, 7)
        assert result.status == "WARNING"

    def test_critical(self):
        result = _parse_cert("x.com", 443, _make_cert(5), 30, 7)
        assert result.status == "CRITICAL"

    def test_expired(self):
        result = _parse_cert("x.com", 443, _make_cert(-1), 30, 7)
        assert result.status == "EXPIRED"

    def test_error_result_status(self):
        result = CertificateResult(
            domain="x.com", port=443, checked_at=datetime.now(timezone.utc),
            is_valid=False, days_remaining=None, expiry_date=None,
            issued_to=None, issued_by=None, serial_number=None,
            subject_alt_names=[], error="Connection refused",
        )
        assert result.status == "ERROR"

    def test_needs_attention(self):
        ok = _parse_cert("x.com", 443, _make_cert(90), 30, 7)
        warn = _parse_cert("x.com", 443, _make_cert(20), 30, 7)
        assert ok.needs_attention is False
        assert warn.needs_attention is True

    def test_custom_thresholds(self):
        # With tight thresholds, 20 days should be OK
        result = _parse_cert("x.com", 443, _make_cert(20), warn_days=15, critical_days=5)
        assert result.status == "OK"


# ------------------------------------------------------------------ #
# check_domain (async, network mocked)
# ------------------------------------------------------------------ #

class TestCheckDomain:
    async def test_success(self):
        with patch("ssl_monitor.checker._fetch_cert", return_value=_make_cert(90)):
            result = await check_domain("example.com")
        assert result.status == "OK"
        assert result.error is None

    async def test_ssl_verification_error(self):
        import ssl
        with patch("ssl_monitor.checker._fetch_cert", side_effect=ssl.SSLCertVerificationError(1, "cert verify failed")):
            result = await check_domain("bad.example.com")
        assert result.status == "ERROR"
        assert result.error is not None
        assert "verification" in result.error.lower()

    async def test_timeout(self):
        with patch("ssl_monitor.checker._fetch_cert", side_effect=TimeoutError()):
            result = await check_domain("slow.example.com", timeout=1)
        assert result.status == "ERROR"
        assert "timed out" in result.error.lower()

    async def test_connection_refused(self):
        with patch("ssl_monitor.checker._fetch_cert", side_effect=ConnectionRefusedError()):
            result = await check_domain("refused.example.com")
        assert result.status == "ERROR"
        assert "refused" in result.error.lower()

    async def test_dns_failure(self):
        import socket
        with patch("ssl_monitor.checker._fetch_cert", side_effect=socket.gaierror("Name or service not known")):
            result = await check_domain("nonexistent.invalid")
        assert result.status == "ERROR"
        assert "dns" in result.error.lower()


# ------------------------------------------------------------------ #
# check_domains
# ------------------------------------------------------------------ #

class TestCheckDomains:
    async def test_multiple_domains(self):
        with patch("ssl_monitor.checker._fetch_cert", return_value=_make_cert(90)):
            targets = [("a.com", 443, 30, 7), ("b.com", 443, 30, 7), ("c.com", 443, 30, 7)]
            results = await check_domains(targets)
        assert len(results) == 3
        assert all(r.status == "OK" for r in results)

    async def test_mixed_results(self):
        def _side_effect(domain, port, timeout):
            if domain == "bad.com":
                raise ConnectionRefusedError()
            return _make_cert(90)

        with patch("ssl_monitor.checker._fetch_cert", side_effect=_side_effect):
            targets = [("good.com", 443, 30, 7), ("bad.com", 443, 30, 7)]
            results = await check_domains(targets)

        by_domain = {r.domain: r for r in results}
        assert by_domain["good.com"].status == "OK"
        assert by_domain["bad.com"].status == "ERROR"
