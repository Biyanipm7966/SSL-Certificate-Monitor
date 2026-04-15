"""Tests for reporters (JSON and HTML)."""

import json
from datetime import datetime, timezone, timedelta

from ssl_monitor.models import CertificateResult
from ssl_monitor.reporter import to_json, to_html


def _make_result(domain: str = "example.com", days: int = 90, error: str | None = None) -> CertificateResult:
    expiry = datetime.now(timezone.utc) + timedelta(days=days) if not error else None
    return CertificateResult(
        domain=domain,
        port=443,
        checked_at=datetime.now(timezone.utc),
        is_valid=error is None,
        days_remaining=days if not error else None,
        expiry_date=expiry,
        issued_to="example.com",
        issued_by="Let's Encrypt",
        serial_number="ABC123",
        subject_alt_names=["example.com", "www.example.com"],
        error=error,
        warn_days=30,
        critical_days=7,
    )


class TestJsonReporter:
    def test_valid_json(self):
        results = [_make_result()]
        output = to_json(results)
        payload = json.loads(output)
        assert "results" in payload
        assert "summary" in payload
        assert "generated_at" in payload

    def test_summary_counts(self):
        results = [
            _make_result("a.com", 90),    # OK
            _make_result("b.com", 20),    # WARNING
            _make_result("c.com", 5),     # CRITICAL
            _make_result("d.com", error="boom"),  # ERROR
        ]
        payload = json.loads(to_json(results))
        assert payload["summary"]["OK"] == 1
        assert payload["summary"]["WARNING"] == 1
        assert payload["summary"]["CRITICAL"] == 1
        assert payload["summary"]["ERROR"] == 1

    def test_total_count(self):
        results = [_make_result(f"host{i}.com") for i in range(5)]
        payload = json.loads(to_json(results))
        assert payload["total"] == 5

    def test_result_fields(self):
        result = _make_result("example.com", 45)
        payload = json.loads(to_json([result]))
        r = payload["results"][0]
        assert r["domain"] == "example.com"
        assert r["status"] == "OK"
        assert r["is_valid"] is True
        assert r["days_remaining"] == 45
        assert r["issued_by"] == "Let's Encrypt"
        assert "example.com" in r["subject_alt_names"]

    def test_error_result(self):
        result = _make_result("bad.com", error="connection refused")
        payload = json.loads(to_json([result]))
        r = payload["results"][0]
        assert r["status"] == "ERROR"
        assert r["error"] == "connection refused"
        assert r["days_remaining"] is None


class TestHtmlReporter:
    def test_produces_html(self):
        results = [_make_result()]
        html = to_html(results)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html

    def test_domain_appears_in_html(self):
        results = [_make_result("myspecialdomain.com")]
        html = to_html(results)
        assert "myspecialdomain.com" in html

    def test_status_appears(self):
        results = [
            _make_result("ok.com", 90),
            _make_result("warn.com", 20),
            _make_result("crit.com", 5),
        ]
        html = to_html(results)
        assert "OK" in html
        assert "WARNING" in html
        assert "CRITICAL" in html

    def test_summary_badges(self):
        results = [_make_result("a.com", 90), _make_result("b.com", error="oops")]
        html = to_html(results)
        assert "badge-ok" in html
        assert "badge-error" in html

    def test_self_contained_no_external_resources(self):
        results = [_make_result()]
        html = to_html(results)
        # Should not load external stylesheets or scripts
        assert '<link rel="stylesheet"' not in html
        assert "<script src=" not in html
