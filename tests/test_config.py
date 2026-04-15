"""Tests for configuration loading."""

import pytest
from pathlib import Path

from ssl_monitor.config import load_config


@pytest.fixture
def tmp_config(tmp_path):
    """Helper that writes a YAML string to a temp file and returns its path."""
    def _write(content: str) -> Path:
        p = tmp_path / "config.yaml"
        p.write_text(content)
        return p
    return _write


class TestLoadConfig:
    def test_simple_string_domains(self, tmp_config):
        cfg = load_config(tmp_config("domains:\n  - google.com\n  - github.com\n"))
        assert len(cfg.domains) == 2
        assert cfg.domains[0].host == "google.com"
        assert cfg.domains[0].port == 443

    def test_dict_domain_with_port(self, tmp_config):
        yaml = "domains:\n  - host: example.com\n    port: 8443\n"
        cfg = load_config(tmp_config(yaml))
        assert cfg.domains[0].port == 8443

    def test_global_thresholds(self, tmp_config):
        yaml = "warn_days: 14\ncritical_days: 3\ndomains:\n  - example.com\n"
        cfg = load_config(tmp_config(yaml))
        assert cfg.warn_days == 14
        assert cfg.critical_days == 3
        # Domain should inherit global thresholds
        assert cfg.domains[0].warn_days == 14
        assert cfg.domains[0].critical_days == 3

    def test_per_domain_threshold_override(self, tmp_config):
        yaml = (
            "warn_days: 30\ncritical_days: 7\n"
            "domains:\n  - host: example.com\n    warn_days: 60\n    critical_days: 14\n"
        )
        cfg = load_config(tmp_config(yaml))
        assert cfg.domains[0].warn_days == 60
        assert cfg.domains[0].critical_days == 14

    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_missing_host_key_raises(self, tmp_config):
        yaml = "domains:\n  - port: 443\n"
        with pytest.raises(ValueError, match="'host'"):
            load_config(tmp_config(yaml))

    def test_empty_domains_raises(self, tmp_config):
        with pytest.raises(ValueError, match="No domains"):
            load_config(tmp_config("domains: []\n"))

    def test_timeout(self, tmp_config):
        yaml = "timeout: 30\ndomains:\n  - example.com\n"
        cfg = load_config(tmp_config(yaml))
        assert cfg.timeout == 30

    def test_slack_config(self, tmp_config):
        yaml = (
            "domains:\n  - example.com\n"
            "slack:\n  webhook_url: https://hooks.slack.com/xxx\n  channel: '#alerts'\n"
        )
        cfg = load_config(tmp_config(yaml))
        assert cfg.slack is not None
        assert cfg.slack.webhook_url == "https://hooks.slack.com/xxx"
        assert cfg.slack.channel == "#alerts"

    def test_slack_missing_webhook_raises(self, tmp_config, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        yaml = "domains:\n  - example.com\nslack:\n  webhook_url: ''\n"
        with pytest.raises(ValueError, match="webhook_url"):
            load_config(tmp_config(yaml))
