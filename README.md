# SSL Certificate Monitor

A fast, async Python tool that monitors TLS/SSL certificate expiry across multiple domains. Get instant console output, JSON/HTML reports, and Slack or email alerts before your certificates expire.

[![CI](https://github.com/prathambiyani/SSL-Certificate-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/prathambiyani/SSL-Certificate-Monitor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- **Async checking** — scans hundreds of domains concurrently with a configurable concurrency cap
- **Three output formats** — colour-coded console table, JSON, and a self-contained HTML report
- **Configurable thresholds** — global and per-domain `warn_days` / `critical_days`
- **Slack notifications** — posts flagged certificates to a webhook channel
- **Email alerts** — sends an HTML summary via SMTP (with TLS)
- **Exit codes** — integrates with CI/CD pipelines (`0` = OK, `1` = warning, `2` = critical/error)
- **Docker-ready** — single-image, runs as a non-root user
- **Tested** — pytest suite with mocked network calls, 100% offline

---

## Quick Start

### Install

```bash
# Clone and install in a virtual environment
git clone https://github.com/prathambiyani/SSL-Certificate-Monitor.git
cd SSL-Certificate-Monitor
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

### Check domains instantly

```bash
ssl-monitor check google.com github.com stripe.com
```

```
╭──────────────────┬────────────┬──────────────┬───────────┬──────────────────────┬───────────────────────╮
│ Domain           │   Status   │   Expires    │ Days Left │ Issuer               │ Subject Alt Names     │
├──────────────────┼────────────┼──────────────┼───────────┼──────────────────────┼───────────────────────┤
│ google.com       │  ✓ OK      │ 2025-04-14   │       83  │ Google Trust Svcs    │ google.com, *.goo...  │
│ github.com       │  ✓ OK      │ 2026-03-23   │      342  │ DigiCert Inc         │ github.com, www.gi... │
│ stripe.com       │  ✓ OK      │ 2025-07-01   │      161  │ Let's Encrypt        │ stripe.com            │
╰──────────────────┴────────────┴──────────────┴───────────┴──────────────────────┴───────────────────────╯

  Summary: 3 OK
```

### Generate an HTML report

```bash
ssl-monitor check google.com github.com --format html --output-file report.html
```

### Scan from a config file

```bash
cp config.example.yaml config.yaml
# edit config.yaml with your domains
ssl-monitor scan --config config.yaml
```

### Send Slack alerts

```bash
ssl-monitor scan --config config.yaml --notify
```

---

## Installation

**Requirements:** Python 3.11+

```bash
pip install -e .
```

**Development setup** (includes test dependencies):

```bash
pip install -e ".[dev]"
```

---

## Usage

### `ssl-monitor check`

Check one or more domains directly from the CLI.

```
ssl-monitor check [OPTIONS] DOMAINS...

Options:
  -p, --port INTEGER          Default port (default: 443)
  -t, --timeout INTEGER       Connection timeout in seconds (default: 10)
  -w, --warn-days INTEGER     Days before expiry to warn (default: 30)
  -c, --critical-days INTEGER Days before expiry to mark critical (default: 7)
  -f, --format [table|json|html]  Output format (default: table)
  -o, --output-file FILE      Save report to a file
      --fail-on-warning       Exit with code 1 on WARNING status
  -h, --help
```

**Examples:**

```bash
# Custom port
ssl-monitor check example.com:8443

# JSON output piped to jq
ssl-monitor check google.com --format json | jq '.results[0].days_remaining'

# Use in CI — exits non-zero if any cert expires within 14 days
ssl-monitor check api.example.com --warn-days 14 --fail-on-warning
```

### `ssl-monitor scan`

Scan all domains from a YAML configuration file.

```
ssl-monitor scan [OPTIONS]

Options:
  -C, --config FILE           Path to YAML config file  [required]
  -f, --format [table|json|html]
  -o, --output-file FILE
  -n, --notify                Send configured Slack/email notifications
      --fail-on-warning
  -h, --help
```

**Example:**

```bash
ssl-monitor scan --config config.yaml --notify --format html -o report.html
```

---

## Configuration

Copy `config.example.yaml` and edit it:

```yaml
warn_days: 30
critical_days: 7
timeout: 10

domains:
  - google.com
  - github.com
  - host: internal.example.com
    port: 8443
    warn_days: 14   # override per-domain

slack:
  webhook_url: https://hooks.slack.com/services/XXX/YYY/ZZZ
  channel: "#ssl-alerts"

email:
  smtp_host: smtp.gmail.com
  smtp_port: 587
  username: you@gmail.com
  password: your-app-password   # or use SMTP_PASSWORD env var
  from_addr: you@gmail.com
  to_addrs:
    - ops@example.com
```

> **Tip:** Store secrets in environment variables (`SLACK_WEBHOOK_URL`, `SMTP_PASSWORD`) instead of the config file.

---

## Docker

```bash
# Build
docker build -t ssl-certificate-monitor .

# Quick check
docker run --rm ssl-certificate-monitor check google.com github.com

# Scan with config and generate HTML report
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v $(pwd)/reports:/app/reports \
  -e SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL \
  ssl-certificate-monitor scan --config /app/config.yaml --notify -f html -o /app/reports/report.html
```

Or with docker-compose (after creating `config.yaml`):

```bash
docker-compose up
```

---

## Running Tests

```bash
pytest
```

Tests mock all network calls — no real SSL connections needed.

```bash
# With coverage
pytest --cov=ssl_monitor --cov-report=term-missing

# Lint
ruff check ssl_monitor/ tests/
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All certificates OK |
| `1` | One or more certificates in WARNING state (unless `--fail-on-warning` is set) |
| `2` | One or more certificates in CRITICAL, EXPIRED, or ERROR state |

This makes it trivial to integrate into CI/CD pipelines or cron jobs.

---

## Project Structure

```
ssl_monitor/
├── models.py      # CertificateResult dataclass + status logic
├── checker.py     # Async SSL checking (concurrent, with semaphore)
├── config.py      # YAML config loading + validation
├── notifier.py    # Slack webhook + SMTP email alerts
├── reporter.py    # Console (Rich), JSON, and HTML output
└── cli.py         # Click CLI — `check` and `scan` commands
tests/
├── test_checker.py
├── test_config.py
└── test_reporter.py
```

---

## License

MIT — see [LICENSE](LICENSE).
