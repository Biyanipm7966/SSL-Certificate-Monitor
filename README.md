# SSL Certificate Monitor

A fast, async Python tool that monitors TLS/SSL certificate expiry across multiple domains. Get instant console output, JSON/HTML reports, Slack or email alerts, and a full web dashboard with user accounts and scan history.

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
- **Web dashboard** — real-time streaming scan UI with Server-Sent Events
- **User accounts** — register/login with email + password; all scans are saved per-user
- **Scan history** — browse past scans, view full certificate details, delete old records
- **Folders** — organise scans into named folders for easy retrieval
- **JWT authentication** — short-lived access tokens (15 min) + long-lived refresh tokens (7 days); sessions auto-renew silently, redirect to login only when the refresh token expires
- **PostgreSQL backend** — production-ready persistence via Docker
- **Docker-ready** — single-image app + PostgreSQL compose stack
- **Tested** — pytest suite with mocked network calls, 100% offline

---

## Quick Start

### Option A — Web Dashboard with Docker (recommended)

```bash
# Clone the repo
git clone https://github.com/prathambiyani/SSL-Certificate-Monitor.git
cd SSL-Certificate-Monitor

# Create .env from the example and set secrets
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and JWT_SECRET_KEY

# Start PostgreSQL + app
docker-compose up --build -d

# Open the dashboard
open http://localhost:8000
```

Register an account, then start scanning domains directly in the browser.

### Option B — CLI only with pipx

```bash
pipx install .

# Check domains instantly
ssl-monitor check google.com github.com stripe.com

# Scan from config, send alerts
ssl-monitor scan --config config.yaml --notify

# Start the web dashboard (SQLite-less — needs PostgreSQL env var for full features)
ssl-monitor serve
```

> **Don't have pipx?** `brew install pipx && pipx ensurepath`, then open a new terminal.

---

## Environment Variables

Copy `.env.example` to `.env` before running docker-compose:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `POSTGRES_PASSWORD` | Password for the PostgreSQL `ssl_monitor` user |
| `JWT_SECRET_KEY` | Secret used to sign JWT tokens — use a long random string |

Generate a strong secret:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

> Never commit `.env` to version control. It is already listed in `.gitignore`.

---

## Web Dashboard

### Running with Docker Compose

```bash
docker-compose up --build
```

This starts two services:
- **db** — PostgreSQL 16 on port 5432
- **app** — The SSL Monitor API + SPA on port 8000

The app waits for PostgreSQL to be healthy before starting, and creates all database tables automatically on first boot.

### Running locally (development)

```bash
# Set required environment variables
export DATABASE_URL="postgresql+asyncpg://ssl_monitor:mypassword@localhost:5432/ssl_monitor"
export JWT_SECRET_KEY="your-secret-key"

# Start PostgreSQL separately (e.g. via Docker)
docker run -d -p 5432:5432 \
  -e POSTGRES_USER=ssl_monitor \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=ssl_monitor \
  postgres:16-alpine

# Install and start the app
pipx install .
ssl-monitor serve --reload
```

### Authentication

The dashboard uses **cookie-based JWT authentication** — no tokens are ever exposed to JavaScript:

- **Access token** — short-lived (15 min), stored in an `httponly` cookie
- **Refresh token** — long-lived (7 days), stored in an `httponly` cookie scoped to `/api/auth/refresh`
- **Auto-refresh** — when an API call returns 401, the frontend silently calls `/api/auth/refresh` and retries the request once. If the refresh token has also expired, the user is redirected to the login page.

### Dashboard Features

| Feature | Description |
|---|---|
| Register / Login | Create an account with email + password |
| Run a scan | Enter one or more domains, stream results in real time |
| Scan history | Browse all past scans with timestamps and summaries |
| Scan detail | View the full certificate breakdown for any past scan |
| Folders | Create named folders to categorise scans |
| Move scans | Assign any scan to a folder from the detail view |
| Delete scans | Remove individual scan records |
| Export HTML | Download a self-contained HTML report for any scan |

---

## CLI Usage

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

### `ssl-monitor serve`

Start the web dashboard.

```
ssl-monitor serve [OPTIONS]

Options:
  --host TEXT     Host to bind to (default: 127.0.0.1)
  -p, --port INT  Port to listen on (default: 8000)
  --reload        Auto-reload on code changes (development)
  -h, --help
```

**Example:**

```bash
ssl-monitor serve
ssl-monitor serve --host 0.0.0.0 --port 8080
```

---

## Configuration (YAML)

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

> Store secrets in environment variables (`SLACK_WEBHOOK_URL`, `SMTP_PASSWORD`) instead of the config file.

---

## Docker

### Full stack (app + PostgreSQL)

```bash
docker-compose up --build
```

### App image only

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

---

## Running Tests

```bash
# Install dev dependencies
pipx inject ssl-certificate-monitor pytest pytest-asyncio pytest-cov ruff

# Run all tests
pytest

# With coverage report
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

---

## Project Structure

```
ssl_monitor/
├── models.py      # CertificateResult dataclass + status logic
├── checker.py     # Async SSL checking (concurrent, with semaphore)
├── config.py      # YAML config loading + validation
├── notifier.py    # Slack webhook + SMTP email alerts
├── reporter.py    # Console (Rich), JSON, and HTML output
├── db.py          # SQLAlchemy async ORM — User, Folder, Scan models
├── auth.py        # bcrypt password hashing, JWT token creation/validation
├── server.py      # FastAPI app — REST API + embedded SPA frontend
└── cli.py         # Click CLI — check, scan, serve commands
tests/
├── test_checker.py
├── test_config.py
└── test_reporter.py
docker-compose.yml  # PostgreSQL + app services
.env.example        # Environment variable template
Dockerfile
```

---

## API Reference

All endpoints are under `/api/`.

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create account `{ email, password }` |
| `POST` | `/api/auth/login` | Login `{ email, password }` |
| `POST` | `/api/auth/refresh` | Issue a new access token using the refresh token cookie |
| `POST` | `/api/auth/logout` | Clear auth cookies |
| `GET` | `/api/auth/me` | Return current user info |

### Folders

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/folders` | List all folders for the current user |
| `POST` | `/api/folders` | Create a folder `{ name }` |
| `PUT` | `/api/folders/{id}` | Rename a folder |
| `DELETE` | `/api/folders/{id}` | Delete a folder |

### Scan History

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/history` | Paginated scan list; accepts `folder_id`, `page`, `per_page` |
| `GET` | `/api/history/{id}` | Get a single scan with full results |
| `PATCH` | `/api/history/{id}` | Move scan to a folder `{ folder_id }` |
| `DELETE` | `/api/history/{id}` | Delete a scan |

### Scanning

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan` | Stream scan results via SSE; body `{ domains: [...] }` |
| `POST` | `/api/export/html` | Generate and download an HTML report |

---

## License

MIT — see [LICENSE](LICENSE).
