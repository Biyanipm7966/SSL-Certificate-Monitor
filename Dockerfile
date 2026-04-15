FROM python:3.12-slim

LABEL maintainer="Pratham Biyani <prathambiyani85@gmail.com>"
LABEL description="SSL Certificate Monitor"

# Security: run as non-root
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Install dependencies first (layer cache)
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[dev]" 2>/dev/null || pip install --no-cache-dir .

# Copy source
COPY ssl_monitor/ ./ssl_monitor/

# Switch to non-root user
USER appuser

ENTRYPOINT ["ssl-monitor"]
CMD ["--help"]
