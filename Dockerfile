FROM python:3.12-slim

LABEL maintainer="Pratham Biyani <prathambiyani85@gmail.com>"
LABEL description="SSL Certificate Monitor"

# Security: run as non-root
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copy source before installing so setuptools can find the package directory
COPY ssl_monitor/ ./ssl_monitor/
COPY pyproject.toml setup.py ./

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# Switch to non-root user
USER appuser

ENTRYPOINT ["ssl-monitor"]
CMD ["--help"]
