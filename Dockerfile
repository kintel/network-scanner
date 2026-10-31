# Stage 1: Dependency resolution with uv
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Stage 2: Minimal runtime image
FROM python:3.12-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl nmap libcap2-bin && \
    curl -fsSL "https://www.wireshark.org/download/automated/data/manuf" -o /app/manuf && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1
WORKDIR /app
COPY enrichment.py network_scanner.py network-scanner.py ./
ENTRYPOINT ["python", "network-scanner.py"]
CMD ["--config", "/config/config.ini", "--dry-run"]

