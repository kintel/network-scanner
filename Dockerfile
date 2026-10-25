# Stage 1: Dependency resolution with uv
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock* ./
RUN uv venv /opt/venv && uv pip install --no-cache -r pyproject.toml

# Stage 2: Minimal runtime image
FROM python:3.12-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap libcap2-bin && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /app
COPY network_scanner.py network-scanner.py ./
ENTRYPOINT ["python", "network-scanner.py"]
CMD ["--config", "/config/config.ini", "--dry-run"]
