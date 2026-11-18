# Phase 8 (ADR-0030 §9): images for the containment demo. Base images pinned by digest.
#   target "gateway": the gateway (API + in-process executor); holds tool credentials.
#   target "agent":   an agent runtime with ONLY agw-sdk (+ the example code); no tool creds.
FROM ghcr.io/astral-sh/uv@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 AS uv

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS base
COPY --from=uv /uv /bin/uv
# C3 (ADR-0036 §3): git_submit_change applies changes server-side with the git CLI.
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY apps ./apps
COPY packages ./packages
COPY integrations ./integrations

FROM base AS gateway
RUN uv sync --frozen --no-dev --package agw-gateway \
 && useradd --system --uid 10001 agw && mkdir -p /var/lib/agw /creds && chown agw /var/lib/agw /creds
COPY infra/docker/gateway/entrypoint.sh /entrypoint.sh
USER agw
ENTRYPOINT ["/entrypoint.sh"]

FROM base AS agent
RUN uv sync --frozen --no-dev --package agw-sdk && useradd --system --uid 10002 agent
COPY examples/containment/probe.py /probe.py
USER agent
ENTRYPOINT ["python", "/probe.py"]

# Phase 9 (compose profile "ui"): one Python runtime for init, gateway, worker, MCP adapter and
# the demo agents (all workspace packages + the example code + the contract artifact).
FROM base AS runtime
RUN uv sync --frozen --no-dev --all-packages && useradd --system --uid 10003 agw \
 && mkdir -p /var/lib/agw /var/lib/agw-sandbox && chown agw /var/lib/agw /var/lib/agw-sandbox
COPY examples ./examples
COPY contracts/artifacts ./contracts/artifacts
COPY infra/docker/ui ./infra/docker/ui
USER agw
