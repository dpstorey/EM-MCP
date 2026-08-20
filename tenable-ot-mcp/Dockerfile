# SPDX-License-Identifier: Apache-2.0
# Multi-stage build. Stage 1 produces a wheel; stage 2 ships only the
# wheel + runtime dependencies on a slim base image. No build toolchain
# lands in the published image.

# ---------- Stage 1: build ----------
FROM python:3.12.7-slim-bookworm AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN pip install --upgrade pip==24.3.1

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/

# Build the application and all runtime dependencies declared in
# pyproject.toml into an offline wheelhouse for the runtime image.
RUN pip wheel --wheel-dir /wheels .

# ---------- Stage 2: runtime ----------
FROM python:3.12.7-slim-bookworm

LABEL org.opencontainers.image.title="Tenable OT MCP Server"
LABEL org.opencontainers.image.description="Open-source MCP server exposing Tenable OT Security data to AI clients."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://gitlab.com/jwalley/tenable-ot-mcp"
LABEL org.opencontainers.image.authors="John Walley <jwalley@1clearpath.com>"
LABEL org.opencontainers.image.vendor="OneClearPath, Incorporated"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MCP_DATA_DIR=/data \
    MCP_BIND_HOST=0.0.0.0 \
    MCP_BIND_PORT=40443

# Patch base-image OS packages (openssl, zlib, etc.) at build time so
# the published image picks up Debian security updates released after
# the base tag was cut.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 mcp && \
    useradd -u 1000 -g 1000 -d /home/mcp -m -s /bin/bash mcp && \
    mkdir -p /data && chown -R 1000:1000 /data

COPY --from=build /wheels /wheels

RUN pip install --no-index --find-links=/wheels tenable-ot-mcp && \
    rm -rf /wheels

USER 1000

WORKDIR /home/mcp

VOLUME ["/data"]
EXPOSE 40443

# Healthcheck against HTTPS (the default). Cert verification is off
# because the cert is the auto-generated self-signed living next to
# the running process — there's no MITM exposure on the loopback path.
# Deployments using MCP_TLS_DISABLE=1 should override this via
# `docker run --health-cmd` or a compose-file healthcheck override.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import ssl, urllib.request, sys; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; sys.exit(0 if urllib.request.urlopen('https://127.0.0.1:40443/healthz', timeout=3, context=ctx).status == 200 else 1)"

ENTRYPOINT ["tenable-ot-mcp"]
CMD ["serve"]
