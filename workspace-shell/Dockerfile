FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV WORKSPACE=/llm-scratch
ENV COMMAND_TIMEOUT=120
ENV MAX_OUTPUT=100000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        diffutils \
        findutils \
        gawk \
        git \
        grep \
        jq \
        nodejs \
        npm \
        pandoc \
        procps \
        sed \
        tar \
        unzip \
        wget \
        zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

RUN useradd \
        --create-home \
        --home-dir /llm-scratch \
        --shell /bin/bash \
        --uid 10001 \
        llm \
    && mkdir -p /llm-scratch \
    && chown -R llm:llm /app /llm-scratch

USER llm

EXPOSE 8000

CMD ["python", "/app/server.py"]
