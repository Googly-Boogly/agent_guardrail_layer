# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools needed by some packages (chromadb, pypdf)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# gosu: privilege-drop helper used by entrypoint.sh to safely switch from
# root (needed to chown bind-mounted volumes) to the non-root agent user.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gosu \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for least-privilege execution
RUN groupadd --gid 1001 agent && \
    useradd --uid 1001 --gid agent --shell /bin/bash --create-home agent

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source and entrypoint
COPY src/ ./src/
COPY examples/ ./examples/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create the logs directory; entrypoint.sh will re-chown it after any bind mount.
RUN mkdir -p /app/logs

# Write guardrail events to the mounted logs volume by default.
# Override with GUARDRAIL_LOG_FILE at runtime.
ENV GUARDRAIL_LOG_FILE=/app/logs/guardrail_events.jsonl \
    GUARDRAIL_LOG_STDOUT=true \
    LLM_PROVIDER=openai \
    LLM_MODEL=gpt-5-mini

# entrypoint.sh runs as root, chowns /app/logs, then execs CMD as agent.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "examples/agent_with_tools.py"]
