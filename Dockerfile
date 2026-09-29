FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Create the non-root user
RUN useradd -m -u 1000 astra

# Create data directory owned by astra (for SQLite checkpoints)
RUN mkdir -p /data && chown -R astra:astra /data

USER astra

# SQLite path — writable by astra, mountable as volume for persistence
ENV ASTRA_CHECKPOINT_DB=/data/astra_checkpoints.db

# Declare volume for persistence
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()"

CMD ["uvicorn", "astra_swarm.api:app", "--host", "0.0.0.0", "--port", "8000"]