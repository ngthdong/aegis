FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml ./
COPY aegis ./aegis

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim AS runtime

RUN useradd --create-home --shell /bin/bash aegis

COPY --from=builder /install /usr/local

WORKDIR /app

COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

RUN mkdir -p /app/data && chown -R aegis:aegis /app

USER aegis

ENV AEGIS_DATABASE_PATH=/app/data/aegis.db

VOLUME ["/app/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1

CMD ["uvicorn", "aegis.api.main:app", "--host", "0.0.0.0", "--port", "8000"]