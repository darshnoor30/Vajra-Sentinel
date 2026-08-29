FROM python:3.12.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VAJRA_HOST=0.0.0.0 \
    VAJRA_PORT=8765

WORKDIR /app

RUN groupadd --system vajra && useradd --system --gid vajra --home-dir /app vajra

COPY pyproject.toml README.md LICENSE ./
COPY app ./app
COPY ml ./ml
COPY artifacts ./artifacts
RUN python -m pip install --upgrade pip && python -m pip install ".[ml]"

RUN mkdir -p /app/runtime && chown -R vajra:vajra /app
USER vajra

EXPOSE 8765
VOLUME ["/app/runtime"]

HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/v1/health', timeout=2)"

CMD ["python", "-m", "app.main"]

