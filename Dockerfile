FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/app/data EVENT_DATABASE=/app/data/events.db \
    DATABASE_URL=sqlite:////app/data/agentveritas.db
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home veritas
COPY backend /app/backend
COPY frontend /app/frontend
COPY deployments /app/deployments
RUN mkdir -p /app/data && chown -R veritas:veritas /app/data
USER veritas
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)"
CMD ["python", "-m", "uvicorn", "backend.app.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
