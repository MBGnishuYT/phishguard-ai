FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PHISHGUARD_ENV=production TRUST_PROXY_HEADERS=true
WORKDIR /app
RUN useradd -m -u 10001 appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
COPY ml ./ml
COPY dashboard ./dashboard
COPY database/schema.sql ./database/schema.sql
# Train the model at build time so the container starts instantly and works fully offline
RUN python -m ml.train > /dev/null && mkdir -p /data && chown -R appuser /app /data
USER appuser
ENV DATABASE_PATH=/data/phishguard.db
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]
