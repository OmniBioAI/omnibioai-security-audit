FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8004

# PR-B0: no compose-level healthcheck existed for this service prior to
# this change (unlike mysql/redis, which gate downstream depends_on
# conditions) -- api-gateway's depends_on only waited on
# condition: service_started. This HEALTHCHECK makes container health
# introspectable via `docker ps`/`docker inspect`; it does not by itself
# change any depends_on condition in docker-compose.yml.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8004/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8004"]
