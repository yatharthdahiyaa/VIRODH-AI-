# Virodh AI gateway image (CPU). Build from the repository root:
#   docker build -f deploy/Dockerfile -t virodh-ai:1.0 .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# OpenCV / RapidOCR runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch torchvision \
    && pip install -r requirements.txt

COPY . .
RUN useradd --system --create-home --uid 10001 virodh \
    && mkdir -p /data /app/logs /app/data/cache \
    && chown -R virodh /data /app/logs /app/data
USER virodh

# Keys are NEVER baked into the image: pass GROQ_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY / VIRODH_ADMIN_TOKEN at run time.
ENV VIRODH_DB=/data/virodh.db \
    VIRODH_LOG_PROMPT_PREVIEW=false \
    VIRODH_ALLOW_LOOPBACK=false
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=60s --retries=3 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).status == 200 else 1)"

# One process per container; scale with replicas (docker compose --scale / k8s). Linux has no Windows accept() issue,
# so --workers N also works inside one container.
CMD ["python", "scripts/virodh_serve.py", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy", "--forwarded-allow-ips", "*"]
