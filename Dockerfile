# VulnScan AI — Chainlit UI for Docker / Hugging Face Spaces (Docker SDK).
# HF Spaces expect the app to listen on port 7860.
#
# After changing orchestrator/rag code, rebuild so the image is not stale:
#   docker build --no-cache -t vulnscan-chainlit .

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

# git: required for orchestrator clone step
# build-essential: helps some scientific / native wheels compile when wheels are missing
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Slim deps only — do not use full requirements.txt here (PyAV/ffmpeg build failures).
COPY requirements-chainlit-docker.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements-chainlit-docker.txt

COPY . /app

EXPOSE 7860

CMD ["chainlit", "run", "app.py", "--host", "0.0.0.0", "--port", "7860"]
