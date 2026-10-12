# syntax=docker/dockerfile:1

# Enterprise Cryptographic Discovery & Analysis Tool (IndraMesh)
# Standard Dockerfile for running the tool in isolated environments.

FROM python:3.11-slim-bookworm

# Set environment variables to prevent Python from writing .pyc files and buffer outputs.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# App environment configuration
ENV PORT=8501

WORKDIR /opt/indramesh

# Install system dependencies.
# `curl` is NOT optional decoration here: the HEALTHCHECK below invokes it, and python:3.11-slim
# does not ship curl. Without this line the image builds cleanly and then reports itself unhealthy
# forever, which is the worst possible failure -- it looks like the app is broken when it is only
# the probe that is. `ca-certificates` is what lets pip reach PyPI over TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the project. `.dockerignore` is what keeps the third-party benchmark corpora -- cloned
# checkouts of paramiko and golang.org/x/crypto, hundreds of MB -- out of the image; without it
# `COPY . .` would ship someone else's source code inside our image.
COPY . .

# Create a generic volume mount point for targets
VOLUME ["/target"]

# Expose web console port
EXPOSE 8501

# Add a healthcheck for the IndraMesh web console
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl --fail --silent http://localhost:8501/api/status || exit 1

# Default command: launch the interactive UI.
# `--allow-unauthenticated-public` is required because a container is bound to 0.0.0.0 by
# nature and app.py now refuses an off-loopback bind without it (the console has no auth, so
# the flag makes the exposure an explicit decision rather than a default).
CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "8501", "--allow-unauthenticated-public"]
