# ── Build stage — install Python dependencies ─────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "poetry==1.8.3"

# Copy lock files first so this layer is cached unless deps change
COPY services/ml-service/pyproject.toml services/ml-service/poetry.lock* ./

# Export to requirements.txt and install with pip (avoids poetry at runtime)
RUN poetry export -f requirements.txt --without-hashes -o requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r ml && useradd -r -g ml ml

WORKDIR /workspace

# Bring installed packages over from the builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Proto-generated Python stubs — imported as proto.gen.python.fraud.v1.*
COPY proto/gen/python/ proto/gen/python/

# Service source code
COPY services/ml-service/ services/ml-service/

# PYTHONPATH=/workspace lets Python resolve proto.gen.python.* from the root
ENV PYTHONPATH=/workspace

# Model artifacts are mounted at runtime; this default matches the volume mount
# defined in docker-compose.yml (./ml/artifacts → /workspace/ml/artifacts)
ENV MODEL_ARTIFACT_PATH=/workspace/ml/artifacts

RUN chown -R ml:ml /workspace
USER ml

WORKDIR /workspace/services/ml-service

# HTTP (FastAPI) and gRPC ports
EXPOSE 8000 50051

# main.py starts both servers: gRPC in a background thread, FastAPI on the main thread
CMD ["python", "main.py"]
