FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install all ML + service dependencies (cached layer)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir \
        fastapi==0.115.0 \
        uvicorn[standard]==0.30.6

# Copy source code
COPY training/ ./training/
COPY parsers/ ./parsers/
COPY utils/ ./utils/
COPY scripts/ ./scripts/
COPY dorsal_train/ ./dorsal_train/
COPY pyproject.toml ./

RUN mkdir -p /data /models /logs

EXPOSE 8090

ENV PYTHONPATH=/app
ENV SERVICE_HOST=0.0.0.0
ENV SERVICE_PORT=8090

CMD ["uvicorn", "dorsal_train.server:app", "--host", "0.0.0.0", "--port", "8090"]
