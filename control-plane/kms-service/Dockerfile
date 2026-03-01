# ─────────────────────────────────────────────
# Stage 1 — Build liboqs
# ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    gcc \
    g++ \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and build liboqs (pinned for cache stability)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git \
    && cmake -S liboqs -B liboqs/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
    && ninja -C liboqs/build \
    && ninja -C liboqs/build install


# ─────────────────────────────────────────────
# Stage 2 — Runtime Image
# ─────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Copy compiled liboqs from builder
COPY --from=builder /usr/local /usr/local

RUN ldconfig

# Install Python dependencies separately for caching
COPY requirements.txt .
RUN OQS_BUILD=skip pip install --no-cache-dir -r requirements.txt

# Copy only application code (last for fast rebuilds)
COPY app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
