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

COPY --from=builder /usr/local /usr/local

RUN ldconfig

COPY requirements.txt .
RUN OQS_BUILD=skip pip install --no-cache-dir -r requirements.txt

COPY simulator.py .

CMD ["python", "simulator.py"]
