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

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app/mtls
COPY --from=builder /usr/local /usr/local
RUN ldconfig
COPY control-plane/kms-service/requirements.txt .
RUN OQS_BUILD=skip pip install --no-cache-dir -r requirements.txt
COPY control-plane/kms-service/app ./app
COPY mtls/mtls_requests.py ./mtls/mtls_requests.py
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--ssl-keyfile", "/certs/kms-service.key", \
     "--ssl-certfile", "/certs/kms-service.crt", \
     "--ssl-ca-certs", "/certs/ca.crt", \
     "--ssl-cert-reqs", "2"]
