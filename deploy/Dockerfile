# syntax=docker/dockerfile:1

# --- Go network collector ---
FROM golang:1.22-bookworm AS go-build
WORKDIR /src
COPY collectors/go-net/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/go-net .

# --- Rust host collector ---
FROM rust:1-bookworm AS rust-build
WORKDIR /src
COPY collectors/rust-host/ ./
RUN mkdir -p /out && cargo build --release && cp target/release/aegis-rust-host /out/rust-host

# --- Python deps ---
FROM python:3.12-slim-bookworm AS py-build
WORKDIR /ml
COPY ml/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt --target /ml/deps
COPY ml/ ./

# --- Gateway runtime ---
FROM node:22-bookworm-slim AS gateway
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates \
    build-essential python3-dev \
    iproute2 procps util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY gateway/package.json ./gateway/
WORKDIR /app/gateway
RUN npm install --omit=dev

WORKDIR /app
COPY gateway/ ./gateway/
COPY schema/ ./schema/
COPY ml/ ./ml/
COPY --from=py-build /ml/deps /app/ml/deps
COPY --from=go-build /out/go-net /app/bin/go-net
COPY --from=rust-build /out/rust-host /app/bin/rust-host

ENV AEGIS_DB_PATH=/data/aegis.db \
    AEGIS_GO_NET_BIN=/app/bin/go-net \
    AEGIS_RUST_HOST_BIN=/app/bin/rust-host \
    AEGIS_PYTHON=python3 \
    PYTHONPATH=/app/ml:/app/ml/deps \
    HOST=0.0.0.0 \
    PORT=8787 \
    NODE_ENV=production

RUN mkdir -p /data && useradd -m -u 10001 aegis \
    && chown -R aegis:aegis /app /data

COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

WORKDIR /app/gateway
USER root
ENTRYPOINT ["/entrypoint.sh"]
