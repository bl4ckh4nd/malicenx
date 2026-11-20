# syntax=docker/dockerfile:1

FROM docker.io/library/node:22-bookworm-slim AS web
WORKDIR /web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM docker.io/library/rust:1.95-bookworm AS server
WORKDIR /src
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/src ./src
# Build output lives in RAM: the release build needs several GB and leaves nothing on disk.
RUN --mount=type=tmpfs,target=/usr/local/cargo/registry \
    --mount=type=tmpfs,target=/src/target \
    cargo build --release --locked && cp target/release/malicenx /malicenx

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data malicenx \
    && mkdir -p /data && chown malicenx /data
COPY --from=server /malicenx /usr/local/bin/malicenx
COPY --from=web /web/dist /app/web
COPY rules /rules
ENV MALICENX_LISTEN=0.0.0.0:3993 \
    MALICENX_DATA=/data \
    MALICENX_WEB_DIR=/app/web \
    MALICENX_RULES=/rules \
    CLAMD_ADDR=clamd:3310
USER malicenx
EXPOSE 3993
ENTRYPOINT ["/usr/local/bin/malicenx"]
