FROM docker.io/library/debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY start.sh /usr/local/bin/start-gateway
ENTRYPOINT ["/usr/local/bin/start-gateway"]
