FROM debian:12-slim

# Install build deps: compiler, cmake, libsodium, OpenSSL dev, etc.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      g++ \
      cmake \
      make \
      libsodium-dev \
      libssl-dev \
      pkg-config \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . /app

# Build C++ Shadowsocks server
RUN mkdir -p build && cd build && \
    cmake .. && \
    make -j && \
    cp ss_server /usr/local/bin/ss_server && \
    cd / && rm -rf /app/build

# Runtime user (optional)
RUN useradd -m vpnuser
USER vpnuser

EXPOSE 8089

# Default args (overridden by docker-compose)
ENV SS_LISTEN_HOST=0.0.0.0
ENV SS_LISTEN_PORT=8089
ENV SS_PASSWORD=changeme

ENTRYPOINT ["/usr/local/bin/ss_server"]
CMD ["0.0.0.0", "8089", "changeme"]
