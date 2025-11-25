FROM debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      g++ cmake make libsodium-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN mkdir -p build && cd build && \
    cmake .. && \
    make -j && \
    cp ss_server /usr/local/bin/ss_server && \
    cd / && rm -rf /app/build

# (Optional) run as non-root in container
RUN useradd -m vpnuser
USER vpnuser

EXPOSE 8388

ENV SS_LISTEN_HOST=0.0.0.0
ENV SS_LISTEN_PORT=8388
ENV SS_PASSWORD=changeme

ENTRYPOINT ["/usr/local/bin/ss_server"]
CMD ["0.0.0.0", "8388", "changeme"]
