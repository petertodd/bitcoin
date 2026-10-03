# Build stage
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libboost-all-dev \
    libevent-dev \
    libtool \
    pkg-config \
    libzmq3-dev \
    libsqlite3-dev \
    # python3 - only needed if running test suite
    # optional for UPnP support:
    # libminiupnpc-dev \
    # optional for NAT-PMP support:
    # libnatpmp-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy local bitcoin source
WORKDIR /build
COPY . .

# Build Bitcoin Core
RUN cmake -B build \
  -DCMAKE_INSTALL_PREFIX=/build \
  -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=/build/bin \
  -DINSTALL_MAN=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_CCACHE=OFF \
  -DBUILD_TESTS=OFF \
  -DREDUCE_EXPORTS=ON \
  -DBUILD_UTIL=ON \
  -DBUILD_WALLET_TOOL=ON \
  -DWITH_ZMQ=ON \
  -DENABLE_IPC=OFF
RUN cmake --build build

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libevent-2.1-7 \
    libevent-extra-2.1-7 \
    libevent-pthreads-2.1-7 \
    libzmq5 \
    libsqlite3-0 \
    libdb5.3++ \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/bin/bitcoind /bin
COPY --from=builder /build/bin/bitcoin-cli /bin

ENV HOME=/data
VOLUME /data/.bitcoin

EXPOSE 8332 8333 18332 18333 18443 18444

ENTRYPOINT ["bitcoind"]
