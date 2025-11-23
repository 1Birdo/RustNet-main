# RustNet C&C Server
FROM rust:1.82-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/rustnet

# Copy workspace files
COPY Cargo.toml ./
COPY server ./server
COPY client ./client

# Build the server
WORKDIR /usr/src/rustnet/server
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 rustnet

# Create directories
RUN mkdir -p /opt/rustnet/config && chown -R rustnet:rustnet /opt/rustnet

# Copy binary
COPY --from=builder /usr/src/rustnet/target/release/rustnet-server /opt/rustnet/
COPY --from=builder /usr/src/rustnet/server/config/server.example.toml /opt/rustnet/config/server.toml

# Set working directory
WORKDIR /opt/rustnet

# Switch to app user
USER rustnet

# Expose ports
EXPOSE 1420 7002

# Set environment
ENV RUST_LOG=info

# Run the server
CMD ["/opt/rustnet/rustnet-server"]
