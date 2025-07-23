FROM rust:1.70 as builder

# Install Arroyo CLI
RUN cargo install arroyo-cli

FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy Arroyo CLI from builder
COPY --from=builder /usr/local/cargo/bin/arroyo /usr/local/bin/arroyo

# Install Python dependencies for UDFs
RUN pip3 install arroyo-udf

# Create app directory
WORKDIR /app

# Copy project files
COPY sql/ ./sql/
COPY scripts/ ./scripts/
COPY config/ ./config/

# Make scripts executable
RUN chmod +x scripts/*.sh

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD /app/scripts/health_check.sh || exit 1

# Default command
CMD ["/app/scripts/deploy.sh"]
