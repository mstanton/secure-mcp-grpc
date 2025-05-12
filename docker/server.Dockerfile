# Build stage
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build
RUN pip install --no-cache-dir ".[telemetry]"

# Runtime stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN useradd -m -r mcpuser && \
    mkdir -p /app/logs /app/traces /app/config /app/certs && \
    chown -R mcpuser:mcpuser /app

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=mcpuser:mcpuser secure_mcp_grpc/ ./secure_mcp_grpc/
COPY --chown=mcpuser:mcpuser scripts/ ./scripts/
COPY --chown=mcpuser:mcpuser config/ ./config/

# Generate Protocol Buffers
RUN python -m secure_mcp_grpc.tools.generate_protos

# Switch to non-root user
USER mcpuser

# Expose the gRPC port
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import grpc; channel = grpc.insecure_channel('localhost:50051'); channel.channel_ready() and exit(0) or exit(1)" || exit 1

# Command to run the server
ENTRYPOINT ["python", "-m", "secure_mcp_grpc.server.main"]
