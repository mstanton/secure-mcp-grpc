# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Create non-root user
RUN useradd -m -r mcpuser && \
    mkdir -p /app/logs /app/traces /app/config /app/certs && \
    chown -R mcpuser:mcpuser /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -e ".[telemetry]"

# Copy the project code
COPY secure_mcp_grpc/ ./secure_mcp_grpc/
COPY scripts/ ./scripts/
COPY config/ ./config/

# Generate Protocol Buffers
RUN python -m secure_mcp_grpc.tools.generate_protos

# Fix permissions
RUN chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Set up logging
RUN mkdir -p ${HOME}/.config/secure_mcp_grpc

# Expose the gRPC port
EXPOSE 50051

# Command to run the server
ENTRYPOINT ["python", "-m", "secure_mcp_grpc.server.main"]
