# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Create non-root user
RUN useradd -m -r dashuser && \
    mkdir -p /app/logs /app/traces /app/config && \
    chown -R dashuser:dashuser /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    ca-certificates \
    curl \
    fonts-liberation \
    # Required for matplotlib/seaborn
    libfreetype6-dev \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Copy requirements first for better caching
COPY requirements.txt .
COPY pyproject.toml .

# Install Python dependencies using uv (much faster than pip)
RUN uv pip install -e ".[dashboard,telemetry]" && \
    # Clean up cache
    find /usr/local/lib/python3.*/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python3.*/site-packages -name "__pycache__" -delete

# Copy the project code
COPY secure_mcp_grpc/ ./secure_mcp_grpc/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Fix permissions
RUN chown -R dashuser:dashuser /app

# Switch to non-root user
USER dashuser

# Expose the dashboard port
EXPOSE 8050

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8050/health || exit 1

# Command to run the dashboard
ENTRYPOINT ["python", "-m", "secure_mcp_grpc.dashboard.app"]
