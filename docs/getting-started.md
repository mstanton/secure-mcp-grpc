# Getting Started with Secure MCP-gRPC

This guide will walk you through setting up and running the Secure MCP-gRPC project using uv for fast and reliable Python package management.

## What is uv?

uv is a modern Python package installer and resolver designed for speed, reliability, and reproducibility. It dramatically speeds up the Python package installation process (often 10-100x faster than pip) while maintaining compatibility with existing Python projects.

## Prerequisites

- Python 3.8 or later
- Git
- Docker and Docker Compose (optional, for containerized deployment)

## Installing uv

### macOS or Linux

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Windows

```powershell
curl.exe -LsSf https://astral.sh/uv/install.ps1 | pwsh -
```

After installation, make sure uv is in your PATH. You might need to restart your terminal.

## Setting Up the Project

### Clone the Repository

```bash
git clone https://github.com/mstanton/secure-mcp-grpc.git
cd secure-mcp-grpc
```

### Option 1: Using the Setup Script (Recommended)

The repository includes a convenient setup script that will set up the virtual environment, install dependencies, and generate Protocol Buffer code:

```bash
./setup.sh
```

Or for a quicker setup if the environment is already initialized:

```bash
./scripts/setup_env.sh
```

### Option 2: Manual Setup

```bash
# Create a virtual environment
uv venv

# Activate the virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -e ".[dev]"

# Generate Protocol Buffer code
./scripts/generate_protos.sh
```

## Configuration

The primary configuration file is located at `config/server.yaml`. Edit this file to adjust security settings, authentication methods, logging, and other options.

For example, to use JWT authentication instead of mTLS, modify the `security.auth.type` setting:

```yaml
security:
  auth:
    type: "jwt"
    jwt:
      secret_key_path: "/app/certs/jwt_secret.key"
      algorithm: "RS256"
      audience: "mcp-clients"
      issuer: "mcp-auth-server"
```

## Running the Server

After setting up the project, you can run the server:

```bash
# Make sure the virtual environment is activated
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Run the server
python -m secure_mcp_grpc.server.main
```

By default, the server listens on `0.0.0.0:50051`.

## Running the Dashboard

The dashboard provides a visual interface for monitoring traffic, security events, and performance metrics:

```bash
# Make sure the virtual environment is activated
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Run the dashboard
python -m secure_mcp_grpc.dashboard.app
```

The dashboard will be accessible at `http://localhost:8050`.

## Docker Deployment

For production deployments, we recommend using Docker:

```bash
# Build and start all services
docker-compose up -d
```

This will start:
- The MCP-gRPC server
- The telemetry dashboard
- Prometheus for metrics collection
- Grafana for advanced visualization

## Testing the Installation

### Test the Server

You can test the server using the included test client:

```bash
# Make sure the virtual environment is activated
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Run the test client
python -m secure_mcp_grpc.cli.client --host localhost --port 50051
```

### Test the Dashboard

Open your browser and navigate to `http://localhost:8050` to verify that the dashboard is running.

## Development Workflow

During development, use the following workflow:

1. Activate the virtual environment:
   ```bash
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Make your changes to the code

3. If you modified Protocol Buffer definitions, regenerate the code:
   ```bash
   ./scripts/generate_protos.sh
   ```

4. Run the tests:
   ```bash
   pytest
   ```

5. Run linting and type checking:
   ```bash
   black .
   isort .
   flake8 .
   mypy .
   ```

## Adding Dependencies

When you need to add a new dependency:

```bash
# For runtime dependencies
uv pip install package-name

# For development dependencies
uv pip install --dev package-name
```

After installing the package, remember to update `pyproject.toml` to include the new dependency.

## Updating Dependencies

To update all dependencies:

```bash
uv pip sync
```

To update a specific package:

```bash
uv pip install --upgrade package-name
```

## Troubleshooting

### Common Issues

1. **Missing `_pb2.py` files**: Run `./scripts/generate_protos.sh` to generate Protocol Buffer code.
2. **"No module named 'secure_mcp_grpc'"**: Make sure the virtual environment is activated and the package is installed in development mode.
3. **Docker build fails**: Ensure Docker has sufficient resources and that all required files are present.

### Getting Help

If you encounter issues not covered here:

1. Check the [GitHub Issues](https://github.com/mstanton/secure-mcp-grpc/issues) to see if the problem has been reported.
2. Review the detailed logs in the `logs/` directory.
3. Open a new issue if the problem persists.

## Next Steps

Now that your environment is set up, you can:

- Explore the project structure to understand the components
- Review the security model and authentication options
- Examine the telemetry and tracing capabilities
- Read the detailed API documentation

Happy coding!
