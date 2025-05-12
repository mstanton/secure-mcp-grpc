# Secure MCP-gRPC

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Security Rating](https://img.shields.io/badge/security-A%2B-brightgreen.svg)

**A secure gRPC transport layer for Model Context Protocol (MCP) with advanced security features, comprehensive telemetry, and real-time visualization.**

*Developed by Matthew Stanton & Claude AI*

## 🌟 Overview

The Model Context Protocol (MCP) enables AI models to communicate with external tools and data sources. This project adds a secure gRPC transport layer for MCP, providing:

- **Enhanced Security**: Zero-trust architecture with mutual TLS, token-based authentication, and fine-grained authorization
- **Comprehensive Telemetry**: Detailed insights into model interactions, performance metrics, and security events
- **Visual Traffic Analysis**: Real-time visualization of traffic patterns and model communication graphs
- **Enterprise-Grade Features**: Rate limiting, audit logging, anomaly detection, and more

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Security Best Practices](#-security-best-practices)
- [Observability](#-observability)
- [Dashboard](#-dashboard)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔒 Security Features

- **Mutual TLS Authentication**: Secure client-server identification with certificate validation
- **Token-based Authentication**: Support for JWT and OAuth 2.0
- **Fine-grained Authorization**: Role-based access control for specific model capabilities
- **Rate Limiting**: Protection against DoS attacks with per-client limits
- **Anomaly Detection**: Identification of unusual patterns and potential threats
- **Audit Logging**: Comprehensive event tracking for compliance requirements
- **Secure Defaults**: All security features enabled by default with sensible configurations

### 📊 Telemetry Capabilities

- **Performance Monitoring**: Response times, throughput, and resource utilization tracking
- **Security Event Logging**: Authentication attempts, authorization failures, and suspicious activities
- **Usage Analytics**: Understanding how models are being used and by whom
- **Health Monitoring**: Real-time status of all system components
- **Anonymous Reporting**: Privacy-preserving aggregated insights

### 🔍 Interaction Tracing

- **Request/Response Capture**: Full payload logging with configurable sanitization
- **Connection Metadata**: Detailed information about clients and sessions
- **Path Traversal**: Tracking of multi-model interaction chains
- **Data Lineage**: Understanding how data flows between models
- **Timing Analysis**: Performance bottleneck identification

### 📈 Visualization Dashboard

- **Traffic Flow Diagrams**: Sankey diagrams showing request patterns
- **Model Interaction Networks**: Graph visualization of model communication
- **Security Event Heatmaps**: Temporal analysis of security incidents
- **Latency Distribution Charts**: Performance profiles across different methods
- **Real-Time Monitoring**: Live updates on system status and metrics

## 🏗️ Architecture

The Secure MCP-gRPC system consists of several core components:

```
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│                   │     │                   │     │                   │
│   AI Model with   │     │  Secure MCP-gRPC  │     │   AI Model with   │
│    MCP Client     │◄───►│      Server       │◄───►│    MCP Client     │
│                   │     │                   │     │                   │
└───────────────────┘     └─────────┬─────────┘     └───────────────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │   Interaction   │
                          │     Tracer      │
                          └─────────┬───────┘
                                   │
                                   ▼
┌───────────────────┐     ┌─────────────────┐     ┌───────────────────┐
│                   │     │                 │     │                   │
│     Prometheus    │◄───►│   Telemetry     │◄───►│     Dashboard     │
│                   │     │   Dashboard     │     │                   │
└───────────────────┘     └─────────────────┘     └───────────────────┘
```

### Key Components:

1. **Secure MCP-gRPC Server**: Core server that handles authentication, authorization, and request processing
2. **Interaction Tracer**: Captures detailed information about model interactions
3. **Telemetry Dashboard**: Web-based visualization of traffic patterns and metrics
4. **MCP Clients**: AI models that communicate with the server
5. **Prometheus/Grafana**: Additional monitoring and alerting tools

## 🚀 Installation

### Prerequisites

- Python 3.8+
- gRPC tools
- TLS certificates for secure communication
- Docker and Docker Compose (for containerized deployment)

### Installation from PyPI

```bash
pip install secure-mcp-grpc
```

### Installation from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-mcp-grpc.git
cd secure-mcp-grpc

# Install in development mode with all extras
pip install -e ".[full]"

# Generate Protocol Buffer code
python -m secure_mcp_grpc.tools.generate_protos
```

### Docker Installation

```bash
# Build and start all services
docker-compose up -d

# To stop all services
docker-compose down
```

## ⚙️ Configuration

Secure MCP-gRPC uses YAML configuration files for server, client, and dashboard settings.

### Server Configuration

The main server configuration file is located at `config/server.yaml`.

```yaml
# Example minimal configuration
server:
  host: "0.0.0.0"
  port: 50051

security:
  auth:
    type: "mtls"
    mtls:
      cert_path: "/path/to/server.crt"
      key_path: "/path/to/server.key"
      ca_path: "/path/to/ca.crt"
```

### Environment Variables

You can also configure the server using environment variables:

```bash
export MCP_SERVER_HOST=0.0.0.0
export MCP_SERVER_PORT=50051
export MCP_AUTH_TYPE=mtls
export MCP_CERT_PATH=/path/to/server.crt
export MCP_KEY_PATH=/path/to/server.key
export MCP_CA_PATH=/path/to/ca.crt
```

See [Configuration Guide](docs/configuration.md) for detailed configuration options.

## 🧰 Usage

### Starting the Server

```python
from secure_mcp_grpc import SecureMCPServer, MTLSAuthProvider
from mcp.server import MCPServer

# Create your MCP server implementation
mcp_server = MCPServer(tools={
    "example_tool": {
        "description": "An example tool",
        "parameters": {
            "param1": {"type": "string"}
        }
    }
})

# Create a secure server with mTLS authentication
auth_provider = MTLSAuthProvider(
    cert_path="/path/to/server.crt",
    key_path="/path/to/server.key",
    ca_path="/path/to/ca.crt"
)

secure_server = SecureMCPServer(
    mcp_server=mcp_server,
    auth_provider=auth_provider,
    host="0.0.0.0",
    port=50051,
    telemetry_enabled=True
)

# Start the server
secure_server.start()
```

### Client Implementation

```python
from secure_mcp_grpc import SecureMCPClient, MTLSAuthProvider

# Create a secure client with mTLS authentication
auth_provider = MTLSAuthProvider(
    cert_path="/path/to/client.crt",
    key_path="/path/to/client.key",
    ca_path="/path/to/ca.crt"
)

client = SecureMCPClient(
    host="localhost",
    port=50051,
    auth_provider=auth_provider
)

# Connect to the server
await client.connect()

# Send a request
response = await client.send_request(
    method="example_tool",
    params={"param1": "value1"}
)

# Print the response
print(response.result)
```

### Running the Dashboard

```bash
# Start the telemetry dashboard
python -m secure_mcp_grpc.dashboard.app --traces-dir /path/to/traces --port 8050
```

## 🔐 Security Best Practices

### Certificate Management

Always use strong certificates for mTLS authentication:

```bash
# Generate a CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 365

# Generate server and client certificates
# (see docs/certificates.md for detailed instructions)
```

### Access Control

Implement the principle of least privilege by restricting model access to only necessary tools:

```yaml
security:
  authorization:
    enabled: true
    default_policy: "deny"
    access_control:
      model-a:
        - "summarize_text"
        - "check_grammar"
      model-b:
        - "analyze_sentiment"
```

### Authentication Token Security

If using JWT or OAuth2:

1. Use short-lived tokens
2. Implement token rotation
3. Validate all claims including audience and issuer
4. Use asymmetric keys when possible

For complete security recommendations, see [Security Guide](docs/security.md).

## 👁️ Observability

### Interaction Tracing

The system captures detailed information about each model interaction:

```python
# Enable interaction tracing
tracer = InteractionTracer(
    storage_path="/path/to/traces",
    export_format="jsonl",
    sanitize_fields=["password", "token", "secret"]
)

# Record a request event
await tracer.record_request(
    method="summarize_text",
    params={"text": "This is a sample text to summarize."},
    session_id="session-123",
    user_id="model-a"
)

# Record a response event
await tracer.record_response(
    request_id="request-456",
    result={"summary": "A sample text."},
    session_id="session-123",
    processing_time_ms=150
)
```

### Metrics

Prometheus metrics are exposed by default on port 9090:

- Request counts and rates
- Response latencies
- Error rates
- Security events
- Resource utilization

### Log Formats

Logs are available in both structured JSON and human-readable formats:

```
2025-05-11 10:15:23 - secure_mcp_grpc.server - INFO - Starting MCP session 8f1c7e5a from 192.168.1.100
2025-05-11 10:15:24 - secure_mcp_grpc.server - INFO - Authentication successful for user model-a
```

## 📊 Dashboard

The telemetry dashboard provides real-time visualization of system activity:

### Dashboard Features

1. **Overview**: Summary metrics and system health
2. **Traffic Flow**: Sankey diagrams of request patterns
3. **Security**: Heatmaps and anomaly detection
4. **Performance**: Latency distributions and bottleneck analysis
5. **Settings**: Configuration options for the dashboard

### Dashboard Screenshots

![Dashboard Overview](docs/images/dashboard-overview.png)
![Traffic Flow](docs/images/traffic-flow.png)
![Security Heatmap](docs/images/security-heatmap.png)

### Dashboard Access

Access the dashboard at `http://your-server:8050/` after starting it.

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to the project.

### Development Setup

```bash
# Set up development environment
pip install -e ".[dev]"

# Run tests
pytest

# Check code style
black .
isort .
flake8 .

# Run type checking
mypy .
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Matthew Stanton**: Lead architect and security expert
- **Claude AI**: Co-creator and documentation contributor
- Anthropic for their work on Model Context Protocol (MCP)
- The gRPC team for their excellent communication framework

---

*For more detailed information, please refer to the [documentation](docs/).*

*Security issues should be reported according to our [security policy](SECURITY.md).*
