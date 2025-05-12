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
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Docker Deployment](#-docker-deployment)
- [Manual Installation](#-manual-installation)
- [Configuration](#-configuration)
- [Security](#-security)
- [Monitoring](#-monitoring)
- [Development](#-development)
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

## 📋 Prerequisites

- Docker and Docker Compose
- Python 3.8+ (for development)
- OpenSSL (for certificate generation)
- Git

## 🚀 Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-mcp-grpc.git
   cd secure-mcp-grpc
   ```

2. Run the setup script:
   ```bash
   ./setup.sh
   ```

3. Start the services:
   ```bash
   docker-compose -f docker/docker-compose.yml up -d
   ```

4. Access the services:
   - gRPC Server: localhost:50051
   - Dashboard: http://localhost:8050
   - Grafana: http://localhost:3000
   - Prometheus: http://localhost:9090

## 🐳 Docker Deployment

### Production Deployment

1. Build and start all services:
   ```bash
   docker-compose -f docker/docker-compose.yml up -d
   ```

2. View logs:
   ```bash
   docker-compose -f docker/docker-compose.yml logs -f
   ```

3. Stop services:
   ```bash
   docker-compose -f docker/docker-compose.yml down
   ```

### Service Details

- **MCP Server**: Secure gRPC server with mTLS authentication
- **Dashboard**: Real-time visualization of traffic and metrics
- **Prometheus**: Metrics collection and storage
- **Grafana**: Advanced metrics visualization and alerting

### Resource Management

Each service has resource limits and reservations:
- MCP Server: 1 CPU, 1GB RAM
- Dashboard: 0.5 CPU, 512MB RAM
- Prometheus: 0.5 CPU, 1GB RAM
- Grafana: 0.5 CPU, 512MB RAM

## ⚙️ Configuration

### Environment Variables

Key environment variables for the MCP server:
```bash
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=50051
MCP_AUTH_TYPE=mtls
MCP_CERT_PATH=/app/certs/server.crt
MCP_KEY_PATH=/app/certs/server.key
MCP_CA_PATH=/app/certs/ca.crt
```

### Configuration Files

- Server config: `config/server.yaml`
- Prometheus config: `config/prometheus/prometheus.yml`
- Grafana config: `config/grafana/provisioning/`

## 🔒 Security

### Certificate Management

1. Generate certificates:
   ```bash
   ./scripts/generate_certs.sh
   ```

2. Update certificates:
   ```bash
   ./scripts/update_certs.sh
   ```

### Security Best Practices

1. Use strong passwords for Grafana
2. Keep certificates secure and regularly rotated
3. Monitor security events in Grafana
4. Use rate limiting for all clients
5. Enable audit logging

## 📊 Monitoring

### Metrics

Key metrics available in Prometheus:
- Request rate
- Response time
- Error rates
- Resource utilization
- Security events

### Dashboards

Pre-configured Grafana dashboards:
- Traffic Overview
- Performance Metrics
- Security Events
- Resource Usage

## 👩‍💻 Development

### Local Development

1. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

2. Run tests:
   ```bash
   pytest tests/
   ```

3. Run benchmarks:
   ```bash
   pytest tests/benchmarks/
   ```

### Code Style

- Use Black for formatting
- Use isort for import sorting
- Use mypy for type checking
- Follow PEP 8 guidelines

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

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
