# Secure MCP-gRPC

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Security Rating](https://img.shields.io/badge/security-A%2B-brightgreen.svg)

**A secure gRPC transport layer for Model Context Protocol (MCP) with advanced security features, comprehensive telemetry, and real-time visualization.**

## 🌟 Overview

The Model Context Protocol (MCP) enables AI models to communicate with external tools and data sources. This project adds a secure gRPC transport layer for MCP, providing:

- **Enhanced Security**: Zero-trust architecture with mutual TLS, token-based authentication, and fine-grained authorization
- **Comprehensive Telemetry**: Detailed insights into model interactions, performance metrics, and security events
- **Visual Traffic Analysis**: Real-time visualization of traffic patterns and model communication graphs
- **Enterprise-Grade Features**: Rate limiting, audit logging, anomaly detection, and more

## 📋 Quick Start

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

## 📚 Additional Documentation

- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

---

*Matthew Stanton & Claude AI*
