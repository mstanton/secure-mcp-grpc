# Secure MCP-gRPC

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Security Rating](https://img.shields.io/badge/security-A%2B-brightgreen.svg)

**A secure gRPC transport layer for Model Context Protocol (MCP) with advanced security features, comprehensive telemetry, and real-time visualization.**

## 🌟 Overview

The Model Context Protocol (MCP) enables AI models to communicate with external tools and data sources. This project adds a secure gRPC transport layer for MCP, providing:

- **Enhanced Security**: Zero-trust architecture with multiple authentication methods (mTLS, JWT, OAuth2, API Key), fine-grained authorization, and comprehensive security controls
- **Comprehensive Telemetry**: Detailed insights into model interactions, performance metrics, and security events
- **Visual Traffic Analysis**: Real-time visualization of traffic patterns and model communication graphs
- **Enterprise-Grade Features**: Advanced rate limiting, session management, audit logging, anomaly detection, and more

## 🔒 Security Features

### Authentication & Authorization
- Multiple authentication methods:
  - Mutual TLS (mTLS) with certificate validation
  - JWT tokens with configurable claims and validation
  - OAuth2 integration with scope validation
  - API key authentication with secure storage
- Fine-grained authorization with role-based access control
- Account lockout after failed attempts
- Session management with configurable timeouts
- IP-based access control and blocking

### Request Security
- Request validation and sanitization
- Size limits and rate limiting per client
- Method access control
- Security headers for HTTP/2 transport
- CORS policies with origin validation
- TLS configuration with modern cipher suites

### Monitoring & Auditing
- Comprehensive security event logging
- Real-time security monitoring
- Audit trail for all security events
- Performance metrics and anomaly detection
- Telemetry integration for security insights

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
                          │   Security      │
                          │   Middleware    │
                          └─────────┬───────┘
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
# Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=50051

# Authentication
MCP_AUTH_TYPE=mtls  # Options: mtls, jwt, oauth2, api_key
MCP_JWT_SECRET=your-secret-key
MCP_JWT_AUDIENCE=your-audience
MCP_JWT_ISSUER=your-issuer

# TLS Configuration
MCP_CERT_PATH=/app/certs/server.crt
MCP_KEY_PATH=/app/certs/server.key
MCP_CA_PATH=/app/certs/ca.crt

# Security Settings
MCP_MAX_REQUEST_SIZE=1048576  # 1MB
MCP_RATE_LIMIT=100  # requests per minute
MCP_SESSION_TIMEOUT=3600  # 1 hour
MCP_MAX_SESSIONS_PER_IP=100
MCP_MAX_FAILED_ATTEMPTS=5
MCP_ACCOUNT_LOCKOUT_DURATION=1800  # 30 minutes
```

### Security Configuration

The security configuration is managed through `security_config.py` and includes:

```python
# Example security configuration
security_config = SecurityConfig(
    max_request_size=1024 * 1024,  # 1MB
    max_sessions_per_ip=100,
    session_timeout=3600,  # 1 hour
    rate_limit=100,  # requests per minute
    allowed_methods={"Call", "Reflect", "HealthStream"},
    require_mtls=True,
    jwt_secret="your-secret-key",
    jwt_audience="your-audience",
    jwt_issuer="your-issuer",
    audit_logging=True
)
```

## 🔒 Security Best Practices

1. **Certificate Management**
   - Generate certificates using the provided script:
     ```bash
     ./scripts/generate_certs.sh
     ```
   - Regularly rotate certificates:
     ```bash
     ./scripts/update_certs.sh
     ```

2. **Authentication**
   - Use strong, unique API keys
   - Implement proper JWT token management
   - Configure OAuth2 with appropriate scopes
   - Enable mTLS for all production deployments

3. **Access Control**
   - Implement least privilege principle
   - Use IP-based access control
   - Configure rate limits appropriately
   - Enable session management

4. **Monitoring**
   - Monitor security events in Grafana
   - Set up alerts for suspicious activities
   - Review audit logs regularly
   - Track failed authentication attempts

## 📊 Monitoring

### Security Metrics

Key security metrics available in Prometheus:
- Authentication success/failure rates
- Rate limit violations
- Session statistics
- IP blocking events
- Security event counts
- Response time distributions
- Error rates by type

### Security Dashboards

Pre-configured Grafana dashboards:
- Security Overview
- Authentication Analytics
- Rate Limiting Statistics
- Session Management
- IP Access Patterns
- Security Event Timeline

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

3. Run security tests:
   ```bash
   pytest tests/security/
   ```

4. Run benchmarks:
   ```bash
   pytest tests/benchmarks/
   ```

## 📚 Additional Documentation

- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Configuration Guide](docs/security-configuration.md)
- [Authentication Guide](docs/authentication.md)
- [Monitoring Guide](docs/monitoring.md)

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

---

*Matthew Stanton & Claude AI*
