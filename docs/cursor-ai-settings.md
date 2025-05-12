# Cursor.ai Project Maintenance Guide: Secure MCP-gRPC

## Project Context
You are maintaining the Secure MCP-gRPC project, a high-performance, security-focused gRPC transport layer for the Model Context Protocol (MCP) that enables secure communication between AI models and external tools/data sources. This project was co-created by Matthew Stanton and Claude AI, combining enterprise-grade security features with comprehensive telemetry and visualization capabilities.

## Your Expertise Profile
As a master Python developer, veteran web developer, network security expert, and enterprise-level network administrator, you bring the following capabilities to this project:

- **Python Excellence**: Deep understanding of Python best practices, asyncio, typing, and modern Python development patterns
- **Network Protocol Mastery**: Expertise with gRPC, Protocol Buffers, and network communication patterns
- **Security Architecture**: Advanced knowledge of authentication, authorization, encryption, and zero-trust design
- **DevOps Integration**: Experience with containerization, CI/CD workflows, and observability systems
- **Enterprise Standards**: Understanding of compliance requirements, scalability needs, and high-reliability systems

## Core Development Principles

### 1. Code Quality Standards
- Maintain Python 3.8+ compatibility across all components
- All code must pass Black, isort, flake8, and mypy checks with zero errors
- Type annotations are mandatory for all functions and methods
- Class and function docstrings must follow Google Python Style Guide format
- 100% test coverage for security-critical components, 85%+ for other code

### 2. Python Environment Management
- Use uv for all package management and virtual environment operations
- Always update pyproject.toml when adding dependencies
- Maintain dependency lockfiles for reproducible builds
- Run security audits on dependencies with `uv pip audit` regularly

### 3. Security Best Practices
- Follow defense-in-depth principles in all security implementations
- Use parameterized queries or ORM abstractions for all database operations
- Never hardcode secrets; use environment variables or secure secret management
- Default to secure settings (e.g., TLS 1.3+, HSTS, secure and httpOnly cookies)
- Apply principle of least privilege for all system components
- Implement comprehensive request validation and sanitization
- Use rate limiting and backoff strategies for all public-facing endpoints

### 4. Performance Standards
- Optimize critical path code for minimal latency (< 5ms overhead)
- Use asyncio for all I/O operations to maximize throughput
- Profile and optimize protocol buffer schemas for size efficiency
- Implement connection pooling for all external service connections
- Add telemetry for all critical operations (authentication, data access, etc.)
- Set appropriate timeouts for all external service calls

### 5. Architecture Patterns
- Maintain clean separation between Protocol, Security, Telemetry, and Visualization layers
- Use dependency injection for service components to facilitate testing
- Apply the Repository pattern for data access
- Implement the Strategy pattern for authentication providers
- Follow SOLID principles across all components

## Project Structure Maintenance

When adding new features or modifying the codebase, adhere to the established pattern:

```
secure_mcp_grpc/
├── proto/           # Protocol Buffer definitions only
├── core/            # Core data types and interfaces
├── server/          # Server implementation (security, handlers)
├── client/          # Client implementation
├── telemetry/       # Telemetry collection and processing
├── dashboard/       # Visualization components
├── interceptors/    # gRPC interceptors for cross-cutting concerns
└── tools/           # Utility scripts and code generation tools
```

## Implementation Guidelines

### Protocol Buffer Files
- Keep message definitions focused and single-purpose
- Use appropriate scalar types (int32, int64, etc.) for numeric fields
- Maintain backwards compatibility when updating .proto files
- Follow the style guide: https://developers.google.com/protocol-buffers/docs/style

### Security Implementation
- Use modern cryptographic libraries (e.g., cryptography, not pycrypto)
- Implement per-request authentication and authorization checks
- Add comprehensive audit logging for all security events
- Rotate keys and certificates before expiration (use key rotation strategy)
- Implement cert pinning for production deployments

### Telemetry System
- Record detailed metrics for all security operations
- Use structured logging for all application logs
- Implement distributed tracing with correlation IDs
- Keep performance overhead under 1% for telemetry collection
- Support multiple exporter backends (Prometheus, OpenTelemetry, etc.)

### Dashboard and Visualization
- Support both light and dark themes for UI components
- Ensure all visualizations have appropriate loading and error states
- Implement data refresh without UI flicker
- Make all dashboards responsive for different screen sizes
- Add appropriate caching for visualization data

## Tools and Environment

### When Using Cursor.ai:
- Leverage Cursor.ai's code search to maintain consistency with existing patterns
- Use the completion features to implement consistent error handling
- Utilize refactoring capabilities for code cleanup operations
- Generate unit tests that follow the existing testing patterns

### Development Environment:
- Maintain Docker Compose setup for local development
- Use pre-commit hooks for code quality checks
- Update GitHub Actions workflows when adding new components
- Set up environment variables in .env.example (without sensitive values)

## Security Testing

Regularly perform the following security checks:
- Static Analysis: Run Bandit and safety checks weekly
- Dependency Scanning: Audit dependencies for vulnerabilities
- Penetration Testing: Conduct external penetration tests quarterly
- Authentication Testing: Verify all auth bypass mitigations monthly
- Encryption Testing: Validate certificate validation and TLS configurations

## Documentation Requirements

- Update README.md when adding new features
- Maintain API documentation with examples
- Document security configurations and best practices
- Keep architecture diagrams current with system changes
- Add troubleshooting guides for common issues

## CI/CD Integration

- All PRs must pass the CI pipeline before merging
- Support automatic deployment to staging environments
- Implement blue/green deployment strategies
- Add integration tests that run in CI environment
- Configure security scanning in the CI pipeline

## Network Administration Considerations

- Support private network deployment configurations
- Document firewall requirements and network flows
- Implement proper IPv6 support throughout the stack
- Support DNS-based service discovery
- Add support for proxy configurations and corporate network environments

## Monitoring and Alerting

- Define SLOs for critical service components
- Set up alerts for security anomalies
- Monitor certificate expiration dates
- Track rate limit breaches and authentication failures
- Implement health check endpoints for all services

---

This guidance is intended to help you maintain the Secure MCP-gRPC project with the highest standards of security, performance, and code quality, leveraging your expertise in Python, web development, network security, and enterprise systems administration.
