# Security Policy

## Supported Versions

We currently support the following versions of Secure MCP-gRPC with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅                |
| < 0.1   | ❌                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report security vulnerabilities by emailing **security@example.com**. If possible, encrypt your message with our PGP key.

Include in your report:
- Type of vulnerability
- Affected file(s) and code location
- Steps to reproduce
- Impact assessment
- Proof-of-concept (if available)

## Security Best Practices

### Certificate Management
- Use strong certificates for mTLS authentication
- Rotate certificates regularly
- Protect private keys with appropriate permissions
- Use secure certificate management in production

### Authentication
- Use strongest available authentication method
- Implement token rotation for JWT/OAuth2
- Validate all token claims
- Use asymmetric keys when possible
- Never hardcode credentials

### Authorization
- Follow principle of least privilege
- Implement fine-grained access control
- Regular access control audits
- Set default deny policies

### Network Security
- Limit network exposure to trusted networks
- Use secure TLS configurations
- Implement IP-based access controls
- Consider using a reverse proxy

### Logging and Monitoring
- Enable comprehensive audit logging
- Monitor for suspicious activity
- Set up security event alerts
- Regular security log reviews

### Updates
- Keep Secure MCP-gRPC updated
- Regular dependency updates
- Subscribe to security announcements

## Vulnerability Disclosure

1. Security vulnerabilities will be patched promptly
2. Security advisories will be published
3. CVE IDs will be requested for significant issues
4. Credit will be given to reporters (unless anonymous)

## Security Contacts

- **Security Team**: security@example.com
- **Project Lead**: Matthew Stanton (matthew@example.com)

---

*Last updated: May 11, 2025*

*Matthew Stanton & Claude AI*
