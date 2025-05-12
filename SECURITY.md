# Security Policy

## Supported Versions

We currently support the following versions of Secure MCP-gRPC with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅                |
| < 0.1   | ❌                |

## Reporting a Vulnerability

The Secure MCP-gRPC team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose any security concerns.

### How to Report a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them by emailing **security@example.com**. If possible, encrypt your message with our PGP key (available on our website).

Please include the following information in your report:

- Type of vulnerability
- Full path of the affected file(s)
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the vulnerability
- Step-by-step instructions to reproduce the vulnerability
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

This information will help us triage your report more quickly.

### What to Expect

When you report a vulnerability, you will receive an acknowledgment within 48 hours. The Secure MCP-gRPC team will then follow these steps:

1. **Confirmation**: We'll work to confirm the vulnerability and its impact.
2. **Fixes**: We'll develop and test a fix for the vulnerability.
3. **Disclosure**: We'll coordinate disclosure with you once a fix is prepared.

Our goal is to resolve all security issues within 90 days of the initial report.

### Bug Bounty

We currently do not offer a bug bounty program, but we are grateful for your contributions to the security of this project. We will acknowledge all security researchers who report valid vulnerabilities in our release notes.

## Security Best Practices for Users

When using Secure MCP-gRPC, please follow these security best practices:

### Certificate Management

- Use strong, properly generated certificates for mTLS authentication
- Rotate certificates regularly
- Protect private keys with appropriate file permissions
- Use a secure certificate management system for production deployments

### Authentication

- Use the strongest authentication method available for your use case
- If using JWT or OAuth2, use short-lived tokens and implement token rotation
- Validate all claims in authentication tokens, including audience and issuer
- Use asymmetric keys when possible
- Never hardcode credentials in your application code

### Authorization

- Follow the principle of least privilege
- Implement fine-grained access control
- Regularly audit access control rules
- Set default deny policies

### Network Security

- Limit network exposure to trusted networks when possible
- Use secure TLS configurations with modern cipher suites
- Implement IP-based access controls where appropriate
- Consider using a reverse proxy or API gateway for additional security

### Logging and Monitoring

- Enable comprehensive audit logging
- Monitor for suspicious activity patterns
- Set up alerts for security events
- Regularly review security logs

### Updating

- Keep Secure MCP-gRPC updated to the latest supported version
- Update dependencies regularly
- Subscribe to security announcements

## Vulnerability Disclosure Policy

Our vulnerability disclosure policy is as follows:

1. Security vulnerabilities will be patched as quickly as possible.
2. A security advisory will be published for all confirmed vulnerabilities.
3. CVE IDs will be requested for significant security issues.
4. Credit will be given to the reporter unless they wish to remain anonymous.

## Security Contacts

For any security-related questions or concerns, please contact:

- **Security Team**: security@example.com
- **Project Lead**: Matthew Stanton (matthew@example.com)

---

This security policy was last updated on May 11, 2025.

*Matthew Stanton & Claude AI*
