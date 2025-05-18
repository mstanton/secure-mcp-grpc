# Contributing to Secure MCP-gRPC

Thank you for your interest in contributing to Secure MCP-gRPC! This document provides guidelines for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-mcp-grpc.git
   cd secure-mcp-grpc
   ```

2. Set up development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   python -m secure_mcp_grpc.tools.generate_protos
   pre-commit install
   ```

## Development Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make changes following code style guidelines

3. Run quality checks:
   ```bash
   pytest
   black .
   isort .
   flake8 .
   mypy .
   ```

4. Commit and push:
   ```bash
   git commit -m "Add feature: your feature description"
   git push origin feature/your-feature-name
   ```

5. Create a pull request

## Code Style

- **Python**: Follow PEP 8 with modifications:
  - Line length: 100 characters
  - Use Black for formatting
  - Use isort for import sorting
  - Use Flake8 for linting
  - Use MyPy for type checking

- **Documentation**: Use Google-style docstrings

- **Commit Messages**: Follow Conventional Commits specification

## Testing Guidelines

- Write unit tests for new functionality
- Ensure tests are fast and reliable
- Use pytest fixtures
- Write integration tests for external interactions
- Include positive and negative test cases
- Aim for 80% code coverage

## Documentation Guidelines

- Document all public APIs
- Update README.md for significant features
- Add/update docstrings
- Include examples for complex functionality
- Document security implications

## Security Guidelines

- Never commit credentials
- Use secure defaults
- Document security assumptions
- Handle sensitive data carefully
- Consider security implications

## Feature Requests and Bug Reports

Use GitHub Issues for bugs and features. For security vulnerabilities, follow our [Security Policy](SECURITY.md).

Include in bug reports:
- Clear description
- Reproduction steps
- Expected vs actual behavior
- Environment information

## License

Contributions will be licensed under the project's [Apache 2.0 License](LICENSE).

## Contact

- Open an issue on GitHub
- Contact maintainers directly

---

*Matthew Stanton & Claude AI*
