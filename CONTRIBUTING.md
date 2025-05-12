# Contributing to Secure MCP-gRPC

Thank you for your interest in contributing to Secure MCP-gRPC! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Getting Started

### Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/yourusername/secure-mcp-grpc.git
   cd secure-mcp-grpc
   ```

3. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

4. Generate Protocol Buffer code:
   ```bash
   python -m secure_mcp_grpc.tools.generate_protos
   ```

5. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following the code style guidelines

3. Run tests to ensure your changes don't break existing functionality:
   ```bash
   pytest
   ```

4. Run code quality checks:
   ```bash
   black .
   isort .
   flake8 .
   mypy .
   ```

5. Commit your changes with a descriptive commit message:
   ```bash
   git commit -m "Add feature: your feature description"
   ```

6. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

7. Create a pull request from your fork to the main repository

## Pull Request Process

1. Ensure all tests pass and code quality checks succeed
2. Update documentation to reflect any changes
3. Add your changes to the CHANGELOG.md file
4. Add your name to CONTRIBUTORS.md if you're not already listed
5. The maintainers will review your PR, provide feedback, and merge when ready

## Code Style Guidelines

This project follows these coding standards:

- **Python**: We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:
  - Line length: 100 characters
  - Use [Black](https://black.readthedocs.io/) for code formatting
  - Use [isort](https://pycqa.github.io/isort/) for import sorting
  - Use [Flake8](https://flake8.pycqa.org/) for linting
  - Use [MyPy](https://mypy.readthedocs.io/) for type checking

- **Documentation**: We use [Google-style docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for Python code.

- **Commit Messages**: Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

## Testing Guidelines

- Write unit tests for all new functionality
- Ensure tests are fast, reliable, and independent
- Use pytest fixtures to reduce test setup boilerplate
- Write integration tests for components that interact with external systems
- Include both positive and negative test cases
- Aim for at least 80% code coverage

## Documentation Guidelines

- Document all public APIs
- Update README.md for significant features
- Add or update docstrings for classes and functions
- Include examples for complex functionality
- Document security implications of features

## Security Guidelines

Since this is a security-focused project, please follow these additional guidelines:

- Never commit credentials, even in tests
- Use secure defaults for all security features
- Document security assumptions and limitations
- Handle sensitive data carefully (tokens, certificates, etc.)
- Consider the implications of your changes on the security model

## Feature Requests and Bug Reports

Please use GitHub Issues to report bugs or request features. For security vulnerabilities, please follow our [Security Policy](SECURITY.md).

When reporting a bug, please include:
- A clear description of the issue
- Steps to reproduce
- Expected and actual behavior
- Environment information (OS, Python version, etc.)

## Licensing

By contributing to this project, you agree that your contributions will be licensed under the project's [Apache 2.0 License](LICENSE).

## Contact

If you have questions or need help, you can:
- Open an issue on GitHub
- Reach out to the maintainers directly

Thank you for contributing to Secure MCP-gRPC!

---

*Matthew Stanton & Claude AI*
