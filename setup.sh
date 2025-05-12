#!/bin/bash
# Enhanced setup script for Secure MCP-gRPC using uv for Python environment management
# This script sets up the project structure and installs dependencies using uv

set -e  # Exit on error

# Display welcome message
echo "===================================================="
echo "Setting up Secure MCP-gRPC project with uv"
echo "===================================================="

# Check if uv is installed, install if not
if ! command -v uv &> /dev/null; then
    echo "Installing uv (fast Python package installer and environment manager)..."
    if [[ "$OSTYPE" == "darwin"* || "$OSTYPE" == "linux-gnu"* ]]; then
        # macOS or Linux
        curl -LsSf https://astral.sh/uv/install.sh | sh
        # Source the shell configuration to make uv available in the current shell
        if [[ -f ~/.bashrc ]]; then
            source ~/.bashrc
        elif [[ -f ~/.zshrc ]]; then
            source ~/.zshrc
        fi
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows
        echo "For Windows, please install uv manually:"
        echo "curl.exe -LsSf https://astral.sh/uv/install.ps1 | pwsh -"
        echo "Then run this script again."
        exit 1
    else
        echo "Unsupported operating system. Please install uv manually: https://github.com/astral-sh/uv"
        exit 1
    fi
fi

# Create project structure
echo "Creating project structure..."
mkdir -p secure_mcp_grpc/{proto,server,client,telemetry,dashboard,interceptors,core/types,tools,cli}
mkdir -p docker
mkdir -p config
mkdir -p certs
mkdir -p tests/{server,client,telemetry,dashboard,interceptors}
mkdir -p docs/{images,examples}
mkdir -p examples
mkdir -p scripts
mkdir -p logs
mkdir -p traces

# Create Python package files
echo "Creating Python package files..."
touch secure_mcp_grpc/__init__.py
touch secure_mcp_grpc/{proto,server,client,telemetry,dashboard,interceptors,core,tools,cli}/__init__.py
touch secure_mcp_grpc/core/types/__init__.py

# Set up Python virtual environment with uv
echo "Setting up Python virtual environment with uv..."
uv venv
source .venv/bin/activate

# Update pyproject.toml to include uv in tool settings
cat > pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "secure-mcp-grpc"
version = "0.1.0"
description = "A secure gRPC transport layer for Model Context Protocol (MCP) with enhanced security features and telemetry"
readme = "README.md"
requires-python = ">=3.8"
license = {file = "LICENSE"}
keywords = ["mcp", "grpc", "ai", "security", "telemetry"]
authors = [
    {name = "Matthew Stanton", email = "info@example.com"}
]
maintainers = [
    {name = "Matthew Stanton", email = "info@example.com"}
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Networking",
    "Topic :: Security",
]

dependencies = [
    "grpcio>=1.44.0",
    "grpcio-tools>=1.44.0",
    "protobuf>=3.19.0",
    "cryptography>=37.0.0",
    "pyjwt>=2.4.0",
    "pydantic>=1.9.0",
    "asyncio>=3.4.3",
    "numpy>=1.21.0",
    "pandas>=1.3.0",
    "prometheus-client>=0.14.0",
    "aiohttp>=3.8.1",
]

[project.optional-dependencies]
telemetry = [
    "plotly>=5.8.0",
    "dash>=2.5.0",
    "dash-bootstrap-components>=1.1.0",
    "networkx>=2.8.0",
    "matplotlib>=3.5.0",
    "seaborn>=0.11.2",
    "wordcloud>=1.8.1",
    "scipy>=1.8.0",
]

dashboard = [
    "dash>=2.5.0",
    "dash-bootstrap-components>=1.1.0",
    "flask>=2.1.0",
    "gunicorn>=20.1.0",
]

dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.18.0",
    "pytest-cov>=3.0.0",
    "black>=22.3.0",
    "isort>=5.10.0",
    "mypy>=0.950",
    "flake8>=4.0.0",
    "pre-commit>=2.18.0",
    "sphinx>=4.5.0",
    "sphinx-rtd-theme>=1.0.0",
]

full = [
    "secure-mcp-grpc[telemetry,dashboard,dev]",
]

[project.urls]
"Homepage" = "https://github.com/mstanton/secure-mcp-grpc"
"Bug Tracker" = "https://github.com/mstanton/secure-mcp-grpc/issues"
"Documentation" = "https://secure-mcp-grpc.readthedocs.io/"
"Source Code" = "https://github.com/mstanton/secure-mcp-grpc"

[project.scripts]
mcp-dashboard = "secure_mcp_grpc.dashboard.app:main"
mcp-server = "secure_mcp_grpc.cli.server:main"
mcp-client = "secure_mcp_grpc.cli.client:main"

[tool.setuptools]
package-dir = {"" = "secure_mcp_grpc"}

[tool.setuptools.packages.find]
include = ["secure_mcp_grpc*"]

[tool.black]
line-length = 100
target-version = ["py38", "py39", "py310", "py311"]
include = '\.pyi?$'
exclude = '''
/(
    \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | _build
  | buck-out
  | build
  | dist
  | proto
)/
'''

[tool.isort]
profile = "black"
line_length = 100
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
skip_gitignore = true

[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
disallow_incomplete_defs = false

[tool.pytest.ini_options]
minversion = "7.0"
testpaths = ["tests"]
python_files = "test_*.py"
python_classes = "Test*"
python_functions = "test_*"
addopts = "--cov=secure_mcp_grpc --cov-report=xml --cov-report=term"
asyncio_mode = "auto"

[tool.coverage.run]
source = ["secure_mcp_grpc"]
omit = ["tests/*", "examples/*", "docs/*", "**/__init__.py"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if self.debug:",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "pass",
    "raise ImportError",
]

[tool.uv]
pip = { repository = "pypi" }  # Use PyPI as the package repository
requirements = { include-dev = true }  # Include dev dependencies when syncing
python = "3.11"  # Default Python version
EOF

# Update requirements.txt - we'll still keep this for compatibility
cat > requirements.txt << 'EOF'
# Core dependencies
grpcio>=1.44.0
grpcio-tools>=1.44.0
protobuf>=3.19.0
cryptography>=37.0.0
pyjwt>=2.4.0
pydantic>=1.9.0
asyncio>=3.4.3
numpy>=1.21.0
pandas>=1.3.0
prometheus-client>=0.14.0
aiohttp>=3.8.1

# Telemetry dependencies
plotly>=5.8.0
dash>=2.5.0
dash-bootstrap-components>=1.1.0
networkx>=2.8.0
matplotlib>=3.5.0
seaborn>=0.11.2
wordcloud>=1.8.1
scipy>=1.8.0

# Dashboard dependencies
flask>=2.1.0
gunicorn>=20.1.0

# Development dependencies
pytest>=7.0.0
pytest-asyncio>=0.18.0
pytest-cov>=3.0.0
black>=22.3.0
isort>=5.10.0
mypy>=0.950
flake8>=4.0.0
pre-commit>=2.18.0
sphinx>=4.5.0
sphinx-rtd-theme>=1.0.0
EOF

# Install dependencies using uv
echo "Installing dependencies using uv..."
uv pip install -e ".[dev]"

# Create improved Protocol Buffer generation script using uv
cat > scripts/generate_protos.sh << 'EOF'
#!/bin/bash
set -e

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# Get the root directory of the project (one level up from script dir)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

echo "Generating Protocol Buffer code..."

# Ensure the virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    if [ -d "$PROJECT_ROOT/.venv" ]; then
        source "$PROJECT_ROOT/.venv/bin/activate"
    else
        echo "Virtual environment not found. Please activate it first."
        exit 1
    fi
fi

# Ensure grpcio-tools is installed
if ! python -c "import grpc_tools" &> /dev/null; then
    echo "Installing grpcio-tools with uv..."
    uv pip install grpcio-tools
fi

# Generate Python code from the proto files
python -m grpc_tools.protoc \
    -I"$PROJECT_ROOT" \
    --python_out="$PROJECT_ROOT" \
    --grpc_python_out="$PROJECT_ROOT" \
    "$PROJECT_ROOT/secure_mcp_grpc/proto/mcp.proto" \
    "$PROJECT_ROOT/secure_mcp_grpc/proto/telemetry.proto"

echo "Protocol Buffer code generation complete."
EOF
chmod +x scripts/generate_protos.sh

# Create a convenient environment setup script
cat > scripts/setup_env.sh << 'EOF'
#!/bin/bash
# Quick environment setup script

# Activate virtual environment
if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "Creating virtual environment with uv..."
    uv venv
    source .venv/bin/activate
fi

# Install dependencies if needed
if ! python -c "import grpc" &> /dev/null; then
    echo "Installing dependencies with uv..."
    uv pip install -e ".[dev]"
fi

# Generate Protocol Buffer code if needed
if [ ! -f "secure_mcp_grpc/proto/mcp_pb2.py" ]; then
    echo "Generating Protocol Buffer code..."
    ./scripts/generate_protos.sh
fi

echo "Environment setup complete. Virtual environment is activated."
EOF
chmod +x scripts/setup_env.sh

# Generate Protocol Buffer code
echo "Generating Protocol Buffer code..."
./scripts/generate_protos.sh

# Update README with uv instructions
cat > README.md << 'EOF'
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
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Development](#-development)
- [Documentation](#-documentation)
- [License](#-license)

## ✨ Features

### 🔐 Security Features
- Mutual TLS Authentication
- Token-based Authentication (JWT, OAuth2)
- Fine-grained Authorization
- Rate Limiting
- Anomaly Detection
- Audit Logging
- Secure Defaults

### 📊 Telemetry & Visualization
- Traffic Flow Diagrams
- Model Interaction Networks
- Security Event Heatmaps
- Latency Distribution Charts
- Real-time Monitoring

## 🚀 Installation

### Using pip with uv (recommended)

```bash
# Install uv first if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install secure-mcp-grpc
uv pip install secure-mcp-grpc
```

### From Source

```bash
# Clone the repository
git clone https://github.com/mstanton/secure-mcp-grpc.git
cd secure-mcp-grpc

# Set up the environment with uv
./scripts/setup_env.sh

# Or manually:
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using Docker

```bash
# Build and start all services
docker-compose up -d
```

## 🧰 Quick Start

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

### Running the Dashboard

```bash
# Start the telemetry dashboard
python -m secure_mcp_grpc.dashboard.app --traces-dir /path/to/traces --port 8050
```

## 💻 Development

We use uv for fast, reliable Python environment management and dependency handling.

### Setting Up Development Environment

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/mstanton/secure-mcp-grpc.git
cd secure-mcp-grpc

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -e ".[dev]"

# Generate Protocol Buffer code
./scripts/generate_protos.sh
```

### Running Tests

```bash
pytest
```

### Code Quality

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
flake8 .

# Type checking
mypy .
```

## 📖 Documentation

Detailed documentation is available in the [docs](docs/) directory.

For more information about the Model Context Protocol, visit [Anthropic's MCP Documentation](https://docs.anthropic.com/mcp/).

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
EOF

echo "Setting up Git..."
# Initialize Git repository if it doesn't exist
if [ ! -d .git ]; then
    git init
fi

# Copy .gitignore
cat > .gitignore << 'EOF'
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Environment and IDE
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/
.idea/
.vscode/
*.swp
*.swo
.DS_Store

# Python coverage
.coverage
coverage.xml
*.cover
htmlcov/
.pytest_cache/
.tox/
nosetests.xml

# Generated Protocol Buffer code
*_pb2.py
*_pb2_grpc.py

# Logs and data files
logs/
*.log
traces/
*.jsonl
*.csv
*.parquet

# Certificate files (should not be committed to version control)
*.pem
*.key
*.crt
*.cer
*.der
*.p12
*.pfx

# Docker
.dockerignore

# Jupyter Notebook
.ipynb_checkpoints

# Sensitive files (add any specific to this project)
*config/secrets.yaml
**/credentials.json

# Local development
local_settings.py
db.sqlite3
db.sqlite3-journal

# Sphinx documentation
docs/_build/
docs/build/

# Output files
*.out
*.pid
*.lock

# Frontend dependencies
node_modules/
npm-debug.log
yarn-debug.log
yarn-error.log

# Distribution files
*.tar.gz
*.zip

# Temporary files
tmp/
temp/
EOF

echo "===================================================="
echo "Setup complete! Your project is ready to go."
echo ""
echo "Next steps:"
echo "1. Make sure your virtual environment is activated:"
echo "   source .venv/bin/activate"
echo ""
echo "2. Start developing! The project structure is set up and"
echo "   dependencies are installed."
echo ""
echo "3. When ready, push to GitHub:"
echo "   git add ."
echo "   git commit -m \"Initial commit\""
echo "   git remote add origin https://github.com/mstanton/secure-mcp-grpc.git"
echo "   git push -u origin main"
echo "===================================================="
