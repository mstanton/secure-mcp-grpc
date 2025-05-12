#!/bin/bash
# Run all linters and code quality checks

set -e  # Exit on error

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# Get the root directory of the project (one level up from script dir)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# Make sure we're in the project root
cd "$PROJECT_ROOT"

# Ensure the virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    if [ -d "$PROJECT_ROOT/.venv" ]; then
        source "$PROJECT_ROOT/.venv/bin/activate"
    else
        echo "Virtual environment not found. Please activate it first."
        exit 1
    fi
fi

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Running code quality checks...${NC}"

# Format with Black
echo -e "\n${YELLOW}Running Black formatter...${NC}"
if black --check .; then
    echo -e "${GREEN}✓ Black check passed${NC}"
else
    echo -e "${RED}✗ Black check failed${NC}"
    echo -e "${YELLOW}Running Black to format code...${NC}"
    black .
    echo -e "${GREEN}✓ Code formatted with Black${NC}"
fi

# Sort imports with isort
echo -e "\n${YELLOW}Running isort...${NC}"
if isort --check .; then
    echo -e "${GREEN}✓ isort check passed${NC}"
else
    echo -e "${RED}✗ isort check failed${NC}"
    echo -e "${YELLOW}Running isort to sort imports...${NC}"
    isort .
    echo -e "${GREEN}✓ Imports sorted with isort${NC}"
fi

# Lint with flake8
echo -e "\n${YELLOW}Running flake8...${NC}"
if flake8 .; then
    echo -e "${GREEN}✓ flake8 check passed${NC}"
else
    echo -e "${RED}✗ flake8 check failed${NC}"
    echo -e "${YELLOW}Please fix the issues reported by flake8${NC}"
fi

# Type check with mypy
echo -e "\n${YELLOW}Running mypy...${NC}"
if mypy secure_mcp_grpc; then
    echo -e "${GREEN}✓ mypy check passed${NC}"
else
    echo -e "${RED}✗ mypy check failed${NC}"
    echo -e "${YELLOW}Please fix the type issues reported by mypy${NC}"
fi

# Run security audit with bandit
echo -e "\n${YELLOW}Running security check with bandit...${NC}"
if command -v bandit &> /dev/null; then
    if bandit -r secure_mcp_grpc; then
        echo -e "${GREEN}✓ bandit security check passed${NC}"
    else
        echo -e "${RED}✗ bandit security check failed${NC}"
        echo -e "${YELLOW}Please fix the security issues reported by bandit${NC}"
    fi
else
    echo -e "${YELLOW}bandit not found. Install with: uv pip install bandit${NC}"
fi

echo -e "\n${BLUE}Code quality check complete!${NC}"
