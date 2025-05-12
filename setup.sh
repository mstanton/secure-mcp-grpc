#!/bin/bash
# Enhanced setup script for Secure MCP-gRPC using uv for Python environment management
# This script sets up the project structure and installs dependencies using uv

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print with color
print_step() {
    echo -e "${GREEN}==>${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}Warning:${NC} $1"
}

print_error() {
    echo -e "${RED}Error:${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_warning "Please do not run this script as root"
    exit 1
fi

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_warning "Python 3 is not installed. Some development features may not work."
    fi
    
    # Check OpenSSL
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL is not installed. Please install OpenSSL first."
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    print_step "Creating necessary directories..."
    
    mkdir -p config/prometheus
    mkdir -p config/grafana/provisioning/datasources
    mkdir -p config/grafana/provisioning/dashboards
    mkdir -p certs
    mkdir -p logs
    mkdir -p traces
}

# Generate certificates
generate_certificates() {
    print_step "Generating SSL certificates..."
    
    # Generate CA key and certificate
    openssl genrsa -out certs/ca.key 4096
    openssl req -new -x509 -key certs/ca.key -out certs/ca.crt -days 365 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=Secure MCP CA"
    
    # Generate server key and CSR
    openssl genrsa -out certs/server.key 2048
    openssl req -new -key certs/server.key -out certs/server.csr \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    
    # Sign server certificate
    openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
        -CAcreateserial -out certs/server.crt -days 365
    
    # Generate client key and CSR
    openssl genrsa -out certs/client.key 2048
    openssl req -new -key certs/client.key -out certs/client.csr \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=client"
    
    # Sign client certificate
    openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
        -CAcreateserial -out certs/client.crt -days 365
    
    # Set proper permissions
    chmod 600 certs/*.key
    chmod 644 certs/*.crt
}

# Create Prometheus configuration
create_prometheus_config() {
    print_step "Creating Prometheus configuration..."
    
    cat > config/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'mcp-server'
    static_configs:
      - targets: ['mcp-server:50051']
    metrics_path: '/metrics'

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF
}

# Create Grafana datasource configuration
create_grafana_datasource() {
    print_step "Creating Grafana datasource configuration..."
    
    cat > config/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
EOF
}

# Create Grafana dashboard configuration
create_grafana_dashboard() {
    print_step "Creating Grafana dashboard configuration..."
    
    cat > config/grafana/provisioning/dashboards/dashboards.yml << EOF
apiVersion: 1

providers:
  - name: 'Default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF
}

# Create server configuration
create_server_config() {
    print_step "Creating server configuration..."
    
    cat > config/server.yaml << EOF
server:
  host: "0.0.0.0"
  port: 50051

security:
  auth:
    type: "mtls"
    mtls:
      cert_path: "/app/certs/server.crt"
      key_path: "/app/certs/server.key"
      ca_path: "/app/certs/ca.crt"
  
  rate_limit:
    enabled: true
    requests_per_minute: 1000
  
  audit_logging:
    enabled: true
    path: "/app/logs/audit.log"

telemetry:
  enabled: true
  exporter: "prometheus"
  traces_dir: "/app/traces"
EOF
}

# Main setup process
main() {
    print_step "Starting setup process..."
    
    check_prerequisites
    create_directories
    generate_certificates
    create_prometheus_config
    create_grafana_datasource
    create_grafana_dashboard
    create_server_config
    
    print_step "Setup completed successfully!"
    echo -e "\nTo start the services, run:"
    echo -e "  ${GREEN}docker-compose -f docker/docker-compose.yml up -d${NC}"
    echo -e "\nAccess the services at:"
    echo -e "  - Dashboard: ${GREEN}http://localhost:8050${NC}"
    echo -e "  - Grafana: ${GREEN}http://localhost:3000${NC}"
    echo -e "  - Prometheus: ${GREEN}http://localhost:9090${NC}"
}

# Run main function
main
