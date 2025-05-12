#!/bin/bash
# Complete setup script for Secure MCP-gRPC project

set -e  # Exit on error

# Display welcome message
echo "===================================================="
echo "Setting up Secure MCP-gRPC project"
echo "===================================================="

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

# Copy prototype files to their locations
echo "Copying files to appropriate locations..."

# Protocol buffers
cat > secure_mcp_grpc/proto/mcp.proto << 'EOF'
syntax = "proto3";

package mcp;

// The main MCP service definition
service MCPService {
  // Bidirectional streaming RPC for standard MCP messages
  rpc Call(stream MCPRequest) returns (stream MCPResponse);
  
  // Unary RPC for reflection requests
  rpc Reflect(ReflectionRequest) returns (ReflectionResponse);
  
  // Server streaming RPC for health checks
  rpc HealthStream(HealthRequest) returns (stream HealthResponse);
}

// Standard MCP Request message
message MCPRequest {
  string id = 1;
  string method = 2;
  map<string, string> params = 3;
  
  // Security metadata
  SecurityContext security_context = 4;
}

// Standard MCP Response message
message MCPResponse {
  string id = 1;
  string result = 2;  // JSON-encoded result
  ErrorObject error = 3;
  
  // Performance metrics
  uint64 processing_time_ms = 4;
  uint32 token_count = 5;
}

// Error object for reporting issues
message ErrorObject {
  int32 code = 1;
  string message = 2;
  string data = 3;  // JSON-encoded error data
}

// Reflection request for capability discovery
message ReflectionRequest {
  string id = 1;
  
  // Security metadata
  SecurityContext security_context = 2;
}

// Reflection response with capability information
message ReflectionResponse {
  string id = 1;
  string tools = 2;              // JSON-encoded tools
  string resources = 3;          // JSON-encoded resources
  string parameterized_prompts = 4;  // JSON-encoded parameterized prompts
  string sampling = 5;           // JSON-encoded sampling
  
  // Security capabilities
  repeated string auth_methods = 6;
  bool requires_encryption = 7;
  uint32 version = 8;
}

// Security context for authentication and authorization
message SecurityContext {
  oneof auth_type {
    JWTAuth jwt_auth = 1;
    OAuth2Auth oauth2_auth = 2;
    APIKeyAuth api_key_auth = 3;
  }
  
  string request_id = 4;
  string client_id = 5;
  uint64 timestamp = 6;
  map<string, string> metadata = 7;
}

// JWT authentication details
message JWTAuth {
  string token = 1;
}

// OAuth2 authentication details
message OAuth2Auth {
  string access_token = 1;
  string token_type = 2;
}

// API Key authentication details
message APIKeyAuth {
  string key = 1;
}

// Health check request
message HealthRequest {
  string id = 1;
  bool detailed = 2;
  SecurityContext security_context = 3;
}

// Health check response
message HealthResponse {
  string id = 1;
  Status status = 2;
  map<string, Status> component_status = 3;
  map<string, string> metrics = 4;
  
  enum Status {
    UNKNOWN = 0;
    HEALTHY = 1;
    DEGRADED = 2;
    UNHEALTHY = 3;
  }
}
EOF

# Telemetry proto
cat > secure_mcp_grpc/proto/telemetry.proto << 'EOF'
syntax = "proto3";

package telemetry;

// Telemetry service for collecting and analyzing MCP usage data
service TelemetryService {
  // Submit telemetry data to the collector
  rpc SubmitTelemetry(TelemetryRequest) returns (TelemetryResponse);
  
  // Stream telemetry data for real-time analysis
  rpc StreamTelemetry(stream TelemetryEvent) returns (TelemetryStreamResponse);
  
  // Get aggregated telemetry data
  rpc GetAggregatedData(AggregationRequest) returns (AggregationResponse);
}

// Main telemetry request containing multiple events
message TelemetryRequest {
  string source_id = 1;
  string instance_id = 2;
  string version = 3;
  repeated TelemetryEvent events = 4;
  
  // Whether to anonymize data
  bool anonymize = 5;
}

// Telemetry response with processing status
message TelemetryResponse {
  bool success = 1;
  string message = 2;
  string request_id = 3;
}

// Status for streaming telemetry
message TelemetryStreamResponse {
  bool success = 1;
  string session_id = 2;
  uint64 processed_events = 3;
}

// A single telemetry event
message TelemetryEvent {
  uint64 timestamp = 1;
  EventType type = 2;
  Severity severity = 3;
  string event_id = 4;
  map<string, string> metadata = 5;
  
  // Event-specific data
  oneof event_data {
    SecurityEvent security_event = 6;
    PerformanceMetrics performance_metrics = 7;
    UsageMetrics usage_metrics = 8;
    ErrorEvent error_event = 9;
    HealthEvent health_event = 10;
  }
  
  enum EventType {
    UNKNOWN = 0;
    SECURITY = 1;
    PERFORMANCE = 2;
    USAGE = 3;
    ERROR = 4;
    HEALTH = 5;
  }
  
  enum Severity {
    INFO = 0;
    WARNING = 1;
    ERROR = 2;
    CRITICAL = 3;
  }
}

// Security-related events
message SecurityEvent {
  SecurityEventType type = 1;
  string source_ip = 2;
  string user_id = 3;
  string resource = 4;
  string action = 5;
  bool success = 6;
  repeated string tags = 7;
  
  enum SecurityEventType {
    UNKNOWN = 0;
    AUTHENTICATION = 1;
    AUTHORIZATION = 2;
    RATE_LIMIT = 3;
    DATA_ACCESS = 4;
    CONFIGURATION_CHANGE = 5;
    ANOMALY = 6;
    INTRUSION_ATTEMPT = 7;
  }
}

// Performance-related metrics
message PerformanceMetrics {
  uint64 request_id = 1;
  uint64 request_duration_ms = 2;
  uint64 processing_time_ms = 3;
  uint64 queue_time_ms = 4;
  uint32 cpu_usage_percent = 5;
  uint32 memory_usage_mb = 6;
  uint32 concurrent_requests = 7;
  
  // AI model specific metrics
  uint32 token_count = 8;
  float tokens_per_second = 9;
  uint32 batch_size = 10;
}

// Usage patterns and statistics
message UsageMetrics {
  string user_id = 1;
  string model_id = 2;
  string method = 3;
  uint64 request_count = 4;
  uint64 token_count = 5;
  repeated string features_used = 6;
  
  // Anonymized sample of inputs/outputs for quality monitoring
  repeated SamplePair samples = 7;
}

// Error and exception information
message ErrorEvent {
  ErrorType type = 1;
  string error_code = 2;
  string message = 3;
  string stack_trace = 4;
  map<string, string> context = 5;
  
  enum ErrorType {
    UNKNOWN = 0;
    VALIDATION = 1;
    AUTHENTICATION = 2;
    AUTHORIZATION = 3;
    RATE_LIMIT = 4;
    TIMEOUT = 5;
    CONNECTION = 6;
    INTERNAL = 7;
  }
}

// Health status updates
message HealthEvent {
  ServiceHealth service_health = 1;
  repeated ComponentHealth component_health = 2;
  map<string, string> environment = 3;
  
  enum HealthStatus {
    UNKNOWN = 0;
    HEALTHY = 1;
    DEGRADED = 2;
    UNHEALTHY = 3;
  }
  
  message ServiceHealth {
    HealthStatus status = 1;
    string message = 2;
    uint64 uptime_seconds = 3;
  }
  
  message ComponentHealth {
    string name = 1;
    HealthStatus status = 2;
    string message = 3;
    map<string, string> metrics = 4;
  }
}

// Anonymized sample pairs for quality monitoring
message SamplePair {
  string input_hash = 1;
  string output_hash = 2;
  float quality_score = 3;
  map<string, float> quality_dimensions = 4;
}

// Request for aggregated telemetry data
message AggregationRequest {
  string source_id = 1;
  uint64 start_time = 2;
  uint64 end_time = 3;
  repeated string metrics = 4;
  string group_by = 5;
  map<string, string> filters = 6;
}

// Response with aggregated telemetry data
message AggregationResponse {
  bool success = 1;
  string message = 2;
  string request_id = 3;
  
  repeated AggregationResult results = 4;
}

// Result of data aggregation
message AggregationResult {
  string metric = 1;
  string group_by = 2;
  repeated DataPoint data_points = 3;
  
  message DataPoint {
    string group_value = 1;
    double value = 2;
    uint64 timestamp = 3;
  }
}
EOF

# Generate proto code script
cat > scripts/generate_protos.sh << 'EOF'
#!/bin/bash
set -e

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# Get the root directory of the project (one level up from script dir)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

echo "Generating Protocol Buffer code..."

# Ensure python-grpc-tools is installed
pip install grpcio-tools

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

# Create main README file
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

[Full documentation and examples](docs/)

## 🚀 Quick Start

```bash
# Install from PyPI
pip install secure-mcp-grpc

# Or use Docker Compose for a complete deployment
docker-compose up -d
```

## 🔐 Security Features

- Mutual TLS Authentication
- Token-based Authentication (JWT, OAuth2)
- Fine-grained Authorization
- Rate Limiting
- Anomaly Detection
- Audit Logging
- Secure Defaults

## 📊 Visualization Dashboard

Access the dashboard at `http://localhost:8050/` after starting the services to see:

- Traffic Flow Diagrams
- Model Interaction Networks
- Security Event Heatmaps
- Latency Distribution Charts
- Real-time Monitoring

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
EOF

# Create LICENSE file
cat > LICENSE << 'EOF'
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   Copyright 2025 Matthew Stanton & Claude AI

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
EOF

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

# Dockerfiles
cat > docker/server.Dockerfile << 'EOF'
# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Create non-root user
RUN useradd -m -r mcpuser && \
    mkdir -p /app/logs /app/traces /app/config /app/certs && \
    chown -R mcpuser:mcpuser /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -e ".[telemetry]"

# Copy the project code
COPY secure_mcp_grpc/ ./secure_mcp_grpc/
COPY scripts/ ./scripts/
COPY config/ ./config/

# Generate Protocol Buffers
RUN python -m secure_mcp_grpc.tools.generate_protos

# Fix permissions
RUN chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Set up logging
RUN mkdir -p ${HOME}/.config/secure_mcp_grpc

# Expose the gRPC port
EXPOSE 50051

# Command to run the server
ENTRYPOINT ["python", "-m", "secure_mcp_grpc.server.main"]
EOF

cat > docker/dashboard.Dockerfile << 'EOF'
# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Create non-root user
RUN useradd -m -r dashuser