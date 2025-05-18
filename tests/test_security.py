"""
Security Test Module

This module contains comprehensive security tests for the Secure MCP-gRPC server.
Tests cover authentication, authorization, rate limiting, and other security features.

Author: Claude
License: Apache 2.0
"""

import pytest
import grpc
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any

from secure_mcp_grpc.server.security_config import SecurityConfig
from secure_mcp_grpc.server.security_middleware import SecurityMiddleware
from secure_mcp_grpc.server.secure_server import SecureMCPServicer
from secure_mcp_grpc.proto import mcp_pb2, mcp_pb2_grpc

class MockContext:
    """Mock gRPC context for testing."""
    def __init__(self, peer: str = "ipv4:127.0.0.1:12345"):
        self.peer = peer
        self._code = None
        self._details = None
        self._trailing_metadata = []
    
    def peer(self) -> str:
        return self.peer
    
    def set_code(self, code: grpc.StatusCode) -> None:
        self._code = code
    
    def set_details(self, details: str) -> None:
        self._details = details
    
    def set_trailing_metadata(self, metadata: List[tuple]) -> None:
        self._trailing_metadata = metadata
    
    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        self._code = code
        self._details = details

class MockRequest:
    """Mock gRPC request for testing."""
    def __init__(self, size: int = 1024):
        self._size = size
    
    def SerializeToString(self) -> bytes:
        return b"x" * self._size

@pytest.fixture
def security_config() -> SecurityConfig:
    """Create a test security configuration."""
    return SecurityConfig(
        max_request_size=1024 * 1024,  # 1MB
        max_sessions_per_ip=10,
        session_timeout=3600,
        rate_limit=100,
        allowed_methods=["Call", "Reflect", "HealthStream"],
        blocked_ips=["192.168.1.1"],
        require_mtls=True
    )

@pytest.fixture
def security_middleware(security_config: SecurityConfig) -> SecurityMiddleware:
    """Create a test security middleware instance."""
    return SecurityMiddleware(security_config)

@pytest.mark.asyncio
async def test_security_middleware_headers(security_middleware: SecurityMiddleware):
    """Test security headers are properly set."""
    context = MockContext()
    request = MockRequest()
    
    result = await security_middleware(request, context, "Call")
    
    assert result is True
    assert len(context._trailing_metadata) > 0
    headers = dict(context._trailing_metadata)
    assert "content-security-policy" in headers
    assert "x-content-type-options" in headers
    assert "x-frame-options" in headers
    assert "x-xss-protection" in headers
    assert "strict-transport-security" in headers

@pytest.mark.asyncio
async def test_security_middleware_method_validation(security_middleware: SecurityMiddleware):
    """Test method validation."""
    context = MockContext()
    request = MockRequest()
    
    # Test allowed method
    result = await security_middleware(request, context, "Call")
    assert result is True
    
    # Test disallowed method
    result = await security_middleware(request, context, "InvalidMethod")
    assert result is False
    assert context._code == grpc.StatusCode.PERMISSION_DENIED

@pytest.mark.asyncio
async def test_security_middleware_ip_blocking(security_middleware: SecurityMiddleware):
    """Test IP blocking."""
    context = MockContext(peer="ipv4:192.168.1.1:12345")
    request = MockRequest()
    
    result = await security_middleware(request, context, "Call")
    assert result is False
    assert context._code == grpc.StatusCode.PERMISSION_DENIED
    assert "IP address blocked" in context._details

@pytest.mark.asyncio
async def test_security_middleware_request_size(security_middleware: SecurityMiddleware):
    """Test request size validation."""
    context = MockContext()
    
    # Test within limit
    request = MockRequest(size=1024)
    result = await security_middleware(request, context, "Call")
    assert result is True
    
    # Test exceeding limit
    request = MockRequest(size=2 * 1024 * 1024)  # 2MB
    result = await security_middleware(request, context, "Call")
    assert result is False
    assert context._code == grpc.StatusCode.INVALID_ARGUMENT
    assert "Request size exceeds limit" in context._details

@pytest.mark.asyncio
async def test_session_limits(security_config: SecurityConfig):
    """Test session limit enforcement."""
    servicer = SecureMCPServicer(
        mcp_server=None,
        auth_provider=None,
        security_config=security_config
    )
    
    # Test within limit
    for i in range(security_config.max_sessions_per_ip):
        assert servicer._check_session_limits("127.0.0.1") is True
        session_id = f"session_{i}"
        servicer.active_sessions[session_id] = {
            "start_time": datetime.now(),
            "client_ip": "127.0.0.1",
            "request_count": 0,
            "user_id": None,
            "last_activity": datetime.now()
        }
    
    # Test exceeding limit
    assert servicer._check_session_limits("127.0.0.1") is False

@pytest.mark.asyncio
async def test_rate_limiting(security_config: SecurityConfig):
    """Test rate limiting functionality."""
    servicer = SecureMCPServicer(
        mcp_server=None,
        auth_provider=None,
        security_config=security_config
    )
    
    # Test within rate limit
    for _ in range(security_config.rate_limit):
        assert servicer._check_rate_limit("127.0.0.1") is True
    
    # Test exceeding rate limit
    assert servicer._check_rate_limit("127.0.0.1") is False

@pytest.mark.asyncio
async def test_session_cleanup(security_config: SecurityConfig):
    """Test session cleanup functionality."""
    servicer = SecureMCPServicer(
        mcp_server=None,
        auth_provider=None,
        security_config=security_config
    )
    
    # Create test session
    session_id = "test_session"
    servicer.active_sessions[session_id] = {
        "start_time": datetime.now(),
        "client_ip": "127.0.0.1",
        "request_count": 0,
        "user_id": None,
        "last_activity": datetime.now()
    }
    
    # Verify session exists
    assert session_id in servicer.active_sessions
    
    # Clean up session
    servicer._cleanup_session(session_id)
    
    # Verify session is removed
    assert session_id not in servicer.active_sessions

@pytest.mark.asyncio
async def test_security_context_validation(security_config: SecurityConfig):
    """Test security context validation."""
    servicer = SecureMCPServicer(
        mcp_server=None,
        auth_provider=None,
        security_config=security_config
    )
    
    # Test valid security context
    context = MockContext()
    request = MockRequest()
    result = await servicer._authenticate_request(request, context, None)
    assert result.success is True
    
    # Test invalid security context
    context = MockContext(peer="ipv4:192.168.1.1:12345")
    result = await servicer._authenticate_request(request, context, None)
    assert result.success is False 