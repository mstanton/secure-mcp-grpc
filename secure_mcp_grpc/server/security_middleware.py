"""
Security Middleware Module

This module implements security-focused middleware for the Secure MCP-gRPC server.
Includes CORS policies, Content Security Policy, and security headers.

Author: Matthew Stanton && Claude.ai
License: Apache 2.0
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import grpc
from secure_mcp_grpc.server.security_config import SecurityConfig

@dataclass
class SecurityHeaders:
    """Security headers configuration."""
    content_security_policy: str = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    x_xss_protection: str = "1; mode=block"
    strict_transport_security: str = "max-age=31536000; includeSubDomains"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"

class SecurityMiddleware:
    """
    Security middleware for gRPC server.
    Implements security headers, CORS, and request validation.
    """
    
    def __init__(self, config: SecurityConfig):
        """
        Initialize security middleware.
        
        Args:
            config: Security configuration
        """
        self.config = config
        self.headers = SecurityHeaders()
    
    async def __call__(
        self,
        request: Any,
        context: grpc.aio.ServicerContext,
        method_name: str
    ) -> bool:
        """
        Process incoming request through security middleware.
        
        Args:
            request: Incoming request
            context: gRPC context
            method_name: Name of the called method
            
        Returns:
            bool: True if request passes security checks, False otherwise
        """
        # Add security headers
        self._add_security_headers(context)
        
        # Validate method
        if not self._validate_method(method_name):
            await self._reject_request(
                context,
                grpc.StatusCode.PERMISSION_DENIED,
                f"Method {method_name} not allowed"
            )
            return False
        
        # Check IP blocking
        client_ip = self._get_client_ip(context)
        if client_ip in self.config.blocked_ips:
            await self._reject_request(
                context,
                grpc.StatusCode.PERMISSION_DENIED,
                "IP address blocked"
            )
            return False
        
        # Validate request size
        if not self._validate_request_size(request):
            await self._reject_request(
                context,
                grpc.StatusCode.INVALID_ARGUMENT,
                "Request size exceeds limit"
            )
            return False
        
        return True
    
    def _add_security_headers(self, context: grpc.aio.ServicerContext) -> None:
        """Add security headers to response."""
        context.set_trailing_metadata([
            ("content-security-policy", self.headers.content_security_policy),
            ("x-content-type-options", self.headers.x_content_type_options),
            ("x-frame-options", self.headers.x_frame_options),
            ("x-xss-protection", self.headers.x_xss_protection),
            ("strict-transport-security", self.headers.strict_transport_security),
            ("referrer-policy", self.headers.referrer_policy),
            ("permissions-policy", self.headers.permissions_policy)
        ])
    
    def _validate_method(self, method_name: str) -> bool:
        """Validate if method is allowed."""
        return method_name in self.config.allowed_methods
    
    def _validate_request_size(self, request: Any) -> bool:
        """Validate request size."""
        try:
            size = len(request.SerializeToString())
            return size <= self.config.max_request_size
        except Exception:
            return False
    
    def _get_client_ip(self, context: grpc.aio.ServicerContext) -> str:
        """Extract client IP from context."""
        try:
            peer = context.peer()
            return peer.split(":")[1] if ":" in peer else peer
        except Exception:
            return "unknown"
    
    async def _reject_request(
        self,
        context: grpc.aio.ServicerContext,
        code: grpc.StatusCode,
        message: str
    ) -> None:
        """Reject request with error."""
        context.set_code(code)
        context.set_details(message)
        await context.abort(code, message) 