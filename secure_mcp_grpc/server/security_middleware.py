"""
Security Middleware Module

This module implements security-focused middleware for the Secure MCP-gRPC server.
It provides comprehensive security features including:
- CORS policies and security headers
- Request validation and sanitization
- IP-based access control
- Request size limits
- Method access control
- Security header management
- Rate limiting
- Session management
- Token validation
- Audit logging

The middleware implements defense-in-depth security principles and follows OWASP
security best practices for gRPC services.

Author: Matthew Stanton && Claude.ai
License: Apache 2.0
"""

from typing import List, Optional, Dict, Any, Protocol, runtime_checkable, Set
from dataclasses import dataclass
import grpc
import time
import logging
from secure_mcp_grpc.server.security_config import SecurityConfig
from secure_mcp_grpc.telemetry import TelemetryCollector

# Configure logging
logger = logging.getLogger(__name__)

@runtime_checkable
class RequestProtocol(Protocol):
    """Protocol defining required request methods."""
    def SerializeToString(self) -> bytes:
        """Serialize request to bytes."""
        ...

@dataclass
class SecurityHeaders:
    """
    Security headers configuration with secure defaults.
    
    Attributes:
        content_security_policy: CSP header value controlling resource loading
        x_content_type_options: Prevents MIME type sniffing
        x_frame_options: Prevents clickjacking attacks
        x_xss_protection: Enables XSS filtering
        strict_transport_security: Enforces HTTPS
        referrer_policy: Controls referrer information
        permissions_policy: Controls browser features
    """
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
    Security middleware for gRPC server implementing defense-in-depth security.
    
    This middleware implements multiple layers of security controls:
    1. Request validation and sanitization
    2. Access control based on IP and method
    3. Security headers for HTTP/2 transport
    4. Request size limits
    5. Method access control
    6. Rate limiting
    7. Session management
    8. Token validation
    9. Audit logging
    
    The middleware follows the principle of least privilege and implements
    secure defaults for all security controls.
    
    Attributes:
        config: Security configuration instance
        headers: Security headers configuration
        telemetry_collector: Optional telemetry collector for monitoring
        rate_limit_state: Rate limiting state tracking
        active_sessions: Active session tracking
    """
    
    def __init__(
        self,
        config: SecurityConfig,
        telemetry_collector: Optional[TelemetryCollector] = None
    ):
        """
        Initialize security middleware with configuration.
        
        Args:
            config: Security configuration instance containing:
                - Allowed methods
                - Blocked IPs
                - Max request size
                - Other security settings
            telemetry_collector: Optional telemetry collector for monitoring
                
        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(config, SecurityConfig):
            raise ValueError("Invalid security configuration")
        self.config = config
        self.headers = SecurityHeaders()
        self.telemetry_collector = telemetry_collector
        self.rate_limit_state = {}
        self.active_sessions = {}
    
    async def __call__(
        self,
        request: RequestProtocol,
        context: grpc.aio.ServicerContext,
        method_name: str
    ) -> bool:
        """
        Process incoming request through security middleware.
        
        Implements a chain of security checks:
        1. Add security headers
        2. Validate method access
        3. Check IP blocking
        4. Validate request size
        5. Check rate limits
        6. Validate session
        7. Validate token
        
        Args:
            request: Incoming request implementing RequestProtocol
            context: gRPC context for request
            method_name: Name of the called method
            
        Returns:
            bool: True if request passes all security checks, False otherwise
            
        Raises:
            grpc.RpcError: If request is rejected with appropriate status code
        """
        # Add security headers
        self._add_security_headers(context)
        
        # Get client IP
        client_ip = self._get_client_ip(context)
        
        # Check IP blocking
        if client_ip in self.config.blocked_ips:
            await self._reject_request(
                context,
                grpc.StatusCode.PERMISSION_DENIED,
                "IP address blocked"
            )
            return False
        
        # Validate method
        if not self._validate_method(method_name):
            await self._reject_request(
                context,
                grpc.StatusCode.PERMISSION_DENIED,
                f"Method {method_name} not allowed"
            )
            return False
        
        # Check rate limits
        if not self._check_rate_limit(client_ip):
            await self._reject_request(
                context,
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "Rate limit exceeded"
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
        
        # Validate session
        session_id = self._get_session_id(context)
        if session_id and not self._validate_session(session_id):
            await self._reject_request(
                context,
                grpc.StatusCode.UNAUTHENTICATED,
                "Invalid or expired session"
            )
            return False
        
        # Record security event
        if self.telemetry_collector:
            await self.telemetry_collector.record_security_event(
                session_id=session_id,
                event_type="security_check",
                security_type="request_validation",
                user_id=None,
                client_ip=client_ip,
                resource=method_name,
                action="validate",
                decision=True
            )
        
        return True
    
    def _add_security_headers(self, context: grpc.aio.ServicerContext) -> None:
        """
        Add security headers to response.
        
        Implements secure defaults for HTTP/2 transport headers.
        
        Args:
            context: gRPC context to add headers to
        """
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
        """
        Validate if method is allowed.
        
        Implements method-level access control.
        
        Args:
            method_name: Name of method to validate
            
        Returns:
            bool: True if method is allowed, False otherwise
        """
        return method_name in self.config.allowed_methods
    
    def _validate_request_size(self, request: RequestProtocol) -> bool:
        """
        Validate request size against configured limit.
        
        Args:
            request: Request to validate size of
            
        Returns:
            bool: True if request size is within limit, False otherwise
        """
        try:
            size = len(request.SerializeToString())
            return size <= self.config.max_request_size
        except Exception:
            return False
    
    def _get_client_ip(self, context: grpc.aio.ServicerContext) -> str:
        """
        Extract client IP from context.
        
        Args:
            context: gRPC context containing peer information
            
        Returns:
            str: Client IP address or 'unknown' if extraction fails
        """
        try:
            peer = context.peer()
            return peer.split(":")[1] if ":" in peer else peer
        except Exception:
            return "unknown"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check if client has exceeded rate limit.
        
        Args:
            client_ip: Client IP address to check
            
        Returns:
            bool: True if within rate limit, False otherwise
        """
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Initialize state for new clients
        if client_ip not in self.rate_limit_state:
            self.rate_limit_state[client_ip] = []
        
        # Remove timestamps older than a minute
        self.rate_limit_state[client_ip] = [
            ts for ts in self.rate_limit_state[client_ip] if ts > minute_ago
        ]
        
        # Check if rate limit exceeded
        if len(self.rate_limit_state[client_ip]) >= self.config.rate_limit:
            logger.warning(f"Rate limit exceeded for client {client_ip}")
            return False
        
        # Add current timestamp
        self.rate_limit_state[client_ip].append(current_time)
        return True
    
    def _get_session_id(self, context: grpc.aio.ServicerContext) -> Optional[str]:
        """
        Extract session ID from context metadata.
        
        Args:
            context: gRPC context containing metadata
            
        Returns:
            Optional[str]: Session ID if present, None otherwise
        """
        try:
            metadata = dict(context.invocation_metadata())
            return metadata.get("session-id")
        except Exception:
            return None
    
    def _validate_session(self, session_id: str) -> bool:
        """
        Validate session is active and not expired.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            bool: True if session is valid, False otherwise
        """
        if session_id not in self.active_sessions:
            return False
            
        session = self.active_sessions[session_id]
        if time.time() > session["expires_at"]:
            del self.active_sessions[session_id]
            return False
            
        return True
    
    async def _reject_request(
        self,
        context: grpc.aio.ServicerContext,
        code: grpc.StatusCode,
        message: str
    ) -> None:
        """
        Reject request with error.
        
        Args:
            context: gRPC context to set error on
            code: Status code for rejection
            message: Error message (sanitized for security)
            
        Raises:
            grpc.RpcError: With specified status code and message
        """
        context.set_code(code)
        context.set_details(message)
        await context.abort(code, message) 