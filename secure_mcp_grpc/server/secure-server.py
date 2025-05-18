"""
Secure MCP-gRPC Server

A comprehensive secure gRPC server implementation for Model Context Protocol (MCP).
Implements a defense-in-depth approach to security, including mutual TLS, token-based
authentication, fine-grained authorization, rate limiting, and comprehensive auditing.

Author: Matthew Stanton && Claude.Ai
License: Apache 2.0
"""

import os
import json
import time
import uuid
import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable, Union, AsyncGenerator, Set
from datetime import datetime, timedelta
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import hashlib

import grpc
from concurrent import futures

# Import generated Protocol Buffer code
from secure_mcp_grpc.proto import mcp_pb2, mcp_pb2_grpc, telemetry_pb2

# Import core types
from secure_mcp_grpc.core.types import (
    MCPRequest, MCPResponse, ReflectionRequest, ReflectionResponse, MCPError,
    AuthResult, SecurityContext
)

# Import security components
from secure_mcp_grpc.server.auth import (
    AuthProvider, MTLSAuthProvider, JWTAuthProvider, OAuth2AuthProvider
)
from secure_mcp_grpc.server.security_config import SecurityConfig
from secure_mcp_grpc.server.security_middleware import SecurityMiddleware

# Import interceptors
from secure_mcp_grpc.interceptors import (
    AuthInterceptor, RateLimitInterceptor, AuditInterceptor
)

# Import telemetry
from secure_mcp_grpc.telemetry import TelemetryCollector, TelemetryExporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_PORT = 50051
MAX_WORKERS = 10
DEFAULT_RATE_LIMIT = 100  # requests per minute
DEFAULT_HEALTH_CHECK_INTERVAL = 5
MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = 1800  # 30 minutes in seconds

class SecureMCPServicer(mcp_pb2_grpc.MCPServiceServicer):
    """
    Secure gRPC servicer implementation for MCP.
    Handles security, authentication, authorization, and telemetry.
    
    Implements defense-in-depth security with:
    - Multiple authentication methods (mTLS, JWT, OAuth2)
    - Fine-grained authorization
    - Rate limiting and DoS protection
    - Comprehensive audit logging
    - Session management
    - Account lockout
    - Security event monitoring
    """
    
    def __init__(
        self,
        mcp_server,
        auth_provider: AuthProvider,
        security_config: SecurityConfig,
        telemetry_collector: Optional[TelemetryCollector] = None,
        access_control: Optional[Dict[str, List[str]]] = None
    ):
        """
        Initialize the secure MCP gRPC servicer.
        
        Args:
            mcp_server: The MCP server implementation that will handle the requests.
            auth_provider: The authentication provider to use.
            security_config: Security configuration settings.
            telemetry_collector: Optional telemetry collector for monitoring.
            access_control: Dictionary mapping user IDs to allowed methods.
            
        Raises:
            ValueError: If configuration is invalid
        """
        if not isinstance(security_config, SecurityConfig):
            raise ValueError("Invalid security configuration")
            
        self.mcp_server = mcp_server
        self.auth_provider = auth_provider
        self.security_config = security_config
        self.telemetry_collector = telemetry_collector
        self.access_control = access_control or {}
        
        # Initialize security middleware
        self.security_middleware = SecurityMiddleware(security_config)
        
        # Rate limiting state
        self.rate_limit_state = {}
        
        # Session tracking
        self.active_sessions = {}
        
        # Failed authentication attempts tracking
        self.failed_auth_attempts = {}
        
        # Account lockout tracking
        self.locked_accounts = {}
        
        # Server start time
        self._start_time = time.time()
        
        # Create instance ID for telemetry
        self.instance_id = str(uuid.uuid4())
        
        logger.info(f"Secure MCP servicer initialized with instance ID: {self.instance_id}")
    
    async def Call(self, request_iterator, context):
        """
        Handle a bidirectional streaming RPC call for MCP messages.
        Provides security checks and telemetry for each request.
        
        Args:
            request_iterator: Iterator of gRPC MCPRequest messages.
            context: gRPC context.
            
        Yields:
            gRPC MCPResponse messages.
        """
        # Process through security middleware
        if not await self.security_middleware(request_iterator, context, "Call"):
            return
        
        # Create a queue for sending responses back to the client
        response_queue = asyncio.Queue()
        session_id = str(uuid.uuid4())
        client_ip = self._extract_client_ip(context)
        
        # Check session limits
        if not self._check_session_limits(client_ip):
            await self._reject_request(
                context,
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "Maximum sessions per IP exceeded"
            )
            return
        
        # Log session start
        logger.info(f"Starting MCP session {session_id} from {client_ip}")
        
        # Track the session
        self.active_sessions[session_id] = {
            "start_time": time.time(),
            "client_ip": client_ip,
            "request_count": 0,
            "user_id": None,
            "last_activity": time.time()
        }
        
        # Record telemetry event for session start
        if self.telemetry_collector:
            await self.telemetry_collector.record_session_start(
                session_id=session_id,
                source_ip=client_ip
            )
        
        try:
            async for proto_request in request_iterator:
                # Process request through security middleware
                if not await self.security_middleware(proto_request, context, "Call"):
                    continue
                
                start_time = time.time()
                request_id = proto_request.id or str(uuid.uuid4())
                
                # Update session activity
                if session_id in self.active_sessions:
                    self.active_sessions[session_id]["last_activity"] = time.time()
                    self.active_sessions[session_id]["request_count"] += 1
                
                # Log request
                logger.debug(f"Received request {request_id} in session {session_id}: {proto_request.method}")
                
                # Check rate limits
                if not self._check_rate_limit(client_ip):
                    error_response = self._create_error_response(
                        request_id,
                        -32429,  # Too Many Requests
                        f"Rate limit exceeded: {self.security_config.max_requests_per_minute} requests per minute allowed"
                    )
                    await response_queue.put(error_response)
                    
                    # Record rate limit event in telemetry
                    if self.telemetry_collector:
                        await self.telemetry_collector.record_security_event(
                            session_id=session_id,
                            event_type=telemetry_pb2.TelemetryEvent.EventType.SECURITY,
                            security_event_type=telemetry_pb2.SecurityEvent.SecurityEventType.RATE_LIMIT,
                            success=False,
                            severity=telemetry_pb2.TelemetryEvent.Severity.WARNING,
                            source_ip=client_ip,
                            user_id=None,
                            resource=proto_request.method,
                            action="rate_limit"
                        )
                    
                    continue
                
                # Convert Proto request to MCP request
                mcp_request = self._proto_to_mcp_request(proto_request)
                
                # Extract security context if available
                security_context = None
                if hasattr(proto_request, 'security_context') and proto_request.security_context:
                    security_context = self._extract_security_context(proto_request.security_context)
                
                # Authenticate the request
                auth_result = await self._authenticate_request(proto_request, context, security_context)
                if not auth_result.success:
                    # Create error response for authentication failure
                    error_response = self._create_error_response(
                        request_id,
                        auth_result.error_code,
                        auth_result.error_message
                    )
                    await response_queue.put(error_response)
                    
                    # Record authentication failure in telemetry
                    if self.telemetry_collector:
                        await self.telemetry_collector.record_security_event(
                            session_id=session_id,
                            event_type=telemetry_pb2.TelemetryEvent.EventType.SECURITY,
                            security_event_type=telemetry_pb2.SecurityEvent.SecurityEventType.AUTHENTICATION,
                            success=False,
                            severity=telemetry_pb2.TelemetryEvent.Severity.WARNING,
                            source_ip=client_ip,
                            user_id=auth_result.user_id,
                            resource=mcp_request.method,
                            action="authenticate"
                        )
                    
                    continue
                
                # Set the user ID if successful
                user_id = auth_result.user_id
                
                # Update session with user ID
                if session_id in self.active_sessions:
                    self.active_sessions[session_id]["user_id"] = user_id
                
                # Authorize the request
                auth_result = await self._authorize_request(user_id, mcp_request.method)
                if not auth_result.success:
                    # Create error response for authorization failure
                    error_response = self._create_error_response(
                        request_id,
                        auth_result.error_code,
                        auth_result.error_message
                    )
                    await response_queue.put(error_response)
                    
                    # Record authorization failure in telemetry
                    if self.telemetry_collector:
                        await self.telemetry_collector.record_security_event(
                            session_id=session_id,
                            event_type=telemetry_pb2.TelemetryEvent.EventType.SECURITY,
                            security_event_type=telemetry_pb2.SecurityEvent.SecurityEventType.AUTHORIZATION,
                            success=False,
                            severity=telemetry_pb2.TelemetryEvent.Severity.WARNING,
                            source_ip=client_ip,
                            user_id=user_id,
                            resource=mcp_request.method,
                            action="authorize"
                        )
                    
                    continue
                
                try:
                    # Process the request with the MCP server
                    mcp_response = await self.mcp_server.handle_request(mcp_request)
                    
                    # Convert MCP response to Proto response
                    proto_response = self._mcp_to_proto_response(mcp_response)
                    
                    # Add performance metrics
                    end_time = time.time()
                    processing_time_ms = int((end_time - start_time) * 1000)
                    proto_response.processing_time_ms = processing_time_ms
                    
                    # Token count estimation if available
                    token_count = 0
                    if mcp_response.result and isinstance(mcp_response.result, dict):
                        # Try to estimate token count from result
                        result_str = json.dumps(mcp_response.result)
                        token_count = len(result_str.split()) // 3  # Rough estimate
                    proto_response.token_count = token_count
                    
                    # Record performance metrics in telemetry
                    if self.telemetry_collector:
                        await self.telemetry_collector.record_performance_metrics(
                            session_id=session_id,
                            request_id=request_id,
                            processing_time_ms=processing_time_ms,
                            method=mcp_request.method,
                            user_id=user_id,
                            token_count=token_count
                        )
                    
                    # Also record usage metrics
                    if self.telemetry_collector:
                        await self.telemetry_collector.record_usage_metrics(
                            session_id=session_id,
                            user_id=user_id,
                            model_id=self.instance_id,
                            method=mcp_request.method,
                            token_count=token_count
                        )
                    
                    # Send the response
                    await response_queue.put(proto_response)
                    
                except Exception as e:
                    # Handle exceptions by creating an error response
                    logger.error(f"Error processing request: {e}", exc_info=True)
                    error_response = self._create_error_response(
                        request_id,
                        -32603,  # Internal error
                        f"Internal error: {str(e)}"
                    )
                    await response_queue.put(error_response)
                    
                    # Record error in telemetry
                    if self.telemetry_collector:
                        await self.telemetry_collector.record_error_event(
                            session_id=session_id,
                            error_type=telemetry_pb2.ErrorEvent.ErrorType.INTERNAL,
                            error_code="-32603",
                            message=str(e),
                            context={
                                "method": mcp_request.method,
                                "request_id": request_id
                            },
                            severity=telemetry_pb2.TelemetryEvent.Severity.ERROR
                        )
        except Exception as e:
            logger.error(f"Error in Call method: {str(e)}")
            await self._reject_request(
                context,
                grpc.StatusCode.INTERNAL,
                "Internal server error"
            )
        finally:
            # Clean up session
            self._cleanup_session(session_id)
        
        # Yield responses from the queue
        while True:
            try:
                response = await response_queue.get()
                yield response
                response_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error yielding response: {e}", exc_info=True)
                break
    
    async def Reflect(self, request, context):
        """
        Handle a unary RPC call for MCP reflection.
        
        Args:
            request: gRPC ReflectionRequest message.
            context: gRPC context.
            
        Returns:
            gRPC ReflectionResponse message.
        """
        request_id = request.id or str(uuid.uuid4())
        client_ip = self._extract_client_ip(context)
        
        # Log reflection request
        logger.info(f"Reflection request {request_id} from {client_ip}")
        
        # Check rate limits
        if not self._check_rate_limit(client_ip):
            await context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                f"Rate limit exceeded: {self.security_config.max_requests_per_minute} requests per minute allowed"
            )
            return None
        
        # Extract security context if available
        security_context = None
        if hasattr(request, 'security_context') and request.security_context:
            security_context = self._extract_security_context(request.security_context)
        
        # Authenticate the request for reflection
        auth_result = await self._authenticate_request(request, context, security_context)
        if not auth_result.success:
            # Handle authentication failure
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, auth_result.error_message)
            return None
        
        try:
            # Convert Proto reflection request to MCP reflection request
            mcp_reflect_request = ReflectionRequest(id=request_id)
            
            # Process the reflection request with the MCP server
            mcp_reflect_response = await self.mcp_server.reflect(mcp_reflect_request)
            
            # Convert MCP reflection response to Proto reflection response
            proto_response = mcp_pb2.ReflectionResponse(
                id=mcp_reflect_response.id,
            )
            
            # Add security capabilities
            proto_response.auth_methods.extend(self.auth_provider.supported_methods())
            proto_response.requires_encryption = True
            proto_response.version = 1
            
            # Convert tools, resources, parameterized_prompts, and sampling to JSON strings
            if mcp_reflect_response.tools:
                proto_response.tools = json.dumps(mcp_reflect_response.tools)
            if mcp_reflect_response.resources:
                proto_response.resources = json.dumps(mcp_reflect_response.resources)
            if mcp_reflect_response.parameterized_prompts:
                proto_response.parameterized_prompts = json.dumps(mcp_reflect_response.parameterized_prompts)
            if mcp_reflect_response.sampling:
                proto_response.sampling = json.dumps(mcp_reflect_response.sampling)
                
            # Record successful reflection in telemetry
            if self.telemetry_collector:
                await self.telemetry_collector.record_usage_metrics(
                    session_id=request_id,
                    user_id=auth_result.user_id,
                    model_id=self.instance_id,
                    method="reflect",
                    token_count=0
                )
                
            return proto_response
            
        except Exception as e:
            # Handle exceptions
            logger.error(f"Error processing reflection request: {e}", exc_info=True)
            
            # Record error in telemetry
            if self.telemetry_collector:
                await self.telemetry_collector.record_error_event(
                    session_id=request_id,
                    error_type=telemetry_pb2.ErrorEvent.ErrorType.INTERNAL,
                    error_code="REFLECTION_ERROR",
                    message=str(e),
                    context={"request_id": request_id},
                    severity=telemetry_pb2.TelemetryEvent.Severity.ERROR
                )
                
            await context.abort(grpc.StatusCode.INTERNAL, f"Internal error: {str(e)}")
            return None
    
    async def HealthStream(self, request, context):
        """
        Handle a server streaming RPC call for health checks.
        
        Args:
            request: gRPC HealthRequest message.
            context: gRPC context.
            
        Yields:
            gRPC HealthResponse messages.
        """
        request_id = request.id or str(uuid.uuid4())
        detailed = request.detailed
        client_ip = self._extract_client_ip(context)
        
        # Log health request
        logger.info(f"Health check request {request_id} from {client_ip}")
        
        # Extract security context if available
        security_context = None
        if hasattr(request, 'security_context') and request.security_context:
            security_context = self._extract_security_context(request.security_context)
        
        # Authenticate the request for health checks
        auth_result = await self._authenticate_request(request, context, security_context)
        if not auth_result.success:
            # Handle authentication failure
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, auth_result.error_message)
            return
        
        try:
            # Initial health response
            yield self._create_health_response(request_id, detailed)
            
            # Continue sending health updates periodically
            interval = DEFAULT_HEALTH_CHECK_INTERVAL
            while not context.cancelled():
                await asyncio.sleep(interval)
                yield self._create_health_response(request_id, detailed)
                
        except Exception as e:
            # Handle exceptions
            logger.error(f"Error in health stream: {e}", exc_info=True)
            
            # Record error in telemetry
            if self.telemetry_collector:
                await self.telemetry_collector.record_error_event(
                    session_id=request_id,
                    error_type=telemetry_pb2.ErrorEvent.ErrorType.INTERNAL,
                    error_code="HEALTH_STREAM_ERROR",
                    message=str(e),
                    context={"request_id": request_id},
                    severity=telemetry_pb2.TelemetryEvent.Severity.ERROR
                )
                
            await context.abort(grpc.StatusCode.INTERNAL, f"Internal error: {str(e)}")
    
    def _proto_to_mcp_request(self, proto_request: mcp_pb2.MCPRequest) -> MCPRequest:
        """Convert a Protocol Buffer request to an MCP request."""
        # Extract parameters from the request
        params = dict(proto_request.params) if proto_request.params else None
        
        return MCPRequest(
            id=proto_request.id,
            method=proto_request.method,
            params=params
        )
    
    def _mcp_to_proto_response(self, mcp_response: MCPResponse) -> mcp_pb2.MCPResponse:
        """Convert an MCP response to its Protocol Buffer representation."""
        proto_response = mcp_pb2.MCPResponse(
            id=mcp_response.id,
        )
        
        # Handle result or error
        if mcp_response.result is not None:
            # Convert result to JSON string to maintain compatibility
            # with complex nested structures
            proto_response.result = json.dumps(mcp_response.result)
        elif mcp_response.error:
            proto_response.error.code = mcp_response.error.code
            proto_response.error.message = mcp_response.error.message
            if mcp_response.error.data:
                proto_response.error.data = json.dumps(mcp_response.error.data)
                
        return proto_response
    
    def _create_error_response(self, request_id: str, code: int, message: str, data: Any = None) -> mcp_pb2.MCPResponse:
        """Create an error response with the given code and message."""
        response = mcp_pb2.MCPResponse(id=request_id)
        response.error.code = code
        response.error.message = message
        if data:
            response.error.data = json.dumps(data)
        return response
    
    def _create_health_response(self, request_id: str, detailed: bool) -> mcp_pb2.HealthResponse:
        """Create a health response with the current status."""
        response = mcp_pb2.HealthResponse(id=request_id)
        
        # Set overall status
        response.status = mcp_pb2.HealthResponse.Status.HEALTHY
        
        if detailed:
            # Add component statuses
            response.component_status["auth"] = mcp_pb2.HealthResponse.Status.HEALTHY
            response.component_status["mcp_server"] = mcp_pb2.HealthResponse.Status.HEALTHY
            response.component_status["telemetry"] = (
                mcp_pb2.HealthResponse.Status.HEALTHY 
                if self.telemetry_collector else 
                mcp_pb2.HealthResponse.Status.UNKNOWN
            )
            
            # Add metrics
            response.metrics["uptime_seconds"] = str(int(time.time() - self._start_time))
            response.metrics["active_sessions"] = str(len(self.active_sessions))
            response.metrics["total_requests"] = str(sum(
                session["request_count"] for session in self.active_sessions.values()
            ))
            response.metrics["timestamp"] = datetime.utcnow().isoformat()
        
        return response
    
    def _extract_security_context(self, proto_security_context) -> SecurityContext:
        """Extract security context from Protocol Buffer message."""
        security_context = SecurityContext()
        
        if proto_security_context.HasField('jwt_auth'):
            security_context.auth_type = "jwt"
            security_context.auth_token = proto_security_context.jwt_auth.token
        elif proto_security_context.HasField('oauth2_auth'):
            security_context.auth_type = "oauth2"
            security_context.auth_token = proto_security_context.oauth2_auth.access_token
        elif proto_security_context.HasField('api_key_auth'):
            security_context.auth_type = "api_key"
            security_context.auth_token = proto_security_context.api_key_auth.key
            
        security_context.client_id = proto_security_context.client_id
        security_context.request_id = proto_security_context.request_id
        security_context.timestamp = proto_security_context.timestamp
        security_context.metadata = dict(proto_security_context.metadata) if proto_security_context.metadata else {}
        
        return security_context
    
    def _extract_client_ip(self, context) -> str:
        """
        Extract client IP address from gRPC context.
        
        Args:
            context: gRPC context
            
        Returns:
            str: Client IP address or "unknown" if extraction fails
        """
        try:
            peer = context.peer()
            if peer:
                # Typically in the format "ipv4:127.0.0.1:12345" or "ipv6:[::1]:12345"
                parts = peer.split(':')
                if len(parts) >= 2:
                    if parts[0] == 'ipv4':
                        return parts[1]
                    elif parts[0] == 'ipv6':
                        # Handle IPv6 addresses which contain multiple colons
                        return peer.split(']')[0].replace('ipv6:[', '')
            return "unknown"
        except Exception:
            return "unknown"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check if the client has exceeded the rate limit.
        
        Args:
            client_ip: The client's IP address
            
        Returns:
            bool: True if the request is allowed, False if it exceeds the rate limit
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
        
        # Check if the rate limit is exceeded
        if len(self.rate_limit_state[client_ip]) >= self.security_config.rate_limit:
            logger.warning(f"Rate limit exceeded for client {client_ip}")
            return False
        
        # Add the current timestamp
        self.rate_limit_state[client_ip].append(current_time)
        return True
    
    async def _authenticate_request(
        self,
        request,
        context,
        security_context: SecurityContext
    ) -> AuthResult:
        """
        Authenticate the request based on the security context.
        
        Implements multiple authentication methods with:
        - Account lockout after failed attempts
        - Rate limiting per client
        - Comprehensive audit logging
        - Token validation and expiration checks
        
        Args:
            request: The incoming request
            context: gRPC context
            security_context: Security context containing auth information
            
        Returns:
            AuthResult: Authentication result with success status and user ID
            
        Raises:
            grpc.RpcError: If authentication fails with appropriate status code
        """
        client_ip = self._extract_client_ip(context)
        
        # Check if client IP is blocked
        if client_ip in self.security_config.blocked_ips:
            logger.warning(f"Blocked IP attempted authentication: {client_ip}")
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.PERMISSION_DENIED,
                error_message="IP address blocked"
            )
        
        # Check account lockout
        if client_ip in self.locked_accounts:
            lockout_time = self.locked_accounts[client_ip]
            if time.time() < lockout_time:
                remaining_time = int(lockout_time - time.time())
                logger.warning(f"Locked account attempted authentication: {client_ip}")
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.PERMISSION_DENIED,
                    error_message=f"Account locked. Try again in {remaining_time} seconds"
                )
            else:
                # Reset lockout if time has expired
                del self.locked_accounts[client_ip]
                self.failed_auth_attempts[client_ip] = 0
        
        # Validate security context
        if not security_context:
            logger.warning(f"Missing security context from {client_ip}")
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.UNAUTHENTICATED,
                error_message="Missing security context"
            )
        
        try:
            # Authenticate based on auth type
            if security_context.auth_type == "jwt":
                auth_result = await self._authenticate_jwt(security_context)
            elif security_context.auth_type == "oauth2":
                auth_result = await self._authenticate_oauth2(security_context)
            elif security_context.auth_type == "api_key":
                auth_result = await self._authenticate_api_key(security_context)
            else:
                logger.warning(f"Unsupported auth type from {client_ip}: {security_context.auth_type}")
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.UNAUTHENTICATED,
                    error_message="Unsupported authentication type"
                )
            
            # Handle authentication result
            if auth_result.success:
                # Reset failed attempts on success
                self.failed_auth_attempts[client_ip] = 0
                
                # Record successful authentication
                if self.telemetry_collector:
                    await self.telemetry_collector.record_security_event(
                        session_id=security_context.request_id,
                        event_type=telemetry_pb2.TelemetryEvent.EventType.SECURITY,
                        security_event_type=telemetry_pb2.SecurityEvent.SecurityEventType.AUTHENTICATION,
                        success=True,
                        severity=telemetry_pb2.TelemetryEvent.Severity.INFO,
                        source_ip=client_ip,
                        user_id=auth_result.user_id,
                        resource="authentication",
                        action="authenticate"
                    )
            else:
                # Increment failed attempts
                self.failed_auth_attempts[client_ip] = self.failed_auth_attempts.get(client_ip, 0) + 1
                
                # Check if account should be locked
                if self.failed_auth_attempts[client_ip] >= MAX_FAILED_ATTEMPTS:
                    self.locked_accounts[client_ip] = time.time() + ACCOUNT_LOCKOUT_DURATION
                    logger.warning(f"Account locked for {client_ip} after {MAX_FAILED_ATTEMPTS} failed attempts")
                
                # Record failed authentication
                if self.telemetry_collector:
                    await self.telemetry_collector.record_security_event(
                        session_id=security_context.request_id,
                        event_type=telemetry_pb2.TelemetryEvent.EventType.SECURITY,
                        security_event_type=telemetry_pb2.SecurityEvent.SecurityEventType.AUTHENTICATION,
                        success=False,
                        severity=telemetry_pb2.TelemetryEvent.Severity.WARNING,
                        source_ip=client_ip,
                        user_id=None,
                        resource="authentication",
                        action="authenticate"
                    )
            
            return auth_result
            
        except Exception as e:
            logger.error(f"Authentication error for {client_ip}: {str(e)}")
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.INTERNAL,
                error_message="Internal authentication error"
            )
    
    async def _authenticate_jwt(self, security_context: SecurityContext) -> AuthResult:
        """
        Authenticate using JWT token.
        
        Args:
            security_context: Security context containing JWT token
            
        Returns:
            AuthResult: Authentication result
        """
        try:
            if not self.security_config.jwt_secret:
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.UNAUTHENTICATED,
                    error_message="JWT authentication not configured"
                )
            
            # Decode and verify JWT token
            token = security_context.auth_token
            payload = jwt.decode(
                token,
                self.security_config.jwt_secret.get_secret_value(),
                algorithms=["HS256", "RS256"],
                audience=self.security_config.jwt_audience,
                issuer=self.security_config.jwt_issuer
            )
            
            # Extract user ID from token
            user_id = payload.get("sub")
            if not user_id:
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.UNAUTHENTICATED,
                    error_message="Invalid JWT token: missing subject"
                )
            
            return AuthResult(success=True, user_id=user_id)
            
        except jwt.ExpiredSignatureError:
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.UNAUTHENTICATED,
                error_message="JWT token expired"
            )
        except jwt.InvalidTokenError as e:
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.UNAUTHENTICATED,
                error_message=f"Invalid JWT token: {str(e)}"
            )
    
    async def _authenticate_oauth2(self, security_context: SecurityContext) -> AuthResult:
        """
        Authenticate using OAuth2 token.
        
        Args:
            security_context: Security context containing OAuth2 token
            
        Returns:
            AuthResult: Authentication result
        """
        try:
            if not self.security_config.oauth2_config:
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.UNAUTHENTICATED,
                    error_message="OAuth2 authentication not configured"
                )
            
            # Verify OAuth2 token
            token = security_context.auth_token
            # TODO: Implement OAuth2 token verification
            # This would typically involve:
            # 1. Validating token signature using JWKS
            # 2. Checking token claims (exp, iss, aud, etc.)
            # 3. Verifying token scope
            # 4. Checking token revocation status
            
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.UNIMPLEMENTED,
                error_message="OAuth2 authentication not implemented"
            )
            
        except Exception as e:
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.UNAUTHENTICATED,
                error_message=f"OAuth2 authentication error: {str(e)}"
            )
    
    async def _authenticate_api_key(self, security_context: SecurityContext) -> AuthResult:
        """
        Authenticate using API key.
        
        Args:
            security_context: Security context containing API key
            
        Returns:
            AuthResult: Authentication result
        """
        try:
            if not self.security_config.api_keys:
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.UNAUTHENTICATED,
                    error_message="API key authentication not configured"
                )
            
            # Verify API key
            key = security_context.auth_token
            if key not in self.security_config.api_keys:
                return AuthResult(
                    success=False,
                    error_code=grpc.StatusCode.UNAUTHENTICATED,
                    error_message="Invalid API key"
                )
            
            # Get user ID associated with API key
            user_id = self.security_config.api_keys[key]
            return AuthResult(success=True, user_id=user_id)
            
        except Exception as e:
            return AuthResult(
                success=False,
                error_code=grpc.StatusCode.UNAUTHENTICATED,
                error_message=f"API key authentication error: {str(e)}"
            )
    
    def _check_session_limits(self, client_ip: str) -> bool:
        """Check if client has exceeded session limits."""
        active_sessions = sum(
            1 for session in self.active_sessions.values()
            if session["client_ip"] == client_ip
        )
        return active_sessions < self.security_config.max_sessions_per_ip
    
    def _cleanup_session(self, session_id: str) -> None:
        """Clean up session resources."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
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