"""
Secure MCP-gRPC Server

A comprehensive secure gRPC server implementation for Model Context Protocol (MCP).
Implements a defense-in-depth approach to security, including mutual TLS, token-based
authentication, fine-grained authorization, rate limiting, and comprehensive auditing.

Author: Claude
License: Apache 2.0
"""

import os
import json
import time
import uuid
import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable, Union, AsyncGenerator
from datetime import datetime

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
DEFAULT_HEALTH_CHECK_INTERVAL = 5  # seconds


class SecureMCPServicer(mcp_pb2_grpc.MCPServiceServicer):
    """
    Secure gRPC servicer implementation for MCP.
    Handles security, authentication, authorization, and telemetry.
    """
    
    def __init__(
        self,
        mcp_server,
        auth_provider: AuthProvider,
        telemetry_collector: Optional[TelemetryCollector] = None,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        access_control: Optional[Dict[str, List[str]]] = None
    ):
        """
        Initialize the secure MCP gRPC servicer.
        
        Args:
            mcp_server: The MCP server implementation that will handle the requests.
            auth_provider: The authentication provider to use.
            telemetry_collector: Optional telemetry collector for monitoring.
            rate_limit: Maximum number of requests per minute per client.
            access_control: Dictionary mapping user IDs to allowed methods.
        """
        self.mcp_server = mcp_server
        self.auth_provider = auth_provider
        self.telemetry_collector = telemetry_collector
        self.rate_limit = rate_limit
        self.access_control = access_control or {}
        
        # Rate limiting state
        self.rate_limit_state = {}
        
        # Session tracking
        self.active_sessions = {}
        
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
        # Create a queue for sending responses back to the client
        response_queue = asyncio.Queue()
        session_id = str(uuid.uuid4())
        client_ip = self._extract_client_ip(context)
        
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
        
        # Create a task to process incoming requests
        async def process_requests():
            user_id = None
            
            try:
                async for proto_request in request_iterator:
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
                            f"Rate limit exceeded: {self.rate_limit} requests per minute allowed"
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
                                user_id=user_id,
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
                # Handle top-level exceptions
                logger.error(f"Top-level error in process_requests: {e}", exc_info=True)
                
                # Record error in telemetry
                if self.telemetry_collector:
                    await self.telemetry_collector.record_error_event(
                        session_id=session_id,
                        error_type=telemetry_pb2.ErrorEvent.ErrorType.INTERNAL,
                        error_code="STREAM_ERROR",
                        message=str(e),
                        context={"session_id": session_id},
                        severity=telemetry_pb2.TelemetryEvent.Severity.ERROR
                    )
            finally:
                # Clean up the session
                if session_id in self.active_sessions:
                    del self.active_sessions[session_id]
                
                # Log session end
                logger.info(f"Ending MCP session {session_id}")
                
                # Record telemetry event for session end
                if self.telemetry_collector:
                    await self.telemetry_collector.record_session_end(session_id)
        
        # Start processing requests in the background
        asyncio.create_task(process_requests())
        
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
                f"Rate limit exceeded: {self.rate_limit} requests per minute allowed"
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
        """Extract client IP address from gRPC context."""
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
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check if the client has exceeded the rate limit.
        
        Args:
            client_ip: The client's IP address.
            
        Returns:
            True if the request is allowed, False if it exceeds the rate limit.
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
        if len(self.rate_limit_state[client_ip]) >= self.rate_limit:
            logger.warning(f"Rate limit exceeded for client {client_ip}")
            return False
        
        # Add the current timestamp
        self.rate_limit_state[client_ip].append(current_time)
        return True
    
    async def _authenticate_request(
        self,
        request,
        context,
        security_context: