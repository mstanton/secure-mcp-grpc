"""
Security Configuration Module

This module defines the security configuration models and validation rules for the Secure MCP-gRPC server.
Implements strict validation using Pydantic models and provides security-focused configuration options.

Author: Matthew Stanton && Claude.ai
License: Apache 2.0
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
from datetime import timedelta

class SecurityConfig(BaseModel):
    """
    Main security configuration model for the MCP server.
    
    Attributes:
        max_request_size: Maximum allowed request size in bytes
        max_sessions_per_ip: Maximum concurrent sessions per IP address
        session_timeout: Session timeout in seconds
        rate_limit: Requests per minute per client
        allowed_methods: List of allowed gRPC methods
        blocked_ips: List of blocked IP addresses
        require_mtls: Whether mTLS is required
        jwt_secret: Secret key for JWT validation
        cors_origins: Allowed CORS origins
    """
    max_request_size: int = Field(
        default=1024 * 1024,  # 1MB
        description="Maximum allowed request size in bytes"
    )
    max_sessions_per_ip: int = Field(
        default=100,
        description="Maximum concurrent sessions per IP address"
    )
    session_timeout: int = Field(
        default=3600,  # 1 hour
        description="Session timeout in seconds"
    )
    rate_limit: int = Field(
        default=100,
        description="Requests per minute per client"
    )
    allowed_methods: List[str] = Field(
        default=["Call", "Reflect", "HealthStream"],
        description="List of allowed gRPC methods"
    )
    blocked_ips: List[str] = Field(
        default=[],
        description="List of blocked IP addresses"
    )
    require_mtls: bool = Field(
        default=True,
        description="Whether mTLS is required"
    )
    jwt_secret: Optional[str] = Field(
        default=None,
        description="Secret key for JWT validation"
    )
    cors_origins: List[str] = Field(
        default=["*"],
        description="Allowed CORS origins"
    )

    @validator('max_request_size')
    def validate_max_request_size(cls, v):
        """Validate maximum request size."""
        if v < 1024:  # Minimum 1KB
            raise ValueError("max_request_size must be at least 1024 bytes")
        if v > 10 * 1024 * 1024:  # Maximum 10MB
            raise ValueError("max_request_size cannot exceed 10MB")
        return v

    @validator('max_sessions_per_ip')
    def validate_max_sessions(cls, v):
        """Validate maximum sessions per IP."""
        if v < 1:
            raise ValueError("max_sessions_per_ip must be at least 1")
        if v > 1000:
            raise ValueError("max_sessions_per_ip cannot exceed 1000")
        return v

    @validator('session_timeout')
    def validate_session_timeout(cls, v):
        """Validate session timeout."""
        if v < 60:  # Minimum 1 minute
            raise ValueError("session_timeout must be at least 60 seconds")
        if v > 24 * 3600:  # Maximum 24 hours
            raise ValueError("session_timeout cannot exceed 24 hours")
        return v

    @validator('rate_limit')
    def validate_rate_limit(cls, v):
        """Validate rate limit."""
        if v < 1:
            raise ValueError("rate_limit must be at least 1 request per minute")
        if v > 10000:
            raise ValueError("rate_limit cannot exceed 10000 requests per minute")
        return v

    class Config:
        """Pydantic model configuration."""
        validate_assignment = True
        extra = "forbid" 