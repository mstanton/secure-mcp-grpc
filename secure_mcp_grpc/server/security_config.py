"""
Security Configuration Module

This module defines the security configuration models and validation rules for the Secure MCP-gRPC server.
Implements strict validation using Pydantic models and provides comprehensive security-focused configuration options.

The configuration implements defense-in-depth security principles including:
- Request size limits and rate limiting
- Session management and timeout controls
- Method access control
- IP-based access control
- mTLS configuration
- JWT validation
- OAuth2 configuration
- API key management
- CORS policies
- Security headers
- Audit logging
- Account lockout
- Token management

Author: Matthew Stanton && Claude.ai
License: Apache 2.0
"""

from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field, validator, SecretStr, HttpUrl
from datetime import timedelta
import ipaddress
import json

class SecurityHeaders(BaseModel):
    """
    Security headers configuration model.
    
    Attributes:
        content_security_policy: CSP header value
        x_content_type_options: MIME type sniffing prevention
        x_frame_options: Clickjacking prevention
        x_xss_protection: XSS filtering
        strict_transport_security: HTTPS enforcement
        referrer_policy: Referrer information control
        permissions_policy: Browser features control
    """
    content_security_policy: str = Field(
        default="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'",
        description="Content Security Policy header value"
    )
    x_content_type_options: str = Field(
        default="nosniff",
        description="X-Content-Type-Options header value"
    )
    x_frame_options: str = Field(
        default="DENY",
        description="X-Frame-Options header value"
    )
    x_xss_protection: str = Field(
        default="1; mode=block",
        description="X-XSS-Protection header value"
    )
    strict_transport_security: str = Field(
        default="max-age=31536000; includeSubDomains",
        description="Strict-Transport-Security header value"
    )
    referrer_policy: str = Field(
        default="strict-origin-when-cross-origin",
        description="Referrer-Policy header value"
    )
    permissions_policy: str = Field(
        default="geolocation=(), microphone=(), camera=()",
        description="Permissions-Policy header value"
    )

class OAuth2Config(BaseModel):
    """
    OAuth2 configuration model.
    
    Attributes:
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        token_url: OAuth2 token endpoint
        jwks_url: JWKS endpoint for token validation
        scope: Required OAuth2 scope
        audience: Required audience claim
        issuer: Required issuer claim
    """
    client_id: str = Field(
        ...,
        description="OAuth2 client ID"
    )
    client_secret: SecretStr = Field(
        ...,
        description="OAuth2 client secret"
    )
    token_url: HttpUrl = Field(
        ...,
        description="OAuth2 token endpoint"
    )
    jwks_url: HttpUrl = Field(
        ...,
        description="JWKS endpoint for token validation"
    )
    scope: str = Field(
        default="openid profile email",
        description="Required OAuth2 scope"
    )
    audience: str = Field(
        ...,
        description="Required audience claim"
    )
    issuer: str = Field(
        ...,
        description="Required issuer claim"
    )

class SecurityConfig(BaseModel):
    """
    Main security configuration model for the MCP server.
    
    Implements comprehensive security controls with secure defaults and strict validation.
    All configuration values are validated to ensure they meet security requirements.
    
    Attributes:
        max_request_size: Maximum allowed request size in bytes
        max_sessions_per_ip: Maximum concurrent sessions per IP address
        session_timeout: Session timeout in seconds
        rate_limit: Requests per minute per client
        allowed_methods: Set of allowed gRPC methods
        blocked_ips: Set of blocked IP addresses
        require_mtls: Whether mTLS is required
        jwt_secret: Secret key for JWT validation
        jwt_audience: Required JWT audience claim
        jwt_issuer: Required JWT issuer claim
        oauth2_config: OAuth2 configuration
        api_keys: Map of API keys to user IDs
        cors_origins: Set of allowed CORS origins
        security_headers: Security headers configuration
        audit_logging: Whether to enable audit logging
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds
        allowed_ciphers: Set of allowed TLS ciphers
        min_tls_version: Minimum TLS version
        max_failed_attempts: Maximum failed authentication attempts before lockout
        account_lockout_duration: Account lockout duration in seconds
        token_expiry: Token expiry duration in seconds
        require_secure_cookies: Whether to require secure cookies
        password_policy: Password policy configuration
    """
    max_request_size: int = Field(
        default=1024 * 1024,  # 1MB
        description="Maximum allowed request size in bytes",
        ge=1024,  # Minimum 1KB
        le=10 * 1024 * 1024  # Maximum 10MB
    )
    max_sessions_per_ip: int = Field(
        default=100,
        description="Maximum concurrent sessions per IP address",
        ge=1,
        le=1000
    )
    session_timeout: int = Field(
        default=3600,  # 1 hour
        description="Session timeout in seconds",
        ge=60,  # Minimum 1 minute
        le=24 * 3600  # Maximum 24 hours
    )
    rate_limit: int = Field(
        default=100,
        description="Requests per minute per client",
        ge=1,
        le=10000
    )
    allowed_methods: Set[str] = Field(
        default={"Call", "Reflect", "HealthStream"},
        description="Set of allowed gRPC methods"
    )
    blocked_ips: Set[str] = Field(
        default=set(),
        description="Set of blocked IP addresses"
    )
    require_mtls: bool = Field(
        default=True,
        description="Whether mTLS is required"
    )
    jwt_secret: Optional[SecretStr] = Field(
        default=None,
        description="Secret key for JWT validation"
    )
    jwt_audience: Optional[str] = Field(
        default=None,
        description="Required JWT audience claim"
    )
    jwt_issuer: Optional[str] = Field(
        default=None,
        description="Required JWT issuer claim"
    )
    oauth2_config: Optional[OAuth2Config] = Field(
        default=None,
        description="OAuth2 configuration"
    )
    api_keys: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of API keys to user IDs"
    )
    cors_origins: Set[str] = Field(
        default={"*"},
        description="Set of allowed CORS origins"
    )
    security_headers: SecurityHeaders = Field(
        default_factory=SecurityHeaders,
        description="Security headers configuration"
    )
    audit_logging: bool = Field(
        default=True,
        description="Whether to enable audit logging"
    )
    max_retries: int = Field(
        default=3,
        description="Maximum number of retry attempts",
        ge=0,
        le=10
    )
    retry_delay: int = Field(
        default=1,
        description="Delay between retries in seconds",
        ge=0,
        le=60
    )
    allowed_ciphers: Set[str] = Field(
        default={
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256"
        },
        description="Set of allowed TLS ciphers"
    )
    min_tls_version: str = Field(
        default="TLSv1.3",
        description="Minimum TLS version",
        regex="^TLSv1\.[23]$"
    )
    max_failed_attempts: int = Field(
        default=5,
        description="Maximum failed authentication attempts before lockout",
        ge=1,
        le=10
    )
    account_lockout_duration: int = Field(
        default=1800,  # 30 minutes
        description="Account lockout duration in seconds",
        ge=60,  # Minimum 1 minute
        le=86400  # Maximum 24 hours
    )
    token_expiry: int = Field(
        default=3600,  # 1 hour
        description="Token expiry duration in seconds",
        ge=300,  # Minimum 5 minutes
        le=86400  # Maximum 24 hours
    )
    require_secure_cookies: bool = Field(
        default=True,
        description="Whether to require secure cookies"
    )
    password_policy: Dict[str, Any] = Field(
        default={
            "min_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "max_age_days": 90,
            "history_size": 5
        },
        description="Password policy configuration"
    )

    @validator('blocked_ips')
    def validate_blocked_ips(cls, v: Set[str]) -> Set[str]:
        """
        Validate blocked IP addresses.
        
        Args:
            v: Set of IP addresses to validate
            
        Returns:
            Set[str]: Validated set of IP addresses
            
        Raises:
            ValueError: If any IP address is invalid
        """
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError as e:
                raise ValueError(f"Invalid IP address in blocked_ips: {ip}") from e
        return v

    @validator('cors_origins')
    def validate_cors_origins(cls, v: Set[str]) -> Set[str]:
        """
        Validate CORS origins.
        
        Args:
            v: Set of CORS origins to validate
            
        Returns:
            Set[str]: Validated set of CORS origins
            
        Raises:
            ValueError: If any origin is invalid
        """
        if "*" in v and len(v) > 1:
            raise ValueError("Wildcard origin '*' cannot be combined with other origins")
        return v

    @validator('allowed_ciphers')
    def validate_allowed_ciphers(cls, v: Set[str]) -> Set[str]:
        """
        Validate allowed TLS ciphers.
        
        Args:
            v: Set of cipher names to validate
            
        Returns:
            Set[str]: Validated set of cipher names
            
        Raises:
            ValueError: If any cipher is invalid
        """
        valid_ciphers = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_128_CCM_SHA256",
            "TLS_AES_128_CCM_8_SHA256"
        }
        invalid_ciphers = v - valid_ciphers
        if invalid_ciphers:
            raise ValueError(f"Invalid TLS ciphers: {invalid_ciphers}")
        return v

    @validator('jwt_secret')
    def validate_jwt_config(cls, v: Optional[SecretStr], values: Dict[str, Any]) -> Optional[SecretStr]:
        """
        Validate JWT configuration.
        
        Args:
            v: JWT secret to validate
            values: Other configuration values
            
        Returns:
            Optional[SecretStr]: Validated JWT secret
            
        Raises:
            ValueError: If JWT configuration is invalid
        """
        if v is not None:
            if not values.get('jwt_audience'):
                raise ValueError("jwt_audience is required when jwt_secret is set")
            if not values.get('jwt_issuer'):
                raise ValueError("jwt_issuer is required when jwt_secret is set")
        return v

    @validator('password_policy')
    def validate_password_policy(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate password policy configuration.
        
        Args:
            v: Password policy to validate
            
        Returns:
            Dict[str, Any]: Validated password policy
            
        Raises:
            ValueError: If password policy is invalid
        """
        if v['min_length'] < 8:
            raise ValueError("Minimum password length must be at least 8 characters")
        if v['max_age_days'] < 30:
            raise ValueError("Maximum password age must be at least 30 days")
        if v['history_size'] < 1:
            raise ValueError("Password history size must be at least 1")
        return v

    class Config:
        """Pydantic model configuration."""
        validate_assignment = True
        extra = "forbid"
        json_encoders = {
            SecretStr: lambda v: v.get_secret_value() if v else None
        } 