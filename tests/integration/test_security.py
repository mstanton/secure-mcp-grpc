"""
Integration tests for security features.
"""
import pytest
import asyncio
from secure_mcp_grpc.server import SecureMCPServer
from secure_mcp_grpc.client import SecureMCPClient
from secure_mcp_grpc.auth import MTLSAuthProvider

@pytest.mark.asyncio
async def test_mtls_authentication(
    test_server_cert: str,
    test_server_key: str,
    test_ca_cert: str
) -> None:
    """Test mutual TLS authentication between client and server."""
    # Create server with mTLS auth
    server_auth = MTLSAuthProvider(
        cert_path=test_server_cert,
        key_path=test_server_key,
        ca_path=test_ca_cert
    )
    
    server = SecureMCPServer(
        host="localhost",
        port=50051,
        auth_provider=server_auth
    )
    
    # Start server
    await server.start()
    
    try:
        # Create client with mTLS auth
        client_auth = MTLSAuthProvider(
            cert_path=test_server_cert,  # Using same cert for testing
            key_path=test_server_key,
            ca_path=test_ca_cert
        )
        
        client = SecureMCPClient(
            host="localhost",
            port=50051,
            auth_provider=client_auth
        )
        
        # Test connection
        await client.connect()
        assert client.is_connected()
        
        # Test basic request
        response = await client.send_request(
            method="test_method",
            params={"test": "value"}
        )
        assert response is not None
        
    finally:
        await server.stop()

@pytest.mark.asyncio
async def test_rate_limiting(
    test_server_cert: str,
    test_server_key: str,
    test_ca_cert: str
) -> None:
    """Test rate limiting functionality."""
    # Create server with rate limiting
    server_auth = MTLSAuthProvider(
        cert_path=test_server_cert,
        key_path=test_server_key,
        ca_path=test_ca_cert
    )
    
    server = SecureMCPServer(
        host="localhost",
        port=50051,
        auth_provider=server_auth,
        rate_limit=10  # 10 requests per second
    )
    
    # Start server
    await server.start()
    
    try:
        # Create client
        client_auth = MTLSAuthProvider(
            cert_path=test_server_cert,
            key_path=test_server_key,
            ca_path=test_ca_cert
        )
        
        client = SecureMCPClient(
            host="localhost",
            port=50051,
            auth_provider=client_auth
        )
        
        await client.connect()
        
        # Send multiple requests quickly
        tasks = []
        for _ in range(15):  # Exceed rate limit
            tasks.append(
                client.send_request(
                    method="test_method",
                    params={"test": "value"}
                )
            )
        
        # Some requests should fail due to rate limiting
        results = await asyncio.gather(*tasks, return_exceptions=True)
        rate_limit_errors = sum(1 for r in results if isinstance(r, Exception))
        assert rate_limit_errors > 0
        
    finally:
        await server.stop() 