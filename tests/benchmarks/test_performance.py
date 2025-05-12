"""
Performance benchmarks for the MCP server.
"""
import asyncio
import time
from typing import List, Dict, Any
import pytest
from secure_mcp_grpc.client import SecureMCPClient
from secure_mcp_grpc.server import SecureMCPServer
from secure_mcp_grpc.auth import MTLSAuthProvider

@pytest.mark.benchmark
@pytest.mark.asyncio
async def test_request_latency(
    test_server_cert: str,
    test_server_key: str,
    test_ca_cert: str
) -> None:
    """Test request latency under load."""
    # Setup server
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
    
    await server.start()
    
    try:
        # Setup client
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
        
        # Run benchmark
        num_requests = 1000
        latencies: List[float] = []
        
        for _ in range(num_requests):
            start_time = time.time()
            await client.send_request(
                method="test_method",
                params={"test": "value"}
            )
            end_time = time.time()
            latencies.append(end_time - start_time)
        
        # Calculate statistics
        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
        p99_latency = sorted(latencies)[int(len(latencies) * 0.99)]
        
        print(f"\nLatency Statistics:")
        print(f"Average: {avg_latency*1000:.2f}ms")
        print(f"P95: {p95_latency*1000:.2f}ms")
        print(f"P99: {p99_latency*1000:.2f}ms")
        
        # Assert performance requirements
        assert avg_latency < 0.1  # Average latency < 100ms
        assert p95_latency < 0.2  # P95 latency < 200ms
        assert p99_latency < 0.5  # P99 latency < 500ms
        
    finally:
        await server.stop()

@pytest.mark.benchmark
@pytest.mark.asyncio
async def test_concurrent_requests(
    test_server_cert: str,
    test_server_key: str,
    test_ca_cert: str
) -> None:
    """Test server performance under concurrent load."""
    # Setup server
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
    
    await server.start()
    
    try:
        # Setup client
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
        
        # Run concurrent benchmark
        num_concurrent = 100
        num_requests = 1000
        start_time = time.time()
        
        async def make_request() -> None:
            for _ in range(num_requests // num_concurrent):
                await client.send_request(
                    method="test_method",
                    params={"test": "value"}
                )
        
        # Create concurrent tasks
        tasks = [make_request() for _ in range(num_concurrent)]
        await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        requests_per_second = num_requests / total_time
        
        print(f"\nConcurrent Performance:")
        print(f"Total time: {total_time:.2f}s")
        print(f"Requests per second: {requests_per_second:.2f}")
        
        # Assert performance requirements
        assert requests_per_second > 100  # At least 100 requests per second
        
    finally:
        await server.stop() 