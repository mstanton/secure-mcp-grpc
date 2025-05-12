"""
Pytest configuration and common fixtures.
"""
import os
import pytest
import asyncio
from typing import AsyncGenerator, Generator

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def test_cert_path() -> str:
    """Return path to test certificates."""
    return os.path.join(os.path.dirname(__file__), "fixtures", "certs")

@pytest.fixture(scope="session")
def test_server_cert() -> str:
    """Return path to server certificate."""
    return os.path.join(test_cert_path(), "server.crt")

@pytest.fixture(scope="session")
def test_server_key() -> str:
    """Return path to server key."""
    return os.path.join(test_cert_path(), "server.key")

@pytest.fixture(scope="session")
def test_ca_cert() -> str:
    """Return path to CA certificate."""
    return os.path.join(test_cert_path(), "ca.crt") 