import pytest

@pytest.fixture
def anyio_backend():
    """Default anyio backend to standard asyncio for consistent test execution."""
    return "asyncio"
