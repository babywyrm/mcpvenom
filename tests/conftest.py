"""Pytest fixtures for mcpnuke tests."""

import sys
from pathlib import Path

import pytest

# Ensure mcpnuke is importable (run from project root or mcpnuke/)
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))


@pytest.fixture
def target_result():
    """Create a TargetResult with sample tools for testing checks."""
    from mcpnuke.core.models import TargetResult

    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = [
        {
            "name": "safe_tool",
            "description": "A safe tool with no issues",
            "inputSchema": {"properties": {}},
        },
    ]
    return r


@pytest.fixture
def result_with_tools():
    """TargetResult factory that accepts tools list."""
    from mcpnuke.core.models import TargetResult

    def _make(tools: list, url: str = "http://localhost:9001/sse"):
        r = TargetResult(url=url)
        r.tools = tools
        return r

    return _make
