"""
mcpvenom — MCP Red Teaming & Security Scanner

Security auditing for Model Context Protocol servers. Enumerates tools,
probes for injection and poisoning, detects rug pulls, and audits
Kubernetes MCP deployments.

Usage:
    mcpvenom --targets http://localhost:9090
    mcpvenom --port-range localhost:9001-9010 --verbose
    python -m mcpvenom --targets http://localhost:9090
"""

__version__ = "6.0.0"
