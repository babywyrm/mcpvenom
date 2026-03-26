"""Reporting: console and JSON output."""

from mcpvenom.reporting.console import print_report  # noqa: F401
from mcpvenom.reporting.json_out import write_json  # noqa: F401

__all__ = ["print_report", "write_json"]
