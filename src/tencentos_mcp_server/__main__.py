"""CLI entry point: python -m tencentos_mcp_server"""

import sys

from tencentos_mcp_server.server import mcp


def cli():
    """Run the TencentOS MCP Server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    cli()
