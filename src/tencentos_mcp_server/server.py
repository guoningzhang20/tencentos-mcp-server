"""FastMCP server instance and tool registration."""

from fastmcp import FastMCP

mcp = FastMCP(
    name="TencentOS MCP Server",
    instructions=(
        "TencentOS Server 系统管理 MCP 服务器。\n"
        "提供系统遥测、故障诊断、补丁评估、合规审计、配置调优等能力。\n"
        "所有操作均为只读，不会修改系统配置。"
    ),
)


def register_all_tools():
    """Import all tool modules to trigger @mcp.tool() registration."""
    # Base layer
    import tencentos_mcp_server.tools.system_info  # noqa: F401
    import tencentos_mcp_server.tools.processes  # noqa: F401
    import tencentos_mcp_server.tools.services  # noqa: F401
    import tencentos_mcp_server.tools.network  # noqa: F401
    import tencentos_mcp_server.tools.storage  # noqa: F401
    import tencentos_mcp_server.tools.logs  # noqa: F401

    # Enhanced layer
    import tencentos_mcp_server.tools.patch_impact  # noqa: F401
    import tencentos_mcp_server.tools.diagnostics  # noqa: F401
    import tencentos_mcp_server.tools.compliance  # noqa: F401
    import tencentos_mcp_server.tools.patch_history  # noqa: F401
    import tencentos_mcp_server.tools.system_tuning  # noqa: F401


register_all_tools()
