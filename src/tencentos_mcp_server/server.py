"""FastMCP server instance and tool registration."""

from fastmcp import FastMCP

mcp = FastMCP(
    name="TencentOS MCP Server",
    instructions=(
        "TencentOS Server 系统管理 MCP 服务器。所有操作均为只读，不会修改系统配置。\n"
        "\n"
        "工具分为 5 个场景，请根据用户意图选择对应场景的工具，不要混用：\n"
        "\n"
        "1. **漏洞/补丁检查**（用户问：有没有漏洞、需不需要打补丁、CVE）\n"
        "   → assess_patch_impact / list_security_advisories / compare_patch_status / check_patch_dependencies\n"
        "\n"
        "2. **故障诊断**（用户问：机器状态、有什么问题、为什么慢、日志报错）\n"
        "   → diagnose_system / get_error_timeline / check_resource_pressure\n"
        "\n"
        "3. **合规审计**（用户问：谁登录了、谁操作了什么、能不能过审计）\n"
        "   → audit_operations / check_compliance / get_privileged_operations\n"
        "\n"
        "4. **补丁历史**（用户问：打过哪些补丁、内核版本变化、补丁时间线）\n"
        "   → get_patch_history / get_kernel_history\n"
        "\n"
        "5. **配置调优**（用户问：参数是否最优、该怎么调、负载类型）\n"
        "   → analyze_system_tuning / get_workload_profile / check_kernel_parameters\n"
        "\n"
        "基础信息工具（system_info/processes/services/network/storage/logs）可在任何场景中辅助使用。"
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
