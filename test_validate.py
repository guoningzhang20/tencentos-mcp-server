#!/usr/bin/env python3
"""Quick validation script — imports all tools, calls each one locally."""

import asyncio
import json
import traceback
import sys
import os

# Force local execution
os.environ.pop("TENCENTOS_MCP_HOST", None)

# Register all tools
from tencentos_mcp_server.server import mcp, register_all_tools

results = {}

async def test_tool(name, coro):
    """Run a single tool and capture result or error."""
    try:
        result = await coro
        if hasattr(result, "model_dump"):
            data = result.model_dump()
        elif isinstance(result, list) and result and hasattr(result[0], "model_dump"):
            data = [r.model_dump() for r in result]
        else:
            data = result
        results[name] = {"status": "OK", "type": type(result).__name__, "sample": str(data)[:500]}
        print(f"  PASS {name}: OK")
        return True
    except Exception as e:
        results[name] = {"status": "FAIL", "error": str(e), "traceback": traceback.format_exc()[-500:]}
        print(f"  FAIL {name}: {e}")
        return False

def get_fn(tool_obj):
    """Extract the raw async function from a FunctionTool or return as-is."""
    if hasattr(tool_obj, 'fn'):
        return tool_obj.fn
    return tool_obj

async def main():
    ok = 0
    fail = 0

    print("\n" + "="*60)
    print("TencentOS MCP Server - Module Validation")
    print("="*60)

    # === Base Layer ===
    print("\n[Base Layer]")

    from tencentos_mcp_server.tools.system_info import get_system_info, get_cpu_info, get_memory_info, get_disk_usage
    for name, tool in [
        ("get_system_info", get_system_info),
        ("get_cpu_info", get_cpu_info),
        ("get_memory_info", get_memory_info),
        ("get_disk_usage", get_disk_usage),
    ]:
        fn = get_fn(tool)
        r = await test_tool(name, fn())
        ok += r; fail += (not r)

    from tencentos_mcp_server.tools.processes import list_processes
    fn = get_fn(list_processes)
    r = await test_tool("list_processes", fn())
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.services import list_services, get_service_status
    fn = get_fn(list_services)
    r = await test_tool("list_services", fn())
    ok += r; fail += (not r)
    fn = get_fn(get_service_status)
    r = await test_tool("get_service_status(sshd)", fn(service_name="sshd"))
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.network import get_network_info, get_network_connections
    fn = get_fn(get_network_info)
    r = await test_tool("get_network_info", fn())
    ok += r; fail += (not r)
    fn = get_fn(get_network_connections)
    r = await test_tool("get_network_connections", fn())
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.storage import get_block_devices
    fn = get_fn(get_block_devices)
    r = await test_tool("get_block_devices", fn())
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.logs import query_logs
    fn = get_fn(query_logs)
    r = await test_tool("query_logs", fn(lines=5))
    ok += r; fail += (not r)

    # === Enhanced Layer ===
    print("\n[Enhanced Layer]")

    from tencentos_mcp_server.tools.patch_impact import assess_patch_impact, list_security_advisories
    fn = get_fn(assess_patch_impact)
    r = await test_tool("assess_patch_impact", fn())
    ok += r; fail += (not r)
    fn = get_fn(list_security_advisories)
    r = await test_tool("list_security_advisories", fn())
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.diagnostics import diagnose_system, get_error_timeline, check_resource_pressure
    fn = get_fn(diagnose_system)
    r = await test_tool("diagnose_system", fn())
    ok += r; fail += (not r)
    fn = get_fn(get_error_timeline)
    r = await test_tool("get_error_timeline", fn())
    ok += r; fail += (not r)
    fn = get_fn(check_resource_pressure)
    r = await test_tool("check_resource_pressure", fn())
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.compliance import audit_operations, check_compliance, get_privileged_operations
    fn = get_fn(audit_operations)
    r = await test_tool("audit_operations", fn(days=1))
    ok += r; fail += (not r)
    fn = get_fn(check_compliance)
    r = await test_tool("check_compliance", fn())
    ok += r; fail += (not r)
    fn = get_fn(get_privileged_operations)
    r = await test_tool("get_privileged_operations", fn(days=1))
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.patch_history import get_patch_history, compare_patch_status, get_kernel_history
    fn = get_fn(get_patch_history)
    r = await test_tool("get_patch_history", fn(last_n=5))
    ok += r; fail += (not r)
    fn = get_fn(compare_patch_status)
    r = await test_tool("compare_patch_status", fn())
    ok += r; fail += (not r)
    fn = get_fn(get_kernel_history)
    r = await test_tool("get_kernel_history", fn())
    ok += r; fail += (not r)

    from tencentos_mcp_server.tools.system_tuning import analyze_system_tuning, get_workload_profile, check_kernel_parameters
    fn = get_fn(analyze_system_tuning)
    r = await test_tool("analyze_system_tuning", fn())
    ok += r; fail += (not r)
    fn = get_fn(get_workload_profile)
    r = await test_tool("get_workload_profile", fn())
    ok += r; fail += (not r)
    fn = get_fn(check_kernel_parameters)
    r = await test_tool("check_kernel_parameters", fn())
    ok += r; fail += (not r)

    # === Summary ===
    print("\n" + "="*60)
    total = ok + fail
    print(f"Total: {total} tools | PASS: {ok} | FAIL: {fail}")
    print("="*60)

    if fail > 0:
        print("\n--- Failure Details ---")
        for name, r in results.items():
            if r["status"] == "FAIL":
                print(f"\n{name}:")
                print(f"  Error: {r['error']}")
                print(f"  Traceback: {r['traceback']}")

    with open("/root/tencentos-mcp-server/test_report.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nDetailed report: /root/tencentos-mcp-server/test_report.json")

    return fail

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
