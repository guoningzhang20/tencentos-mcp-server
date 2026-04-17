# TencentOS MCP Server

> MCP Server for TencentOS Server — 系统遥测、故障诊断、补丁评估、合规审计、配置调优

基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 构建，让 AI 助手（如 CodeBuddy / Cursor / VS Code Copilot）能够直接读取和分析 TencentOS Server 系统状态。

## ✨ 核心特性

### 基础层 — 系统遥测（对标 Red Hat linux-mcp-server）

| 模块 | 工具 | 说明 |
|------|------|------|
| **system_info** | `get_system_information` / `get_cpu_information` / `get_memory_information` | OS、内核、CPU、内存 |
| **processes** | `list_processes` / `find_process` | 进程列表与搜索 |
| **services** | `list_services` / `get_service_status` | systemd 服务状态 |
| **network** | `get_network_interfaces` / `get_network_connections` / `check_port` | 网络接口、连接、端口 |
| **storage** | `get_disk_usage` / `get_block_devices` | 磁盘与块设备 |
| **logs** | `query_journal_logs` | journalctl 日志查询 |

### 增强层 — 诊断与建议（TencentOS 独有）

| 模块 | 工具 | 解决的问题 |
|------|------|-----------|
| **① 补丁影响评估** | `assess_patch_impact` / `list_security_advisories` / `check_restart_requirements` | 打补丁前评估对业务的影响，推荐修复策略 |
| **② 故障诊断** | `diagnose_system` / `get_error_timeline` / `check_resource_pressure` | 多源日志关联分析，读懂机器状态 |
| **③ 合规举证** | `audit_operations` / `check_compliance` / `get_user_activities` | 谁在什么时候操作了什么，审计取证 |
| **④ 补丁版本管理** | `get_patch_history` / `compare_patch_status` / `get_kernel_history` | 补丁履历 + 版本 Gap 分析 + CVE 交叉比对 |
| **⑤ 系统配置调优** | `analyze_system_tuning` / `get_workload_profile` / `check_kernel_parameters` | 负载画像 + 参数最佳实践对比 + 调优建议 |

> 🔒 **所有操作均为只读**。增强层仅提供诊断分析和建议，不会修改任何系统配置。

## 🚀 快速开始

### 方式一：pip 安装（开发 / 本地调试）

```bash
# 安装
pip install -e .

# 运行（stdio 模式，供 MCP 客户端连接）
tencentos-mcp-server

# 或通过 Python module
python -m tencentos_mcp_server
```

### 方式二：容器运行（推荐生产使用）

```bash
# 构建
docker build -t tencentos-mcp-server:latest .

# 运行（本地模式）
docker run -i --rm tencentos-mcp-server:latest

# 运行（SSH 远程模式）
docker run -i --rm \
  -v ~/.ssh:/root/.ssh:ro \
  -e TENCENTOS_MCP_HOST=192.168.1.100 \
  -e TENCENTOS_MCP_USER=ops \
  -e TENCENTOS_MCP_SSH_KEY_PATH=/root/.ssh/id_ed25519 \
  tencentos-mcp-server:latest
```

## ⚙️ IDE 配置

### CodeBuddy / Cursor / VS Code

在 `~/.workbuddy/mcp.json`（或对应 IDE 的 MCP 配置文件）中添加：

```json
{
  "mcpServers": {
    "tencentos": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "${env:HOME}/.ssh:/root/.ssh:ro",
        "tencentos-mcp-server:latest"
      ],
      "env": {
        "TENCENTOS_MCP_HOST": "YOUR_SERVER_IP",
        "TENCENTOS_MCP_USER": "ops",
        "TENCENTOS_MCP_SSH_KEY_PATH": "/root/.ssh/id_ed25519"
      }
    }
  }
}
```

完整的配置示例参见 [`mcp-config-example.json`](./mcp-config-example.json)。

## 🏗️ 架构

```
┌──────────────────────────────────────────────────────────┐
│                    AI Agent (IDE)                         │
│               CodeBuddy / Cursor / VS Code               │
└────────────────────┬─────────────────────────────────────┘
                     │ MCP Protocol (stdio)
┌────────────────────▼─────────────────────────────────────┐
│              TencentOS MCP Server                        │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  基础层 (Base)                                       │ │
│  │  system_info │ processes │ services                  │ │
│  │  network     │ storage   │ logs                      │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  增强层 (Enhanced) — TencentOS 独有                  │ │
│  │  patch_impact │ diagnostics │ compliance             │ │
│  │  patch_history│ system_tuning                        │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  执行层 (Executor)                                   │ │
│  │  本地 subprocess  ←→  SSH asyncssh                   │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   ┌─────────────┐    ┌─────────────────┐
   │ TencentOS   │    │  TencentOS CVE  │
   │ Server      │    │  Database       │
   │ (本地/远程)  │    │  mirrors.       │
   │             │    │  tencent.com    │
   └─────────────┘    └─────────────────┘
```

## 📦 项目结构

```
tencentos-mcp-server/
├── pyproject.toml                    # 项目配置 & 依赖
├── Containerfile                     # 容器构建文件
├── README.md
├── LICENSE                           # Apache-2.0
├── mcp-config-example.json           # IDE MCP 配置示例
└── src/tencentos_mcp_server/
    ├── __init__.py
    ├── __main__.py                   # CLI 入口
    ├── server.py                     # FastMCP 实例 & 工具注册
    ├── executor.py                   # 命令执行抽象层
    ├── config.py                     # 配置管理
    ├── audit.py                      # 审计日志装饰器
    ├── models.py                     # Pydantic 数据模型
    ├── best_practices.py             # 调优最佳实践规则
    └── tools/
        ├── system_info.py            # 系统信息
        ├── processes.py              # 进程管理
        ├── services.py               # 服务状态
        ├── network.py                # 网络信息
        ├── storage.py                # 存储信息
        ├── logs.py                   # 日志查询
        ├── patch_impact.py           # ① 补丁影响评估
        ├── diagnostics.py            # ② 故障诊断
        ├── compliance.py             # ③ 合规举证
        ├── patch_history.py          # ④ 补丁版本管理
        └── system_tuning.py          # ⑤ 系统配置调优
```

## 🔑 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TENCENTOS_MCP_HOST` | 目标主机 IP（空 = 本地执行） | — |
| `TENCENTOS_MCP_USER` | SSH 用户名 | `root` |
| `TENCENTOS_MCP_SSH_KEY_PATH` | SSH 私钥路径 | `~/.ssh/id_rsa` |
| `TENCENTOS_MCP_SSH_PORT` | SSH 端口 | `22` |
| `TENCENTOS_MCP_LOG_LEVEL` | 日志级别 | `INFO` |

## 📄 协议

Apache License 2.0

## 🙏 致谢

- [Red Hat linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server) — 本项目的设计灵感来源
- [FastMCP](https://github.com/jlowin/fastmcp) — Python MCP 框架
- [TencentOS Server](https://cloud.tencent.com/product/ts) — 腾讯云自研服务器操作系统
