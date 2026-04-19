# TencentOS MCP Server

> MCP Server for TencentOS Server — 系统遥测、故障诊断、补丁评估、合规审计、配置调优

基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 构建，让 AI 助手（如 CodeBuddy / Cursor / VS Code Copilot）能够直接读取和分析 TencentOS Server 系统状态。

## ✨ 核心特性

### 基础层 — 系统遥测（对标 Red Hat linux-mcp-server）

| 模块 | 工具 | 说明 |
|------|------|------|
| **system_info** | `get_system_info` / `get_cpu_info` / `get_memory_info` / `get_disk_usage` | OS、内核、CPU、内存、磁盘 |
| **processes** | `list_processes` | 进程列表（按 CPU/内存排序） |
| **services** | `list_services` / `get_service_status` | systemd 服务状态 |
| **network** | `get_network_info` / `get_network_connections` | 网络接口、连接 |
| **storage** | `get_block_devices` | 块设备 |
| **logs** | `query_logs` | journalctl 日志查询 |

### 增强层 — 诊断与建议（TencentOS 独有）

| 模块 | 工具 | 解决的问题 |
|------|------|-----------|
| **① 补丁影响评估** | `assess_patch_impact` / `list_security_advisories` / `check_patch_dependencies` | 打补丁前评估对业务的影响，推荐修复策略 |
| **② 故障诊断** | `diagnose_system` / `get_error_timeline` / `check_resource_pressure` | 多源日志关联分析，读懂机器状态 |
| **③ 合规举证** | `audit_operations` / `check_compliance` / `get_privileged_operations` | 谁在什么时候操作了什么，审计取证 |
| **④ 补丁版本管理** | `get_patch_history` / `compare_patch_status` / `get_kernel_history` | 补丁履历 + 版本 Gap 分析 + CVE 交叉比对 |
| **⑤ 系统配置调优** | `analyze_system_tuning` / `get_workload_profile` / `check_kernel_parameters` | 负载画像 + 参数最佳实践对比 + 调优建议 |

> 🔒 **所有操作均为只读**。增强层仅提供诊断分析和建议，不会修改任何系统配置。

---

## 🎯 三种部署模式

先看清楚你要的是哪种模式，再看对应章节的安装步骤。

| 模式 | MCP Server 装在哪 | 被管机装什么 | 适用场景 |
|------|------------------|------------|---------|
| **A. 本地模式** | 你的机器 / 被管机本身 | — | 管一台本机，最简单 |
| **B. 跨机 SSH 模式** | 一台"管控机" | **零部署**（只需一个 SSH 账号） | 管远程一台或多台服务器 |
| **C. 多客户端共享 HTTP** | 一台"管控机" + 开启 HTTP 端口 | 同 B | 团队多人共用同一套 MCP |

> 💡 推荐路径：**先用 A 跑通 → 再切 B 验证跨机 → 有团队场景再上 C**

---

## 💻 本地 stdio 模式（模式 A）

> 最简单的起步方式：MCP Server 和 IDE 客户端跑在同一台机器上，管的也是这台机器。适合开发机体检、功能试跑。

### 1. 环境要求

- TencentOS Server 4 / CentOS 8+ / RHEL 8+（被管目标）
- Python 3.9+
- 管控机执行 `dnf` / `systemctl` / `journalctl` 需要合适的权限（通常是 root 或 sudoers）

### 2. 克隆 + 安装

```bash
git clone https://github.com/guoningzhang20/tencentos-mcp-server.git
cd tencentos-mcp-server
pip install .
```

安装完成后，系统里会多一个可执行命令：`/usr/local/bin/tencentos-mcp-server`（或你 venv 的 bin 目录）。

### 3. 选一种传输协议启动

```bash
# ① stdio 模式（默认）— 由 MCP 客户端（IDE）自动拉起，不要手动执行
#    配置方法见下方「IDE 配置」章节
tencentos-mcp-server

# ② SSE 模式 — 启动 HTTP 服务，适合远程连接或多客户端共享
tencentos-mcp-server --transport sse --host 0.0.0.0 --port 8000

# ③ Streamable HTTP 模式 — MCP 最新推荐协议
tencentos-mcp-server --transport streamable-http --host 0.0.0.0 --port 8000
```

> ⚠️ **stdio 模式通过 stdin/stdout 通信**，直接在终端执行会看到进程"卡住"等输入——这是正常行为，按 `Ctrl+C` 退出。如需手动测试功能，请用 SSE 或 Streamable HTTP 模式。

**三种传输协议对比：**

| 协议 | 启动方式 | 适用场景 |
|------|---------|---------|
| `stdio` | MCP 客户端（IDE）自动拉起子进程 | 本地 IDE 插件（CodeBuddy / Cursor），**无需手动运行** |
| `sse` | 手动启动 HTTP 服务，客户端连 `http://host:port/sse` | 远程服务器、多客户端共享 |
| `streamable-http` | 手动启动 HTTP 服务，客户端连 `http://host:port/mcp` | MCP 协议最新标准，推荐新项目使用 |

### 4. IDE 配置（CodeBuddy / Cursor / VS Code）

编辑 `~/.workbuddy/mcp.json`（或对应 IDE 的 MCP 配置文件）：

```json
{
  "mcpServers": {
    "tencentos": {
      "type": "stdio",
      "command": "tencentos-mcp-server"
    }
  }
}
```

保存 → 重启 IDE → 工具列表里能看到 `tencentos` 分组下的 26 个工具即为成功。

---

## 🌐 跨机 SSH 模式（模式 B）

**这是本项目最推荐的模式**：一台"管控机"跑 MCP Server，通过 SSH 远程操作多台被管目标机，被管机零部署。

### 架构

```
┌────────────┐          ┌──────────────────┐    SSH (asyncssh)   ┌─────────────────┐
│ AI 客户端  │  stdio   │  管控机           │ ──────────────────► │ 被管目标机       │
│ (IDE 插件) │ ───────► │  MCP Server       │                     │ 零部署           │
│            │ ◄─────── │  + SSH 密钥       │ ◄────────────────── │ TencentOS 4      │
└────────────┘          └──────────────────┘                     └─────────────────┘
```

### Step 1 — 在管控机装 MCP Server

```bash
git clone https://github.com/guoningzhang20/tencentos-mcp-server.git
cd tencentos-mcp-server
pip install .
```

### Step 2 — 打通 SSH 免密到被管机

```bash
# 管控机上生成密钥（如已有可跳过）
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''

# 把公钥下发到被管机
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@<TARGET_HOST>

# 权限必须严格
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519

# 首次手动 SSH 一次，把被管机指纹写入 known_hosts
ssh root@<TARGET_HOST> 'hostname && uname -r'
```

> ⚠️ **踩坑点**：`known_hosts` 里必须有被管机条目，否则 asyncssh 会报 `Host key verification failed`。如果你想禁用主机密钥校验（**仅限测试环境**），设置 `TENCENTOS_MCP_SSH_KNOWN_HOSTS=none`。

### Step 3 — 启动服务并指定被管机

```bash
TENCENTOS_MCP_HOST=<TARGET_HOST> \
TENCENTOS_MCP_USER=root \
TENCENTOS_MCP_SSH_KEY_PATH=/root/.ssh/id_ed25519 \
tencentos-mcp-server --transport streamable-http --host 0.0.0.0 --port 8000
```

### Step 4 — 验证 MCP 真的在管被管机（三方对照法）

这是今天调试最值钱的经验：**光看 MCP 返回不够，必须和 SSH 直连结果对照**。

```bash
# A. 直连被管机看真实 hostname
ssh root@<TARGET_HOST> 'hostname && uname -r && uptime -s'

# B. 通过 MCP 调 get_system_info，对比 hostname / kernel / 启动时间
curl -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_system_info","arguments":{}}}'

# A 和 B 的 hostname 一致 → 跨机管理链路打通
```

> ⚠️ **常见误判**：不要凭"主机名像"就下结论，同网段多台机器 hostname 规则可能雷同。**一律三方对照**（MCP 返回 vs SSH 直连 vs 云控制台）。

---

## 🏢 多客户端共享 HTTP 模式（模式 C）

在模式 B 基础上，加 **API Key 认证**+ **防火墙**+ **systemd 托管**，让团队多人共用同一台 MCP Server。

### Step 1 — 生成 API Key

```bash
openssl rand -hex 32
# 输出示例：7f3a8e2d9c1b4f5e6...（64 位随机 hex，请保管好）
```

**这个 key 是客户端的"暗号"，服务端启动参数和客户端配置必须完全一致。**

### Step 2 — 启动服务（带认证）

```bash
tencentos-mcp-server \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8000 \
  --api-key <YOUR_API_KEY>
```

| 参数 | 作用 |
|------|------|
| `--transport streamable-http` | MCP 最新推荐协议，标准 HTTP |
| `--host 0.0.0.0` | 监听所有网卡；`127.0.0.1` 则仅本机 |
| `--port 8000` | 任选未被占用的端口 |
| `--api-key` | Bearer Token 认证密钥，配合 `0.0.0.0` 必开 |

### Step 3 — 开放防火墙 + 腾讯云安全组

```bash
# firewalld
firewall-cmd --permanent --add-port=8000/tcp
firewall-cmd --reload
```

**如果机器在腾讯云，还必须去云控制台「安全组」里放行 8000/tcp 入方向**——这是最容易漏的一步，防火墙通了但安全组没开，外面死活连不上。

### Step 4 — 验证服务可用

```bash
# 1. 没 Key 应返回 401
curl -i http://127.0.0.1:8000/mcp

# 2. 带 Key 的完整 JSON-RPC 请求应返回 MCP 响应
curl -i -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer <YOUR_API_KEY>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

> ⚠️ **Accept 头必须同时带 `application/json, text/event-stream`**，少任何一个 MCP 服务端都会返回 **406 Not Acceptable**——这个错误排查起来巨耗时，今天就踩过。

### Step 5 — 客户端配置

```json
{
  "mcpServers": {
    "tencentos": {
      "type": "http",
      "url": "http://<你的管控机 IP>:8000/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_API_KEY>"
      }
    }
  }
}
```

**三个字段核对清单：**

- `type`：必须显式写 `"http"`，否则部分客户端会按 stdio 去拉子进程，报 `spawn ENOENT`
- `url`：`/mcp` 路径不能改
- `Authorization`：`Bearer ` + 空格 + API Key（大小写敏感，别漏空格）

### Step 6 — 生产化（systemd 托管，**必做**）

前台运行 SSH 一断服务就死，**生产环境必须用 systemd**：

```ini
# /etc/systemd/system/tencentos-mcp.service
[Unit]
Description=TencentOS MCP Server
After=network.target

[Service]
Type=simple
User=root
Environment="TENCENTOS_MCP_API_KEY=<YOUR_API_KEY>"
Environment="TENCENTOS_MCP_HOST=<TARGET_HOST>"
Environment="TENCENTOS_MCP_USER=root"
Environment="TENCENTOS_MCP_SSH_KEY_PATH=/root/.ssh/id_ed25519"
ExecStart=/usr/local/bin/tencentos-mcp-server \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tencentos-mcp
sudo systemctl status tencentos-mcp

# 查日志
journalctl -u tencentos-mcp -f
```

> 💡 **注意**：跨机 SSH 模式的所有环境变量（`TENCENTOS_MCP_HOST` 等）都要用 `Environment=` 在 unit 文件里声明，**当前 shell 的环境变量 systemd 拿不到**。

### Step 7 — 公网暴露（HTTPS + 反向代理）

如果 MCP Server 要暴露到公网，**Bearer Token 明文 HTTP 传输等于裸奔**，必须加 HTTPS。推荐 Nginx 反代：

```nginx
# /etc/nginx/conf.d/mcp.conf
server {
    listen 443 ssl http2;
    server_name mcp.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.yourdomain.com/privkey.pem;

    location /mcp {
        proxy_pass http://127.0.0.1:8000/mcp;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Streamable HTTP 长连接必需
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_set_header Connection "";
    }
}
```

此时服务端启动参数改为 `--host 127.0.0.1`（让 Nginx 作为唯一入口），客户端 `url` 改为 `https://mcp.yourdomain.com/mcp`。

---

## 🐳 容器运行（可选）

```bash
# 构建
docker build -f Containerfile -t tencentos-mcp-server:latest .

# 运行（本地模式）
docker run -i --rm tencentos-mcp-server:latest

# 运行（SSH 远程模式）
docker run -i --rm \
  -v ~/.ssh:/root/.ssh:ro \
  -e TENCENTOS_MCP_HOST=<TARGET_HOST> \
  -e TENCENTOS_MCP_USER=root \
  -e TENCENTOS_MCP_SSH_KEY_PATH=/root/.ssh/id_ed25519 \
  tencentos-mcp-server:latest
```

完整配置参见 [`mcp-config-example.json`](./mcp-config-example.json)。

---

## 🆘 常见问题排查

| 现象 | 原因 | 解决 |
|------|------|------|
| 客户端报 `spawn tencentos ENOENT` | 配置里缺 `"type": "http"`，被当 stdio 拉子进程 | 加 `"type": "http"` |
| 返回 `401 Unauthorized` | API Key 不匹配，或缺 `Bearer ` 前缀 | 检查 Header 与服务端 `--api-key` 一致 |
| 返回 `406 Not Acceptable` | 缺 `Accept: application/json, text/event-stream` | 补全 Accept 头 |
| 返回 `connection refused` / 超时 | 网络不通 | `curl <url>` 在客户端机器上测；检查 firewalld **和**云安全组 |
| SSH 断开后服务就停 | 前台进程随终端退出 | 上 systemd 托管（Step 6） |
| MCP 返回的 hostname / kernel 和预期不符 | 跨机配置不对 / 主机名雷同误判 | 三方对照：MCP 返回 vs `ssh root@<ip>` 直连 vs 云控制台 |
| `Host key verification failed` | 管控机 known_hosts 没有被管机指纹 | 先手动 `ssh root@<ip>` 一次接受指纹 |
| systemd 启动成功但环境变量没生效 | 用了当前 shell 的变量 | 所有变量必须写到 unit 文件的 `Environment=` 里 |
| MCP 进程存在但工具调用报错 | SSH 私钥权限不对 | `chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_ed25519` |

---

## 🏗️ 架构

```
┌──────────────────────────────────────────────────────────┐
│                    AI Agent (IDE)                         │
│               CodeBuddy / Cursor / VS Code               │
└───────┬──────────────┬───────────────┬───────────────────┘
        │ stdio        │ SSE          │ Streamable HTTP
        │ (子进程)      │ (HTTP 长连接) │ (HTTP 双向流)
        │              │ /sse         │ /mcp
┌───────▼──────────────▼───────────────▼───────────────────┐
│              TencentOS MCP Server                        │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  传输层 (Transport)                                  │ │
│  │  stdio  │  SSE (uvicorn)  │  Streamable HTTP        │ │
│  ├─────────────────────────────────────────────────────┤ │
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
| `TENCENTOS_MCP_TRANSPORT` | 传输协议（stdio / sse / streamable-http） | `stdio` |
| `TENCENTOS_MCP_BIND_HOST` | SSE/HTTP 监听地址 | `127.0.0.1` |
| `TENCENTOS_MCP_BIND_PORT` | SSE/HTTP 监听端口 | `8000` |
| `TENCENTOS_MCP_API_KEY` | SSE/HTTP 模式的 Bearer Token 认证密钥 | — |
| `TENCENTOS_MCP_HOST` | 目标主机 IP（空 = 本地执行） | — |
| `TENCENTOS_MCP_USER` | SSH 用户名 | `root` |
| `TENCENTOS_MCP_SSH_KEY_PATH` | SSH 私钥路径 | `~/.ssh/id_rsa` |
| `TENCENTOS_MCP_SSH_PORT` | SSH 端口 | `22` |
| `TENCENTOS_MCP_SSH_KNOWN_HOSTS` | SSH known_hosts（auto/none/路径） | `auto` |
| `TENCENTOS_MCP_AUDIT` | 启用工具调用审计日志 | `true` |
| `TENCENTOS_MCP_LOG_LEVEL` | 日志级别 | `INFO` |

## 🔒 安全

### 设计原则

- **全只读**：所有 26 个工具均标记 `readOnlyHint=True`，不执行任何修改操作
- **输入清理**：所有用户输入参数经过白名单验证，防止命令注入
- **审计日志**：每次工具调用自动记录（可通过 `TENCENTOS_MCP_AUDIT` 开关）
- **容器非 root**：Containerfile 中以 `mcp` 用户运行

### 安全建议

| 场景 | 建议 |
|------|------|
| **本地开发** | 使用 stdio 模式，无需额外安全配置 |
| **内网部署** | 使用 SSE/HTTP + API Key，监听 `127.0.0.1` |
| **公网暴露** | ⚠️ 强烈建议：反向代理 (nginx) + TLS + API Key |

## 📄 协议

Apache License 2.0

## 🙏 致谢

- [Red Hat linux-mcp-server](https://github.com/rhel-lightspeed/linux-mcp-server) — 本项目的设计灵感来源
- [FastMCP](https://github.com/jlowin/fastmcp) — Python MCP 框架
- [TencentOS Server](https://cloud.tencent.com/product/ts) — 腾讯云自研服务器操作系统
