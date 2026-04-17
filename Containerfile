# TencentOS Server 4 slim as base
FROM ccr.ccs.tencentyun.com/tencentos/tencentos-server-4:latest

LABEL maintainer="TencentOS Team"
LABEL description="TencentOS MCP Server — system telemetry, diagnostics, and recommendations"
LABEL version="0.1.0"

# Install Python 3.11+ and build dependencies
RUN dnf install -y python3.11 python3.11-pip openssh-clients && \
    dnf clean all && \
    alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1

# Create non-root user
RUN useradd -m -s /bin/bash mcp

# Copy project files
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package
RUN python3 -m pip install --no-cache-dir -e .

# Switch to non-root
USER mcp

# stdio transport — MCP clients connect via stdin/stdout
ENTRYPOINT ["tencentos-mcp-server"]
