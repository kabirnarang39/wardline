"""Real end-to-end proof that a real MCP client can complete the
initialize handshake through Wardline, call an allowed tool, and have a
denied tool still correctly rejected by policy. Every framework guide in
this directory depends on this same underlying mechanism — this script
demonstrates it directly, using only the official mcp SDK (no
LangChain/LlamaIndex/CrewAI/OpenAI Agents SDK install required).

Usage:
    go build -o /tmp/wardline-bin ./cmd/wardline   # from the repo root
    python3 -m venv /tmp/wardline-integrations-venv
    source /tmp/wardline-integrations-venv/bin/activate
    pip install mcp uvicorn
    python3 docs/integrations/examples/mcp_client_smoke_test.py
"""
import asyncio
import os
import subprocess
import sys
import tempfile
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


UPSTREAM_SERVER_CODE = '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("integrations-smoke-upstream", stateless_http=True, port=%(upstream_port)d)

@mcp.tool()
def allowed_tool() -> str:
    """A tool this smoke test's policy allows for the test identity."""
    return "allowed_tool result"

@mcp.tool()
def denied_tool() -> str:
    """A tool this smoke test's policy denies for the test identity."""
    return "denied_tool result"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
'''

POLICY_YAML = """
rules:
  - identity: "smoke-agent"
    tool: "allowed_tool"
    effect: allow
  - identity: "smoke-agent"
    tool: "*"
    effect: deny
default: deny
"""


async def call_tool(wardline_port, tool_name):
    async with streamablehttp_client(
        f"http://127.0.0.1:{wardline_port}/mcp",
        headers={"X-Wardline-Identity": "smoke-agent"},
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(tool_name, {})


async def main():
    wardline_bin = os.environ.get("WARDLINE_BIN", "/tmp/wardline-bin")
    if not os.path.exists(wardline_bin):
        print(f"Build wardline first: go build -o {wardline_bin} ./cmd/wardline", file=sys.stderr)
        sys.exit(1)

    upstream_port = 18200
    wardline_port = 18201

    with tempfile.TemporaryDirectory() as d:
        upstream_path = os.path.join(d, "upstream.py")
        with open(upstream_path, "w") as f:
            f.write(UPSTREAM_SERVER_CODE % {"upstream_port": upstream_port})

        policy_path = os.path.join(d, "policy.yaml")
        with open(policy_path, "w") as f:
            f.write(POLICY_YAML)

        config_path = os.path.join(d, "wardline.yaml")
        with open(config_path, "w") as f:
            f.write(f"""
listen: ":{wardline_port}"
upstream: "http://127.0.0.1:{upstream_port}"
policy_file: "{policy_path}"
audit:
  output: stdout
features: {{}}
""")

        upstream_proc = subprocess.Popen([sys.executable, upstream_path])
        wardline_proc = subprocess.Popen([wardline_bin, "serve", "--config", config_path])
        time.sleep(2)

        try:
            print("=== initialize + call allowed_tool ===")
            result = await call_tool(wardline_port, "allowed_tool")
            print("SUCCESS:", result)
            assert not result.isError, "expected allowed_tool to succeed"

            print("=== initialize + call denied_tool ===")
            try:
                result = await call_tool(wardline_port, "denied_tool")
                print("UNEXPECTED SUCCESS:", result)
                sys.exit(1)
            except* Exception as eg:
                for e in eg.exceptions:
                    print("EXPECTED DENIAL:", type(e).__name__, str(e)[:200])

            print("\nAll checks passed: handshake works, allowed tool succeeds, denied tool is still rejected.")
        finally:
            wardline_proc.terminate()
            upstream_proc.terminate()
            wardline_proc.wait(timeout=5)
            upstream_proc.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())
