"""Real end-to-end proof that a real MCP client can complete the
initialize handshake through Wardline, call an allowed tool, and have a
denied tool still correctly rejected by policy. Every framework guide in
this directory depends on this same underlying mechanism — this script
demonstrates it directly, using only the official mcp SDK (no
LangChain/LlamaIndex/CrewAI/OpenAI Agents SDK install required).

Requires Python 3.11+ (uses `except*` syntax).

Usage:
    go build -o /tmp/wardline-bin ./cmd/wardline   # from the repo root
    python3 -m venv /tmp/wardline-integrations-venv
    source /tmp/wardline-integrations-venv/bin/activate
    pip install mcp
    python3 docs/integrations/examples/mcp_client_smoke_test.py

Ports default to 18200 (upstream) / 18201 (wardline); override with the
SMOKE_TEST_UPSTREAM_PORT / SMOKE_TEST_WARDLINE_PORT env vars if either is
taken on your machine.
"""
import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time

import httpx
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


def wait_until_ready(proc, port, name, timeout=5.0):
    """Poll until `port` accepts connections, or fail fast if `proc` has
    already exited (a clearer signal than an opaque connection error)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited early with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{name} did not start listening on port {port} within {timeout}s")


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

    upstream_port = int(os.environ.get("SMOKE_TEST_UPSTREAM_PORT", 18200))
    wardline_port = int(os.environ.get("SMOKE_TEST_WARDLINE_PORT", 18201))

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

        try:
            wait_until_ready(upstream_proc, upstream_port, "upstream server")
            wait_until_ready(wardline_proc, wardline_port, "wardline")

            print("=== initialize + call allowed_tool ===")
            result = await call_tool(wardline_port, "allowed_tool")
            print("SUCCESS:", result)
            assert not result.isError, "expected allowed_tool to succeed"

            print("=== initialize + call denied_tool ===")
            try:
                result = await call_tool(wardline_port, "denied_tool")
                print("UNEXPECTED SUCCESS:", result)
                sys.exit(1)
            except* httpx.HTTPStatusError as eg:
                saw_403 = False
                for e in eg.exceptions:
                    print("EXPECTED DENIAL:", type(e).__name__, str(e)[:200])
                    if e.response.status_code == 403:
                        saw_403 = True
                if not saw_403:
                    raise RuntimeError(
                        "denied_tool call raised HTTPStatusError(s) but none was a 403 "
                        "— this is not the policy denial we expected"
                    )

            print("\nAll checks passed: handshake works, allowed tool succeeds, denied tool is still rejected.")
        finally:
            for proc in (wardline_proc, upstream_proc):
                proc.terminate()
            for proc in (wardline_proc, upstream_proc):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass  # nothing more we can do; don't let this mask the real exception


if __name__ == "__main__":
    asyncio.run(main())
