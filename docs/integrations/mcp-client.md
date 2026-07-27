# Raw MCP Client

Every framework's MCP support (LangChain, LlamaIndex, OpenAI Agents SDK,
CrewAI) is a thin wrapper around the same mechanism this guide uses
directly: the official `mcp` Python SDK's streamable-HTTP transport.
Read this guide first — the other guides assume it.

Verified against `mcp==1.28.1`.

## Install

```bash
pip install mcp
```

## Connect through Wardline

```python
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def main():
    async with streamablehttp_client(
        "http://<wardline-listen-addr>/mcp",
        headers={"X-Wardline-Identity": "my-agent"},
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool("some_tool", {})
            print(result)

asyncio.run(main())
```

Replace `<wardline-listen-addr>` with wherever `wardline serve` is
listening, and point Wardline's own `upstream` config at your real MCP
server — Wardline forwards the handshake and the tool call transparently.

## How a policy denial surfaces

A `tools/call` Wardline's policy denies returns `403 Forbidden` at the
HTTP layer. The `mcp` SDK's transport calls `response.raise_for_status()`
on any non-2xx status inside an `anyio` task group — so the denial
surfaces as an `httpx.HTTPStatusError`, commonly wrapped in a Python
`ExceptionGroup` rather than a clean, single exception:

```python
try:
    result = await session.call_tool("some_tool", {})
except* Exception as eg:
    for e in eg.exceptions:
        print(type(e).__name__, e)
        if e.__cause__:
            print("  caused by:", e.__cause__)
```

(`except*` requires Python 3.11+. On 3.10, catch `ExceptionGroup`
directly and iterate its `.exceptions` attribute.) This is not specific
to Wardline — any MCP server's non-2xx response looks the same to this
transport.
