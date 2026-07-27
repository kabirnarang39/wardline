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
(`/mcp` here is FastMCP's own default mount point for its streamable-HTTP
endpoint, not something Wardline requires or enforces — Wardline forwards
whatever path the client requests verbatim, so match whatever path
segment your specific upstream MCP server actually mounts on.)

## How a policy denial surfaces

A `tools/call` Wardline's policy denies returns `403 Forbidden` at the
HTTP layer. Catching this correctly requires wrapping the entire
connection, not just the tool call — open a fresh session per call and
put your `try` around the whole `async with` chain:

```python
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def call_tool(tool_name, arguments):
    async with streamablehttp_client(
        "http://<wardline-listen-addr>/mcp",
        headers={"X-Wardline-Identity": "my-agent"},
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(tool_name, arguments)

try:
    result = await call_tool("some_tool", {})
    print(result)
except* httpx.HTTPStatusError as eg:
    for e in eg.exceptions:
        print(e.response.status_code, e.response.reason_phrase)
```

This works because the denial cancels the transport's `anyio` task
group — the resulting `ExceptionGroup[httpx.HTTPStatusError]` only
surfaces when the `async with streamablehttp_client(...)` block exits,
not at the `call_tool()` call site itself. A `try` placed only around
`call_tool()`, still inside the `async with` blocks, will NOT catch it —
verified empirically against a real Wardline denial. (Note also that the
response object is a streaming response Wardline never sends a body for
past its status — `e.response.text`/`.aread()` raises
`httpx.ResponseNotRead`/`StreamClosed` by the time this handler runs;
`.status_code` and `.reason_phrase` are always safe to read.)

**Don't reuse one session across multiple calls if you need to handle
denials gracefully.** A denial on a long-lived session (one `initialize`
followed by many `call_tool` calls) doesn't raise a catchable
`httpx.HTTPStatusError` at all — it raises `asyncio.CancelledError` at
the call site instead, and permanently kills the session: every
subsequent call on that same session, including calls to tools the
policy *would* allow, also raises `CancelledError`. Open a fresh session
per call (as shown above) if a caller needs to keep working after a
denial.

(On Python 3.10, `except*` isn't available — install the
`exceptiongroup` backport package (already a dependency of `mcp`/`anyio`
on that version) and `from exceptiongroup import ExceptionGroup`, then
catch `ExceptionGroup` directly and iterate `.exceptions`.)

This is not specific to Wardline — any MCP server's non-2xx response
looks the same to this transport.
