# LlamaIndex

LlamaIndex's MCP support (the `llama-index-tools-mcp` package) connects
over the same transport documented in the
[raw MCP client guide](mcp-client.md) — this guide only covers the
LlamaIndex-specific wrapper around it.

Verified against `llama-index-tools-mcp==0.4.8`.

## Install

```bash
pip install llama-index-tools-mcp
```

## Connect through Wardline

```python
import asyncio
from llama_index.tools.mcp import BasicMCPClient, McpToolSpec

async def main():
    client = BasicMCPClient(
        "http://<wardline-listen-addr>/mcp",
        headers={"X-Wardline-Identity": "my-agent"},
    )

    tool_spec = McpToolSpec(client=client)
    tools = await tool_spec.to_tool_list_async()
    print([t.metadata.name for t in tools])

    result = await client.call_tool("some_tool", {})
    print(result)

asyncio.run(main())
```

Replace `<wardline-listen-addr>` with wherever `wardline serve` is
listening. `BasicMCPClient` picks the streamable-HTTP transport
automatically for a plain `http(s)://` URL (an `/sse`-suffixed URL
selects SSE instead — the same `headers=` kwarg works for both).

## How a policy denial surfaces

Same underlying mechanism as the [raw MCP client](mcp-client.md#how-a-policy-denial-surfaces)
— `BasicMCPClient` has no try/except of its own around HTTP calls, it
delegates entirely to the `mcp` SDK's transport:

```python
import httpx

try:
    result = await client.call_tool("some_tool", {})
except* httpx.HTTPStatusError as eg:
    for e in eg.exceptions:
        print(e.response.status_code, e.response.reason_phrase)
```

(`e.response.text`/`.aread()` isn't safe to call here — by the time
this handler runs the underlying stream is already closed, and it
raises `httpx.ResponseNotRead`/`StreamClosed`; `.status_code` and
`.reason_phrase` are always safe.)

(On Python 3.10, `except*` isn't available — install the
`exceptiongroup` backport package (already a dependency of `mcp`/`anyio`
on that version) and `from exceptiongroup import ExceptionGroup`, then
catch `ExceptionGroup` directly and iterate `.exceptions`.) This is distinct from
`mcp.shared.exceptions.McpError`, which `ClientSession` raises for
JSON-RPC-level protocol errors after a successful HTTP 2xx — a Wardline
policy denial never reaches that layer, it fails at the transport level
as above.
