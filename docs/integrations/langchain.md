# LangChain

LangChain's MCP support (the `langchain-mcp-adapters` package) connects
over the same transport documented in the
[raw MCP client guide](mcp-client.md) — this guide only covers the
LangChain-specific wrapper around it.

Verified against `langchain-mcp-adapters==0.3.0` (requires `mcp>=1.9.2`).

## Install

```bash
pip install langchain-mcp-adapters
```

## Connect through Wardline

```python
import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient

async def main():
    client = MultiServerMCPClient(
        {
            "wardline": {
                "transport": "streamable_http",
                "url": "http://<wardline-listen-addr>/mcp",
                "headers": {"X-Wardline-Identity": "my-agent"},
            }
        }
    )

    tools = await client.get_tools()
    print([t.name for t in tools])

    result = await tools[0].ainvoke({})
    print(result)

asyncio.run(main())
```

Replace `<wardline-listen-addr>` with wherever `wardline serve` is
listening. `"transport"` also accepts `"http"` or `"streamable-http"` as
synonyms — `"streamable_http"` is the canonical documented value.

## How a policy denial surfaces

A denied `tools/call` fails the same way it does for the
[raw MCP client](mcp-client.md#how-a-policy-denial-surfaces) —
`langchain-mcp-adapters` doesn't catch or reshape the transport-level
error, it re-raises it unmodified:

```python
import httpx

try:
    result = await tools[0].ainvoke({})
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
catch `ExceptionGroup` directly and iterate `.exceptions`.) This is distinct from a genuine MCP
protocol-level tool error (`CallToolResult(isError=True)`, which
LangChain wraps as a `ToolException` or an error-status `ToolMessage`
depending on config) — a Wardline policy denial is an HTTP-transport
failure, not a protocol-level one, so it takes the `httpx.HTTPStatusError`
path above, not the `ToolException` path.
