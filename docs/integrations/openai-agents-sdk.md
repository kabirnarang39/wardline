# OpenAI Agents SDK

The OpenAI Agents SDK has first-class MCP client support built in,
connecting over the same transport documented in the
[raw MCP client guide](mcp-client.md) — this guide only covers the
SDK-specific wrapper around it.

Verified against the `openai-agents` package's current source (2026-07-27).

## Install

```bash
pip install openai-agents
```

## Connect through Wardline

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

async def main():
    async with MCPServerStreamableHttp(
        name="Wardline MCP Server",
        params={
            "url": "http://<wardline-listen-addr>/mcp",
            "headers": {"X-Wardline-Identity": "my-agent"},
            "timeout": 10,
        },
        cache_tools_list=True,
    ) as server:
        agent = Agent(
            name="Assistant",
            instructions="Use the MCP tools to answer questions.",
            mcp_servers=[server],
        )
        result = await Runner.run(agent, "List available tools and use one.")
        print(result.final_output)

asyncio.run(main())
```

Replace `<wardline-listen-addr>` with wherever `wardline serve` is
listening. `MCPServerSse` (same `params` shape) is also available for an
`/sse`-style upstream.

## How a policy denial surfaces

Unlike the other frameworks in this guide set, the OpenAI Agents SDK
*does* catch the raw transport error and re-raise it as its own typed
exception, `agents.exceptions.UserError`, rather than leaving a bare
`ExceptionGroup`/`httpx.HTTPStatusError` for the caller to unwrap:

```python
from agents import UserError

try:
    result = await Runner.run(agent, "call the protected tool")
except UserError as e:
    print(f"MCP call failed: {e.message}")
    if e.__cause__ is not None:
        print(f"HTTP status: {e.__cause__.response.status_code}")  # 403, etc.
```

`UserError` doesn't expose the original HTTP status code as a first-class
attribute, but the original `httpx.HTTPStatusError` is chained via
`from e` and reachable as `err.__cause__`.
