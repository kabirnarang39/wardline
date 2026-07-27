# OpenAI Agents SDK

The OpenAI Agents SDK has first-class MCP client support built in,
connecting over the same transport documented in the
[raw MCP client guide](mcp-client.md) — this guide only covers the
SDK-specific wrapper around it.

Verified against `openai-agents==0.18.3`.

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

**A single denied tool call can kill the whole MCP server connection for
that agent — this is the operationally important fact here, more than
which exception type to catch.** `MCPServerStreamableHttp` holds one
long-lived session, opened once and reused across every tool call
`Runner.run` makes — the same long-lived-session shape documented in the
[raw MCP client guide](mcp-client.md#how-a-policy-denial-surfaces).
Verified empirically against a real Wardline denial with
`openai-agents==0.18.3`: calling the server object's `call_tool()`
directly (bypassing the agent loop, to see the raw exception) raises
`asyncio.CancelledError` at the call site — **not**
`agents.exceptions.UserError` — and the session is left permanently
dead: every subsequent call on that same server, including a call to a
tool the policy *would* allow, also raises `CancelledError`.

```python
from agents.mcp import MCPServerStreamableHttp

async with MCPServerStreamableHttp(
    name="Wardline MCP Server",
    params={
        "url": "http://<wardline-listen-addr>/mcp",
        "headers": {"X-Wardline-Identity": "my-agent"},
        "timeout": 10,
    },
    cache_tools_list=True,
) as server:
    await server.call_tool("allowed_tool", {})   # succeeds
    try:
        await server.call_tool("denied_tool", {})
    except asyncio.CancelledError:
        print("denied — and this MCPServerStreamableHttp is now dead")
    # any further call_tool() on `server`, including to allowed_tool,
    # also raises CancelledError from here on — reconnect to recover.
```

This contradicts what the SDK's own source suggests at first read:
`agents/mcp/server.py` does contain code that converts an
`httpx.HTTPStatusError` into `agents.exceptions.UserError`, but that
conversion path is only reachable from `cleanup()` — it shows up as a
log line during connection teardown ("HTTP error during cleanup of MCP
server ...: 403 Forbidden"), not as something the caller's own code can
catch around a tool call.

There's a second, independent reason the previously-documented
`except UserError` pattern around `Runner.run(...)` wouldn't work even
if the exception type were right: `Runner.run`'s default tool-error
handling (`failure_error_function=default_tool_error_function`) catches
tool failures itself and turns them into a model-visible error string
inside the agent loop — it does not propagate as a Python exception to
your own code calling `Runner.run` in the normal case. Catching
anything around `Runner.run` for this purpose doesn't work regardless
of exception type; the agent loop absorbs it first.

**Practical takeaway:** if an operator needs the agent to keep working
after a policy denial, don't hold one `MCPServerStreamableHttp` across
many calls without a plan to reconnect after a failure — a single 403
from Wardline can silently take down that agent's entire MCP tool
connection, not just the one call.
