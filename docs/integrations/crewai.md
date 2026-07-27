# CrewAI

CrewAI's MCP support (the `crewai-tools` package's `MCPServerAdapter`)
connects over the same transport documented in the
[raw MCP client guide](mcp-client.md) — this guide only covers the
CrewAI-specific wrapper around it.

Verified against `crewai-tools[mcp]` (pins `mcp>=1.28.1,<2`,
`mcpadapt>=0.1.9`) — code lives in the `crewAIInc/crewAI` monorepo; the
older standalone `crewAI-tools` repo is archived and its README examples
are stale.

## Install

```bash
pip install 'crewai-tools[mcp]'
```

## Connect through Wardline

```python
from crewai import Agent, Task, Crew
from crewai_tools import MCPServerAdapter

server_params = {
    "url": "http://<wardline-listen-addr>/mcp",
    "transport": "streamable-http",
    "headers": {"X-Wardline-Identity": "my-agent"},
}

with MCPServerAdapter(server_params, connect_timeout=60) as tools:
    print([t.name for t in tools])

    agent = Agent(
        role="Tool User",
        goal="Use the MCP-provided tools to complete the task",
        backstory="An agent wired to remote MCP tools via Wardline.",
        tools=tools,
        verbose=True,
    )
    task = Task(description="...", expected_output="...", agent=agent)
    Crew(agents=[agent], tasks=[task]).kickoff()
```

Replace `<wardline-listen-addr>` with wherever `wardline serve` is
listening. `connect_timeout` (default 30s) is the adapter's own timeout
for establishing the connection.

## How a policy denial surfaces

Two distinct cases:

**A denial during the initial connection** (entering the `with
MCPServerAdapter(...)` block) is wrapped in a plain `RuntimeError`:

```python
try:
    with MCPServerAdapter(server_params) as tools:
        ...
except RuntimeError as e:
    print(e)            # "Failed to initialize MCP Adapter: ..."
    print(e.__cause__)   # the original httpx.HTTPStatusError
```

**A denial on an individual tool call** (connection already
established) is NOT caught by CrewAI or its `mcpadapt` dependency — it
surfaces the same way it does for the
[raw MCP client](mcp-client.md#how-a-policy-denial-surfaces), an
`httpx.HTTPStatusError` commonly wrapped in an `ExceptionGroup`:

```python
import httpx

try:
    result = some_mcp_tool.run(**kwargs)
except* httpx.HTTPStatusError as eg:
    for e in eg.exceptions:
        print(e.response.status_code, e.request.url)
except httpx.HTTPStatusError as e:
    print(e.response.status_code)
```

(On Python 3.10, drop the `except*` form and catch `ExceptionGroup`
directly, iterating `.exceptions`.)
